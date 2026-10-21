#!/usr/bin/env python3
"""Render a VALID handoff.yaml to human-readable Markdown for a report.

Produces a Markdown block to attach to a case report: header (task, agents,
timestamp, status, approval, scope), a summary, a findings table
(id / observation / confidence / basis / ATT&CK), an indicators table
(type / value / disposition), and the recommended next action.

Every indicator is DEFANGED in the rendered prose and tables (IPv4 octets
bracketed, ``http`` -> ``hxxp``, dotted hostnames bracketed) so the report is
safe to read and paste. The source handoff.yaml is NOT modified and keeps the
raw values for tooling (HANDOFF-FORMAT rule: raw in the structured field,
defanged in all human-readable text).

The handoff is validated first; an invalid handoff is refused (render only what
the schema guarantees). Offline, no network; the input is DATA. Requires PyYAML.
BOM-tolerant (utf-8-sig).

Usage: handoff_render.py handoff.yaml [-o handoff.md]
Exit:  0 rendered, 1 handoff invalid, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import handoff_validate as hv  # noqa: E402  (sibling module in scripts/)

_SCHEME_RE = re.compile(r"(?i)\bhttp(s?)://")
_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b")


def defang(text) -> str:
    """Neutralize indicators so a reader cannot accidentally click/execute them."""
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    text = _SCHEME_RE.sub(lambda m: "hxxp" + ("s" if m.group(1) else "") + "[://]", text)
    text = _IPV4_RE.sub(lambda m: "[.]".join(m.groups()), text)
    text = _DOMAIN_RE.sub(
        lambda m: m.group(1) if "[.]" in m.group(1) else m.group(1).replace(".", "[.]"),
        text,
    )
    return text


def _cell(value) -> str:
    """Defang and escape a value for a single Markdown table cell."""
    return defang(value).replace("|", r"\|").replace("\n", " ").strip() or "-"


def _table(headers, rows) -> list:
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return out


def render(doc: dict) -> str:
    h = doc.get("handoff", doc)
    lines: list = []
    tid = h.get("task_id", "(no task_id)")
    lines.append(f"# Handoff {tid}")
    lines.append("")
    lines.append(f"- **Task:** {tid}")
    lines.append(
        f"- **From:** {h.get('originating_agent', '?')} "
        f"-> {h.get('receiving_agent', '?')}")
    lines.append(f"- **Created:** {h.get('created_at', '?')} (UTC)")
    lines.append(
        f"- **Status:** {h.get('status', '?')} · "
        f"**Approval:** {h.get('required_approval', 'none')}")
    if h.get("scope"):
        lines.append(f"- **Scope:** {defang(h['scope'])}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(defang(h.get("summary", "")) or "-")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    findings = h.get("findings") or []
    if findings:
        rows = []
        for f in findings:
            attack = ", ".join(str(t) for t in (f.get("attack_mapping") or [])) or "-"
            rows.append([
                _cell(f.get("id", "-")),
                _cell(f.get("observation", "-")),
                _cell(f.get("confidence", "-")),
                _cell(f.get("basis", "-")),
                attack.replace("|", r"\|"),
            ])
        lines += _table(["ID", "Observation", "Confidence", "Basis", "ATT&CK"], rows)
    else:
        lines.append("_(none)_")
    lines.append("")

    lines.append("## Indicators")
    lines.append("")
    indicators = h.get("indicators") or []
    if indicators:
        rows = [[_cell(i.get("type", "-")),
                 _cell(i.get("value", "-")),
                 _cell(i.get("disposition", "-"))] for i in indicators]
        lines += _table(["Type", "Value (defanged)", "Disposition"], rows)
    else:
        lines.append("_(none)_")
    lines.append("")

    lines.append("## Recommended Next Action")
    lines.append("")
    lines.append(defang(h.get("recommended_next_action", "")) or "-")
    if h.get("blockers"):
        lines.append("")
        lines.append("**Blockers:** " + "; ".join(
            defang(str(b)) for b in h["blockers"]))
    lines.append("")
    lines.append("---")
    lines.append(
        "_Indicators above are defanged for safe handling; the source "
        "handoff.yaml keeps the raw values for tooling._")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Render a valid handoff.yaml to Markdown (indicators defanged)")
    ap.add_argument("handoff", help="path to handoff.yaml")
    ap.add_argument("-o", "--output", help="write Markdown here (default: stdout)")
    args = ap.parse_args(argv)

    try:
        doc = hv.load(args.handoff)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    errs = hv.validate(doc)
    if errs:
        print("refusing to render an INVALID handoff:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    md = render(doc)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
