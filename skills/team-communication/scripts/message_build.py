#!/usr/bin/env python3
"""Compose, validate and render the team's non-handoff messages.

Three structured message types that travel alongside handoffs:

  * ``status``     — progress on a task_id
  * ``escalation`` — raise to the Security Team Lead / human operator
                     (carries severity + required_approval)
  * ``rfi``        — request-for-input: ask a named agent/human for specific
                     information, with a needs_by deadline

Input is a small structured object (YAML/JSON file, or CLI flags that override
it) with: type, task_id, from_agent, to, severity, body, plus needs_by (rfi)
and required_approval (escalation). The script validates the enums and the
per-type required fields, then renders Markdown with every indicator in the
body DEFANGED (IPv4 bracketed, ``http`` -> ``hxxp``, dotted hosts bracketed).

It only PRODUCES an artifact — it never sends anything. Delivery is the
orchestrator's / human's job. Offline, no network; the input is DATA.
Requires PyYAML. BOM-tolerant (utf-8-sig).

Usage:
  message_build.py --type status --task-id CASE-2026-0142 \
      --from-agent security-analyst --to security-team-lead \
      --severity medium --body "Triage 60% complete."
  message_build.py --type rfi -f msg.yaml -o rfi.md
Exit: 0 rendered, 1 validation failed, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import handoff_validate as hv  # noqa: E402  (sibling module in scripts/)
from handoff_render import defang  # noqa: E402  (shared, canonical defang)

TYPES = {"status", "escalation", "rfi"}
VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}
# needs_by: a UTC datetime (reuse the handoff rule) or a bare calendar date.
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

COMMON_REQUIRED = ["type", "task_id", "from_agent", "to", "severity", "body"]
TITLES = {
    "status": "Status Update",
    "escalation": "Escalation",
    "rfi": "Request for Input",
}


def load_file(path) -> dict:
    import yaml  # type: ignore

    with open(path, encoding="utf-8-sig") as f:
        data = yaml.safe_load(f.read())
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("message input is not a mapping")
    return dict(data.get("message", data))


def validate_message(m: dict) -> list:
    """Return a list of error strings ([] means valid)."""
    errs: list = []
    mtype = m.get("type")
    if mtype not in TYPES:
        errs.append(f"type must be one of {sorted(TYPES)} (got {mtype!r})")
    for k in COMMON_REQUIRED:
        if not m.get(k):
            errs.append(f"missing required field: {k}")
    tid = m.get("task_id")
    if tid and not hv.TASK_ID_RE.match(str(tid)):
        errs.append(
            f"task_id '{tid}' is not a stable id (expected <PREFIX>-YYYY-NNNN)")
    sev = m.get("severity")
    if sev and sev not in VALID_SEVERITY:
        errs.append(f"severity '{sev}' not in {sorted(VALID_SEVERITY)}")

    if mtype == "escalation":
        appr = m.get("required_approval")
        if not appr:
            errs.append("escalation requires required_approval")
        elif appr not in hv.VALID_APPROVAL:
            errs.append(
                f"required_approval '{appr}' not in {sorted(hv.VALID_APPROVAL)}")
    if mtype == "rfi":
        nb = m.get("needs_by")
        if not nb:
            errs.append("rfi requires needs_by")
        elif not (DATE_RE.match(str(nb)) or hv.UTC_TS_RE.match(str(nb))):
            errs.append(
                f"needs_by '{nb}' must be a date (YYYY-MM-DD) or UTC ISO-8601")
    return errs


def render(m: dict) -> str:
    mtype = m["type"]
    title = TITLES[mtype]
    sev = str(m.get("severity", "")).upper()
    header = f"# {title} ({sev}) — {m.get('task_id', '?')}"
    lines = [header, ""]
    lines.append(f"- **Task:** {m.get('task_id', '?')}")
    lines.append(f"- **From -> To:** {m.get('from_agent', '?')} -> {m.get('to', '?')}")
    lines.append(f"- **Severity:** {m.get('severity', '?')}")
    if mtype == "escalation":
        lines.append(f"- **Approval required:** {m.get('required_approval', '?')}")
    if mtype == "rfi":
        lines.append(f"- **Needs by:** {m.get('needs_by', '?')} (UTC)")
    lines.append("")
    lines.append(defang(m.get("body", "")) or "-")
    lines.append("")
    lines.append("---")
    lines.append(
        "_Indicators in the body are defanged; this is an artifact to be "
        "routed by a human / the orchestrator, not sent by this tool._")
    return "\n".join(lines) + "\n"


def collect(args) -> dict:
    m: dict = {}
    if args.file:
        m.update(load_file(args.file))
    # CLI flags override file values when provided.
    overrides = {
        "type": args.type,
        "task_id": args.task_id,
        "from_agent": args.from_agent,
        "to": args.to,
        "severity": args.severity,
        "body": args.body,
        "needs_by": args.needs_by,
        "required_approval": args.required_approval,
    }
    for k, v in overrides.items():
        if v is not None:
            m[k] = v
    return m


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Compose/validate/render a team status, escalation, or RFI")
    ap.add_argument("--type", choices=sorted(TYPES), help="message type")
    ap.add_argument("-f", "--file", help="structured input (YAML/JSON)")
    ap.add_argument("--task-id")
    ap.add_argument("--from-agent")
    ap.add_argument("--to")
    ap.add_argument("--severity", choices=sorted(VALID_SEVERITY))
    ap.add_argument("--body")
    ap.add_argument("--needs-by", help="rfi deadline (UTC ISO-8601 or YYYY-MM-DD)")
    ap.add_argument("--required-approval", choices=sorted(hv.VALID_APPROVAL),
                    help="escalation approval gate")
    ap.add_argument("-o", "--output", help="write Markdown here (default: stdout)")
    args = ap.parse_args(argv)

    try:
        m = collect(args)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    errs = validate_message(m)
    if errs:
        print("INVALID message:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    md = render(m)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
