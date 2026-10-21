#!/usr/bin/env python3
"""Normalize a PARTIAL handoff into a schema-complete handoff.yaml.

Reads a partial handoff (YAML or JSON), fills in the mechanical fields the
author can omit, and emits a normalized ``handoff.yaml`` that satisfies
``agents/platform/policies/HANDOFF-FORMAT.md``:

  * generates ``task_id`` as ``CASE-<YYYY>-<NNNN>`` when absent
    (``--task-id`` sets it explicitly; ``--now`` makes the generated id and the
    timestamp deterministic)
  * stamps ``created_at`` as a UTC ISO-8601 timestamp
  * defaults ``status: open`` and ``required_approval: none``
  * keeps each structured indicator ``value`` raw (defanging happens only at
    render time)

It fills mechanics only; it never fabricates findings, a summary, or scope.
If the normalized result is still invalid (e.g. no findings), it prints the
validation errors and exits non-zero. Offline, no network; the input is DATA.
Requires PyYAML. BOM-tolerant (utf-8-sig).

Usage:
  handoff_compose.py partial.yaml
  handoff_compose.py partial.json --task-id CASE-2026-0142 -o handoff.yaml
  handoff_compose.py partial.yaml --now 2026-10-21T08:00:00Z
Exit: 0 wrote a valid handoff, 1 result still invalid, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import handoff_validate as hv  # noqa: E402  (sibling module in scripts/)

# Order mechanical/optional fields sensibly for a readable emitted document.
FIELD_ORDER = [
    "task_id",
    "originating_agent",
    "receiving_agent",
    "created_at",
    "scope",
    "summary",
    "findings",
    "indicators",
    "recommended_next_action",
    "required_approval",
    "status",
    "blockers",
]


def _read_text(path):
    if path in (None, "-"):
        return sys.stdin.read()
    with open(path, encoding="utf-8-sig") as f:
        return f.read()


def load_partial(path) -> dict:
    import yaml  # type: ignore

    data = yaml.safe_load(_read_text(path))
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("input is not a mapping")
    h = data.get("handoff", data)
    if not isinstance(h, dict):
        raise ValueError("'handoff' is not a mapping")
    return dict(h)


def _parse_now(now: str | None) -> datetime:
    if not now:
        return datetime.now(timezone.utc)
    iso = now.strip()
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def generate_task_id(when: datetime) -> str:
    """Deterministic, collision-light id derived from the date (day-of-year)."""
    return "CASE-%04d-%04d" % (when.year, int(when.strftime("%j")))


def normalize(partial: dict, task_id: str | None, when: datetime) -> dict:
    h = dict(partial)
    h["task_id"] = task_id or h.get("task_id") or generate_task_id(when)
    h["created_at"] = h.get("created_at") or when.strftime("%Y-%m-%dT%H:%M:%SZ")
    h.setdefault("status", "open")
    h.setdefault("required_approval", "none")
    h.setdefault("blockers", [])
    # Indicator values are kept raw on purpose; do not touch them here.
    ordered = {k: h[k] for k in FIELD_ORDER if k in h}
    for k, v in h.items():  # preserve any extra author fields after known ones
        ordered.setdefault(k, v)
    return ordered


def dump(handoff: dict) -> str:
    import yaml  # type: ignore

    return yaml.safe_dump(
        {"handoff": handoff}, sort_keys=False, default_flow_style=False,
        allow_unicode=True, width=100)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Normalize a partial handoff into a complete handoff.yaml")
    ap.add_argument("input", nargs="?", default="-",
                    help="partial handoff (YAML/JSON); '-' or omitted = stdin")
    ap.add_argument("--task-id", help="set task_id explicitly (stable across the chain)")
    ap.add_argument("--now", help="override 'now' (UTC ISO-8601) for determinism")
    ap.add_argument("-o", "--output", help="write handoff.yaml here (default: stdout)")
    args = ap.parse_args(argv)

    try:
        partial = load_partial(args.input)
        when = _parse_now(args.now)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    handoff = normalize(partial, args.task_id, when)
    errs = hv.validate({"handoff": handoff})
    if errs:
        print("INVALID handoff after normalization:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    text = dump(handoff)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {args.output} (task_id {handoff['task_id']})", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
