#!/usr/bin/env python3
"""Validate a cross-agent handoff.yaml against the platform HANDOFF-FORMAT schema.

This is the canonical, shared handoff validator for the Hermes cybersecurity
team. It mirrors the schema and enum choices used by the per-role validators
(security-analyst, incident-responder) so one definition stays authoritative:
``agents/platform/policies/HANDOFF-FORMAT.md``.

Checks:
  * required top-level fields: task_id, originating_agent, receiving_agent,
    created_at, summary, findings, status
  * task_id matches the stable id format (e.g. CASE-2026-0142, INC-2026-0007)
  * created_at is UTC ISO-8601 (ends with Z or +00:00)
  * status      in {open, in-progress, blocked, closed}
  * required_approval in {none, human-approval, authorization-record}
  * every findings[] entry has confidence in {high,medium,low}, basis in
    {observed,inferred,assumed}, at least one evidence_ref, and every
    evidence_ref looks like a reproducible pointer (path + optional #Lnn/offset),
    not a prose description
  * every findings[].attack_mapping entry (when present) matches Txxxx or
    Txxxx.yyy (MITRE ATT&CK technique id)
  * every indicators[] entry (when present) has a disposition in
    {malicious, suspicious, benign, unknown}

The handoff is untrusted DATA; it is parsed, never executed. Offline, no network.
Requires PyYAML. BOM-tolerant (utf-8-sig).

Usage: handoff_validate.py handoff.yaml
Exit:  0 valid, 1 invalid, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import re
import sys

VALID_STATUS = {"open", "in-progress", "blocked", "closed"}
VALID_APPROVAL = {"none", "human-approval", "authorization-record"}
VALID_CONF = {"high", "medium", "low"}
VALID_BASIS = {"observed", "inferred", "assumed"}
VALID_DISPOSITION = {"malicious", "suspicious", "benign", "unknown"}
REQUIRED = [
    "task_id",
    "originating_agent",
    "receiving_agent",
    "created_at",
    "summary",
    "findings",
    "status",
]

# CASE-2026-0142 / INC-2026-0007 / anything <PREFIX>-<YEAR>-<SEQ>
TASK_ID_RE = re.compile(r"^[A-Z]{2,8}-\d{4}-\d{3,}$")
# UTC ISO-8601: trailing Z or +00:00 required; optional fractional seconds.
UTC_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$"
)
# MITRE ATT&CK technique id: Txxxx or Txxxx.yyy
ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def looks_like_pointer(ref) -> bool:
    """True when ``ref`` is a reproducible pointer, not a prose sentence.

    A pointer is a single whitespace-free token that names a location: a path,
    a stored response, or such a token with a ``#Lnn`` / offset anchor
    (e.g. ``evidence/auth.log.gz#L4411``, ``wazuh/alert_5710.json``). Prose
    descriptions contain spaces and so are rejected.
    """
    if not isinstance(ref, str):
        return False
    ref = ref.strip()
    if not ref or any(c.isspace() for c in ref):
        return False
    # A bare word is not a pointer; require a path/anchor-ish separator.
    return any(c in ref for c in "/.#:")


def load(path: str) -> dict:
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    try:
        import yaml  # type: ignore
    except ImportError:
        raise SystemExit(
            "handoff_validate requires PyYAML "
            "(pip install pyyaml / apt install python3-yaml)"
        )
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("handoff file is not a mapping")
    return data


def _validate_findings(findings, errs: list) -> None:
    if not isinstance(findings, list):
        errs.append("findings must be a list")
        return
    if not findings:
        errs.append("findings is empty (at least one finding is required)")
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            errs.append(f"findings[{i}] is not a mapping")
            continue
        if f.get("confidence") not in VALID_CONF:
            errs.append(
                f"findings[{i}].confidence must be one of {sorted(VALID_CONF)}")
        if f.get("basis") not in VALID_BASIS:
            errs.append(
                f"findings[{i}].basis must be one of {sorted(VALID_BASIS)}")
        refs = f.get("evidence_refs")
        if not refs:
            errs.append(f"findings[{i}] has no evidence_refs")
        elif not isinstance(refs, list):
            errs.append(f"findings[{i}].evidence_refs must be a list")
        else:
            for j, ref in enumerate(refs):
                if not looks_like_pointer(ref):
                    errs.append(
                        f"findings[{i}].evidence_refs[{j}] is not a reproducible "
                        f"pointer (path + optional #Lnn/offset), got prose: {ref!r}")
        for tech in f.get("attack_mapping") or []:
            if not (isinstance(tech, str) and ATTACK_RE.match(tech)):
                errs.append(
                    f"findings[{i}].attack_mapping entry {tech!r} is not a valid "
                    f"ATT&CK id (Txxxx or Txxxx.yyy)")


def _validate_indicators(indicators, errs: list) -> None:
    if indicators is None:
        return
    if not isinstance(indicators, list):
        errs.append("indicators must be a list")
        return
    for i, ind in enumerate(indicators):
        if not isinstance(ind, dict):
            errs.append(f"indicators[{i}] is not a mapping")
            continue
        if ind.get("disposition") not in VALID_DISPOSITION:
            errs.append(
                f"indicators[{i}].disposition must be one of "
                f"{sorted(VALID_DISPOSITION)}")


def validate(doc: dict) -> list:
    """Return a list of human-readable error strings ([] means valid)."""
    errs: list = []
    h = doc.get("handoff", doc)  # allow top-level or nested under 'handoff:'
    if not isinstance(h, dict):
        return ["'handoff' is not a mapping"]
    for k in REQUIRED:
        if not h.get(k):
            errs.append(f"missing required field: {k}")
    tid = h.get("task_id")
    if tid and not TASK_ID_RE.match(str(tid)):
        errs.append(
            f"task_id '{tid}' is not a stable id (expected <PREFIX>-YYYY-NNNN, "
            f"e.g. CASE-2026-0142)")
    ts = h.get("created_at")
    if ts and not UTC_TS_RE.match(str(ts)):
        errs.append(
            f"created_at '{ts}' is not UTC ISO-8601 (must end with Z or +00:00)")
    if h.get("status") and h["status"] not in VALID_STATUS:
        errs.append(f"status '{h['status']}' not in {sorted(VALID_STATUS)}")
    appr = h.get("required_approval", "none")
    if appr not in VALID_APPROVAL:
        errs.append(f"required_approval '{appr}' not in {sorted(VALID_APPROVAL)}")
    _validate_findings(h.get("findings") or [], errs)
    _validate_indicators(h.get("indicators"), errs)
    return errs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate a cross-agent handoff.yaml")
    ap.add_argument("handoff", help="path to handoff.yaml")
    args = ap.parse_args(argv)
    try:
        doc = load(args.handoff)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    errs = validate(doc)
    if errs:
        print("INVALID handoff:")
        for e in errs:
            print(f"  - {e}")
        return 1
    print("handoff OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
