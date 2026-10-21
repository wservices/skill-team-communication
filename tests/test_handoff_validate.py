"""Behavior-contract tests for handoff_validate.py — offline, requires PyYAML."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "team-communication" / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


hv = _load("handoff_validate")
pytest.importorskip("yaml")


def good():
    return {
        "handoff": {
            "task_id": "CASE-2026-0142",
            "originating_agent": "security-analyst",
            "receiving_agent": "threat-intelligence-analyst",
            "created_at": "2026-10-15T11:42:00Z",
            "summary": "SSH brute force then a successful auth",
            "status": "open",
            "required_approval": "none",
            "findings": [
                {"id": "F1", "observation": "87 failed auths then 1 success",
                 "confidence": "high", "basis": "observed",
                 "evidence_refs": ["evidence/auth.log.gz#L4411"],
                 "attack_mapping": ["T1110.001"]}
            ],
            "indicators": [
                {"type": "ipv4", "value": "198.51.100.23",
                 "disposition": "suspicious"}
            ],
        }
    }


def test_good_handoff_is_valid():
    assert hv.validate(good()) == []


def test_subtechnique_and_plain_technique_both_valid():
    doc = good()
    doc["handoff"]["findings"][0]["attack_mapping"] = ["T1110", "T1110.001"]
    assert hv.validate(doc) == []


def test_missing_summary_and_findings_reported():
    doc = good()
    del doc["handoff"]["summary"]
    del doc["handoff"]["findings"]
    errs = hv.validate(doc)
    assert any("summary" in e for e in errs)
    assert any("findings" in e for e in errs)


def test_bad_status_enum():
    doc = good()
    doc["handoff"]["status"] = "pending"
    assert any("status" in e for e in hv.validate(doc))


def test_bad_required_approval_enum():
    doc = good()
    doc["handoff"]["required_approval"] = "maybe"
    assert any("required_approval" in e for e in hv.validate(doc))


def test_bad_confidence_and_basis():
    doc = good()
    doc["handoff"]["findings"][0]["confidence"] = "very-high"
    doc["handoff"]["findings"][0]["basis"] = "guessed"
    errs = hv.validate(doc)
    assert any("confidence" in e for e in errs)
    assert any("basis" in e for e in errs)


def test_prose_evidence_ref_rejected():
    doc = good()
    doc["handoff"]["findings"][0]["evidence_refs"] = ["87 failed logins in the auth log"]
    assert any("reproducible pointer" in e for e in hv.validate(doc))


def test_pointer_heuristic_accepts_paths_rejects_prose():
    assert hv.looks_like_pointer("evidence/auth.log.gz#L4411")
    assert hv.looks_like_pointer("wazuh/alert_5710.json")
    assert not hv.looks_like_pointer("the auth log around 10am")
    assert not hv.looks_like_pointer("notes")  # bare word is not a pointer


def test_bad_attack_mapping_rejected():
    doc = good()
    doc["handoff"]["findings"][0]["attack_mapping"] = ["T99", "TA0001"]
    errs = hv.validate(doc)
    assert sum("ATT&CK id" in e for e in errs) == 2


def test_bad_task_id_and_created_at():
    doc = good()
    doc["handoff"]["task_id"] = "nope"
    doc["handoff"]["created_at"] = "2026-10-15 11:42:00"  # space, no Z
    errs = hv.validate(doc)
    assert any("task_id" in e for e in errs)
    assert any("created_at" in e for e in errs)


def test_bad_indicator_disposition():
    doc = good()
    doc["handoff"]["indicators"][0]["disposition"] = "scary"
    assert any("disposition" in e for e in hv.validate(doc))
