"""Behavior-contract tests for handoff_compose.py — offline, requires PyYAML."""
import importlib.util
import sys
from datetime import datetime, timezone
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


hc = _load("handoff_compose")
pytest.importorskip("yaml")

WHEN = hc._parse_now("2026-10-21T08:00:00Z")


def partial():
    return {
        "originating_agent": "security-analyst",
        "receiving_agent": "threat-intelligence-analyst",
        "summary": "SSH brute force from 198.51.100.23",
        "findings": [
            {"id": "F1", "observation": "87 failed auths then 1 success",
             "confidence": "high", "basis": "observed",
             "evidence_refs": ["evidence/auth.log.gz#L4411"]}
        ],
        "indicators": [
            {"type": "ipv4", "value": "198.51.100.23", "disposition": "suspicious"}
        ],
    }


def test_generates_task_id_from_now_day_of_year():
    h = hc.normalize(partial(), None, WHEN)
    # 2026-10-21 is day 294 of the year.
    assert h["task_id"] == "CASE-2026-0294"


def test_explicit_task_id_wins():
    h = hc.normalize(partial(), "CASE-2026-0142", WHEN)
    assert h["task_id"] == "CASE-2026-0142"


def test_existing_task_id_preserved_when_no_override():
    p = partial()
    p["task_id"] = "INC-2026-0007"
    h = hc.normalize(p, None, WHEN)
    assert h["task_id"] == "INC-2026-0007"


def test_created_at_stamped_utc_from_now():
    h = hc.normalize(partial(), None, WHEN)
    assert h["created_at"] == "2026-10-21T08:00:00Z"


def test_defaults_applied():
    h = hc.normalize(partial(), None, WHEN)
    assert h["status"] == "open"
    assert h["required_approval"] == "none"
    assert h["blockers"] == []


def test_indicator_value_kept_raw():
    h = hc.normalize(partial(), None, WHEN)
    assert h["indicators"][0]["value"] == "198.51.100.23"  # NOT defanged


def test_normalized_partial_validates_and_main_succeeds(tmp_path, capsys):
    import yaml
    src = tmp_path / "partial.yaml"
    src.write_text(yaml.safe_dump({"handoff": partial()}), encoding="utf-8")
    out = tmp_path / "handoff.yaml"
    rc = hc.main([str(src), "--now", "2026-10-21T08:00:00Z", "-o", str(out)])
    assert rc == 0
    doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert doc["handoff"]["task_id"] == "CASE-2026-0294"
    assert doc["handoff"]["status"] == "open"


def test_main_exits_nonzero_when_still_invalid(tmp_path):
    import yaml
    bad = {k: v for k, v in partial().items() if k != "findings"}
    src = tmp_path / "bad.yaml"
    src.write_text(yaml.safe_dump(bad), encoding="utf-8")
    rc = hc.main([str(src), "--now", "2026-10-21T08:00:00Z"])
    assert rc == 1
