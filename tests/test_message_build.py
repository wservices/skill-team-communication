"""Behavior-contract tests for message_build.py — offline, requires PyYAML."""
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


mb = _load("message_build")
pytest.importorskip("yaml")


def base(**over):
    m = {
        "type": "status",
        "task_id": "CASE-2026-0142",
        "from_agent": "security-analyst",
        "to": "security-team-lead",
        "severity": "medium",
        "body": "Triage 60% done; beacon to 198.51.100.23 confirmed.",
    }
    m.update(over)
    return m


def test_status_valid():
    assert mb.validate_message(base()) == []


def test_status_render_defangs_body():
    md = mb.render(base())
    assert md.startswith("# Status Update (MEDIUM) — CASE-2026-0142")
    assert "198[.]51[.]100[.]23" in md
    assert "198.51.100.23" not in md


def test_bad_severity_rejected():
    assert any("severity" in e for e in mb.validate_message(base(severity="spicy")))


def test_bad_task_id_rejected():
    assert any("task_id" in e for e in mb.validate_message(base(task_id="x")))


def test_missing_required_field_rejected():
    m = base()
    del m["body"]
    assert any("body" in e for e in mb.validate_message(m))


def test_escalation_requires_approval():
    m = base(type="escalation")
    assert any("required_approval" in e for e in mb.validate_message(m))


def test_escalation_valid_and_rendered():
    m = base(type="escalation", severity="critical",
             required_approval="human-approval",
             body="Isolate web01; C2 at http://evil.example.com.")
    assert mb.validate_message(m) == []
    md = mb.render(m)
    assert "Escalation (CRITICAL)" in md
    assert "**Approval required:** human-approval" in md
    assert "hxxp[://]evil[.]example[.]com" in md


def test_rfi_requires_needs_by():
    m = base(type="rfi")
    assert any("needs_by" in e for e in mb.validate_message(m))


def test_rfi_bad_needs_by_format():
    m = base(type="rfi", needs_by="next tuesday")
    assert any("needs_by" in e for e in mb.validate_message(m))


def test_rfi_valid_and_rendered():
    m = base(type="rfi", severity="low", needs_by="2026-10-22T00:00:00Z",
             body="Need the web01 memory capture SHA256.")
    assert mb.validate_message(m) == []
    md = mb.render(m)
    assert "Request for Input (LOW)" in md
    assert "Needs by:** 2026-10-22T00:00:00Z" in md
