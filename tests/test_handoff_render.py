"""Behavior-contract tests for handoff_render.py — offline, requires PyYAML."""
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


hr = _load("handoff_render")
pytest.importorskip("yaml")


def good():
    return {
        "handoff": {
            "task_id": "CASE-2026-0142",
            "originating_agent": "security-analyst",
            "receiving_agent": "threat-intelligence-analyst",
            "created_at": "2026-10-15T11:42:00Z",
            "scope": "Host web01 (10.0.4.11)",
            "summary": "Brute force from 198.51.100.23; beacon http://evil.example.com/x",
            "status": "open",
            "required_approval": "none",
            "findings": [
                {"id": "F1", "observation": "1 success for deploy from 198.51.100.23",
                 "confidence": "high", "basis": "observed",
                 "evidence_refs": ["evidence/auth.log.gz#L4411"],
                 "attack_mapping": ["T1110.001"]}
            ],
            "indicators": [
                {"type": "ipv4", "value": "198.51.100.23",
                 "disposition": "suspicious"},
                {"type": "domain", "value": "evil.example.com",
                 "disposition": "malicious"},
            ],
        }
    }


def test_defang_ipv4():
    assert hr.defang("198.51.100.23") == "198[.]51[.]100[.]23"


def test_defang_url_scheme_and_host():
    assert hr.defang("http://evil.example.com") == "hxxp[://]evil[.]example[.]com"
    assert hr.defang("https://a.bad.net") == "hxxps[://]a[.]bad[.]net"


def test_summary_is_defanged_in_output():
    md = hr.render(good())
    assert "198[.]51[.]100[.]23" in md
    assert "hxxp[://]evil[.]example[.]com" in md
    assert "198.51.100.23" not in md  # no raw IP leaks into the prose


def test_findings_table_has_columns_and_attack():
    md = hr.render(good())
    assert "| ID | Observation | Confidence | Basis | ATT&CK |" in md
    row = [ln for ln in md.splitlines() if ln.startswith("| F1 ")][0]
    assert "high" in row and "observed" in row and "T1110.001" in row


def test_indicators_table_defanged():
    md = hr.render(good())
    assert "| ipv4 | 198[.]51[.]100[.]23 | suspicious |" in md
    assert "| domain | evil[.]example[.]com | malicious |" in md


def test_render_refuses_invalid_handoff(tmp_path, capsys):
    import yaml
    doc = good()
    doc["handoff"]["status"] = "pending"  # invalid enum
    src = tmp_path / "bad.yaml"
    src.write_text(yaml.safe_dump(doc), encoding="utf-8")
    rc = hr.main([str(src)])
    assert rc == 1
    assert "INVALID" in capsys.readouterr().err
