"""CLI 기본값 테스트 (API·DB 없음). 에이전트 호출은 가짜로 바꿔서 CLI가 무엇을 넘기는지만 본다."""

import json

import vulnagent.agent
from vulnagent import cli
from vulnagent.agent import TriageRun

REPORT = {"summary": "s", "unchecked": [], "notes": [], "packages": [
    {"package": "npm/node-serialize@0.0.4", "upgrade_to": None, "reason": "r", "workaround": "역직렬화하지 않는다 (CWE-502)",
     "vulnerabilities": [{"id": "CVE-2017-5941", "rank": 1, "priority": "critical", "kev": False, "cwe": "CWE-502"}]}]}


def _fake_triage(seen: dict):
    async def fake(path, companion=None, **kwargs):
        seen.update(kwargs)
        return None, TriageRun(status="ok", report=REPORT, model_requested=kwargs["model"], cwe=kwargs["cwe"])
    return fake


def test_triage_passes_cwe_labels_by_default_and_no_cwe_turns_it_off(monkeypatch, capsys, tmp_path):
    """8주차 결과를 기본값으로: GHSA/NVD 라벨 전달. --no-cwe면 이전(v5)과 같은 보고서."""
    log = tmp_path / "runs.jsonl"
    monkeypatch.setenv("VULNAGENT_RUNLOG", str(log))
    warned = []
    monkeypatch.setattr(cli, "_warn_if_no_cwe_catalog", lambda: warned.append(1))
    seen: dict = {}
    monkeypatch.setattr(vulnagent.agent, "triage_file", _fake_triage(seen))

    assert cli.main(["triage", "requirements.txt"]) == 0
    assert seen["cwe"] == "labels" and seen["validate"] and seen["tool_hints"] and warned == [1]
    printed = json.loads(capsys.readouterr().out)
    assert printed["packages"][0]["vulnerabilities"][0]["cwe"] == "CWE-502"
    record = json.loads(log.read_text().splitlines()[-1])
    assert record["cwe"] == "labels" and record["workarounds"] == 1

    assert cli.main(["triage", "requirements.txt", "--no-cwe"]) == 0
    assert seen["cwe"] is None and warned == [1]  # 끄면 카탈로그도 확인하지 않는다
    assert json.loads(log.read_text().splitlines()[-1])["cwe"] is None


class _FakeConn:
    def __init__(self, table: bool, rows: bool):
        self.answers = [{"t": table}, {"ok": rows}]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, _sql):
        answer = self.answers.pop(0)
        return type("R", (), {"fetchone": lambda _self: answer})()


def test_catalog_warning(monkeypatch, capsys):
    monkeypatch.setattr(cli, "connect", lambda _url: _FakeConn(table=False, rows=False))
    cli._warn_if_no_cwe_catalog()
    assert "CWE catalog is not loaded" in capsys.readouterr().err

    monkeypatch.setattr(cli, "connect", lambda _url: _FakeConn(table=True, rows=True))
    cli._warn_if_no_cwe_catalog()
    assert capsys.readouterr().err == ""

    def unreachable(_url):
        raise OSError("no database")
    monkeypatch.setattr(cli, "connect", unreachable)
    cli._warn_if_no_cwe_catalog()  # DB에 못 붙으면 조용히 넘어간다 (MCP 서버가 오류를 낸다)
    assert capsys.readouterr().err == ""
