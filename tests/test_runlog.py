"""실행 기록: 무엇을 남기고 (수치·파일 이름) 무엇을 남기지 않는지 (보고서·문서 내용), 요약이 맞는지."""

import json

from vulnagent import runlog
from vulnagent.agent import TriageRun
from vulnagent.docs.extract import Extraction, Finding


def _run():
    run = TriageRun(status="ok", report=None, model_requested="claude-opus-5-5", fallback_ran=True,
                    models_served=["claude-opus-5-5", "claude-sonnet-5-5"], corrections=1)
    run.calls = [
        {"model": "claude-opus-5-5", "usage": {"input_tokens": 1_000_000, "output_tokens": 0}},
        {"model": "claude-sonnet-5-5", "usage": {"input_tokens": 0, "output_tokens": 100_000}},
    ]
    run.tool_calls = [{"name": "check_packages", "latency_s": 0.1, "is_error": False},
                      {"name": "get_vulnerability", "latency_s": 0.1, "is_error": True}]
    run.report = {"summary": "SECRET-SUMMARY", "packages": [{"package": "x", "vulnerabilities": [{}, {}]}],
                  "unchecked": [], "notes": []}
    return run


def test_triage_record_prices_each_call_by_the_model_that_served_it(tmp_path, monkeypatch):
    log = tmp_path / "runs.jsonl"
    monkeypatch.setenv("VULNAGENT_RUNLOG", str(log))
    runlog.log_triage(_run(), "requirements.txt", 12.345)
    rec = json.loads(log.read_text())
    assert rec["cost_usd"] == 4.0 + 1.0  # opus 입력 100만 토큰 $4 + sonnet 출력 10만 토큰 $1
    assert (rec["turns"], rec["tool_calls"], rec["tool_errors"], rec["corrections"]) == (2, 2, 1, 1)
    assert rec["fallback_ran"] and rec["vulnerabilities"] == 2 and rec["latency_s"] == 12.35
    assert "SECRET-SUMMARY" not in log.read_text()  # 보고서 내용은 남기지 않는다


def test_extract_record_and_summary(tmp_path, monkeypatch):
    log = tmp_path / "runs.jsonl"
    monkeypatch.setenv("VULNAGENT_RUNLOG", str(log))
    ext = Extraction(method="llm", model="claude-haiku-5-5", usage={"input_tokens": 2000, "output_tokens": 400},
                     findings=[Finding(ecosystem="Maven", package="log4j-core", version="2.14.1", ids=["CVE-2021-44228"])],
                     alerts=["llm dropped CVE-2021-44228"])
    runlog.log_extract(ext, "report.pdf", 3.0, defended=True)
    runlog.log_triage(_run(), "report.pdf", 20.0, source="extract")
    assert "log4j-core" not in log.read_text()
    s = runlog.summarize()
    assert s["runs"] == 2 and s["by_kind"] == {"extract": 1, "triage": 1}
    assert s["extract_runs_with_injection_warnings"] == 1 and s["triage_runs_with_corrections"] == 1
    assert s["total_cost_usd"] == round(5.0 + (2000 * 0.10 + 400 * 0.50) / 1e6, 4)


def test_off_and_unknown_model(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNAGENT_RUNLOG", "off")
    runlog.log_run("triage", status="ok")
    assert runlog.summarize() == {"runs": 0}
    assert runlog.cost_usd({"input_tokens": 10}, "some-other-model") is None
