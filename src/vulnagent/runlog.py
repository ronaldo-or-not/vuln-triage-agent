"""실행 기록 (6주차): 실제 사용에서 실행마다 한 줄씩 남기고, 비용·지연·교정·경고를 요약한다.

평가는 결과를 따로 남기지만, 실제 사용은 그동안 아무 기록도 없었다. 운영에서는 "이번 달 얼마 썼나",
"느려졌나", "검증 교정이 얼마나 자주 일어나나", "인젝션 경고가 몇 번 울렸나"를 알아야 한다.
문서 원문이나 보고서 내용은 남기지 않는다 (파일 이름과 수치만).

  VULNAGENT_RUNLOG=/path/runs.jsonl   (기본: ~/.vulnagent/runs.jsonl, "off"이면 기록 안 함)
  vulnagent runs                      요약 출력
"""

import json
import os
import statistics
import time
from collections import Counter
from pathlib import Path

PRICES = {  # 100만 토큰당 (입력, 출력) 달러. 캐시 쓰기 1.25배, 캐시 읽기 0.1배
    "claude-opus-5-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
}
USAGE_KEYS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")


def _price(model: str | None) -> tuple[float, float] | None:
    if not model:
        return None
    return next((p for name, p in PRICES.items() if model.startswith(name)), None)


def cost_usd(usage: dict | None, model: str | None) -> float | None:
    price = _price(model)
    if not usage or price is None:
        return None
    p_in, p_out = price
    return round(((usage.get("input_tokens") or 0) * p_in + (usage.get("output_tokens") or 0) * p_out
                  + (usage.get("cache_creation_input_tokens") or 0) * p_in * 1.25
                  + (usage.get("cache_read_input_tokens") or 0) * p_in * 0.1) / 1e6, 6)


def log_path() -> Path | None:
    value = os.environ.get("VULNAGENT_RUNLOG", str(Path.home() / ".vulnagent" / "runs.jsonl"))
    return None if value.lower() == "off" else Path(value)


def log_run(kind: str, **fields) -> None:
    path = log_path()
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "kind": kind, **fields}
        with path.open("a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass  # 기록 실패가 본 작업을 막지 않게 한다


def log_triage(run, file_label: str, latency_s: float, source: str = "file") -> None:
    """에이전트 실행 한 번. 모델 대체(fallback)가 일어나면 호출마다 실제로 응답한 모델 단가로 계산한다."""
    costs = [cost_usd(c["usage"], c.get("model")) for c in run.calls]
    log_run("triage", file=file_label, source=source, status=run.status, model=run.model_requested,
            models_served=sorted(set(run.models_served)), fallback_ran=run.fallback_ran,
            turns=len(run.calls), tool_calls=len(run.tool_calls),
            tool_errors=sum(1 for t in run.tool_calls if t.get("is_error")),
            corrections=run.corrections, usage=run.usage_total(),
            cost_usd=round(sum(c for c in costs if c is not None), 6) if any(c is not None for c in costs) else None,
            latency_s=round(latency_s, 2),
            packages=len((run.report or {}).get("packages", [])),
            vulnerabilities=sum(len(p.get("vulnerabilities", [])) for p in (run.report or {}).get("packages", [])))


def log_extract(extraction, file_label: str, latency_s: float, defended: bool) -> None:
    log_run("extract", file=file_label, method=extraction.method, model=extraction.model, defended=defended,
            status="ok", usage=extraction.usage, cost_usd=cost_usd(extraction.usage, extraction.model),
            latency_s=round(latency_s, 2), findings=len(extraction.findings),
            warnings=len(extraction.suspected_injections) + len(extraction.alerts))


def summarize(path: Path | None = None) -> dict:
    path = path or log_path()
    if path is None or not path.exists():
        return {"runs": 0}
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    if not rows:
        return {"runs": 0}
    latencies = sorted(r["latency_s"] for r in rows if r.get("latency_s") is not None)
    triage = [r for r in rows if r["kind"] == "triage"]
    return {
        "runs": len(rows),
        "first": rows[0]["ts"], "last": rows[-1]["ts"],
        "by_kind": dict(Counter(r["kind"] for r in rows)),
        "by_model": dict(Counter(r.get("model") for r in rows)),
        "status": dict(Counter(r.get("status") for r in rows)),
        "total_cost_usd": round(sum(r.get("cost_usd") or 0 for r in rows), 4),
        "latency_s": {"p50": statistics.median(latencies) if latencies else None,
                      "p90": latencies[min(len(latencies) - 1, int(0.9 * len(latencies)))] if latencies else None},
        "triage_runs_with_corrections": sum(1 for r in triage if r.get("corrections")),
        "triage_runs_with_fallback": sum(1 for r in triage if r.get("fallback_ran")),
        "extract_runs_with_injection_warnings": sum(1 for r in rows if r["kind"] == "extract" and r.get("warnings")),
    }
