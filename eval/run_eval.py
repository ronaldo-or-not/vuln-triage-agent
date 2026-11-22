"""평가 러너: 케이스마다 실제 에이전트(vulnagent.agent.run_triage)를 돌리고 채점한다.

  # 비용 없는 자체 점검: 정답 보고서(~100%)와 빈 보고서(대부분 0%)가 채점기를 통과하는지
  python eval/run_eval.py --fake oracle
  python eval/run_eval.py --fake null

  # 실제 실행 (유료). 하네스가 바뀌면 사용자가 한 번 --approve-harness로 승인해야 돈다.
  python eval/run_eval.py --variant baseline --reps 1 --cases pypi-django-nv,maven-java-goof-struts
  python eval/run_eval.py --variant baseline --reps 2

출력 (.claude/hillclimb/triage/<variant>/)
  results.jsonl          케이스×반복마다 한 줄 (점수, 토큰, 지연, 모델). 끝나는 즉시 기록, 재실행 시 이어서
  traces/<id>_rep<k>.json  전체 대화 (시스템 프롬프트, 도구 호출과 결과, 최종 보고서)
  errors.jsonl           점수를 못 낸 시도 (API 오류, 시간 초과, 다른 모델이 응답 등). 점수에 섞지 않는다
"""

import argparse
import asyncio
import hashlib
import json
import math
import os
import random
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import anthropic  # noqa: E402
from casefiles import AS_OF, load_cases, load_gold, parse_case  # noqa: E402
from grade import METRICS, grade, null_report, oracle_report  # noqa: E402

from vulnagent.agent import DEFAULT_MODEL, build_user_message, run_triage  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FLOW = ROOT / ".claude" / "hillclimb" / "triage"
STATE = FLOW / "_state.json"
HARNESS_SHA = FLOW / "harness.sha"


# ------------------------------------------------------------------ 하네스 무결성 확인
def harness_digest() -> str:
    state = json.loads(STATE.read_text())
    paths = [Path(__file__).resolve()] + [ROOT / p for p in state["harness_paths"]]
    h = hashlib.sha256()
    for path in sorted(paths):
        files = sorted(f for f in path.rglob("*") if f.is_file() and "__pycache__" not in f.parts) if path.is_dir() else [path]
        for f in files:
            h.update(str(f.relative_to(ROOT)).encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def check_harness(approve: bool) -> None:
    digest = harness_digest()
    if approve:
        HARNESS_SHA.write_text(digest + "\n")
        print(f"harness approved: {digest[:12]}", file=sys.stderr)
        return
    recorded = HARNESS_SHA.read_text().strip() if HARNESS_SHA.exists() else None
    if recorded != digest:
        print("harness changed since last approval (runner, agent, grader, cases or gold).\n"
              "Review the change, then run once with --approve-harness.", file=sys.stderr)
        sys.exit(2)


# ------------------------------------------------------------------ 결과 파일
def read_done(results: Path) -> set[tuple[str, int]]:
    if not results.exists():
        return set()
    done = set()
    for line in results.read_text().splitlines():
        row = json.loads(line)
        done.add((row["prompt_id"], row["rep"]))
    return done


def append_jsonl(path: Path, row: dict, lock: asyncio.Lock) -> None:
    with path.open("a") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


SPENT = {"usd": 0.0}  # 이 variant 폴더에서 지금까지 쓴 추정 비용 (지출 상한 판단용)


def cost_usd(usage: dict | None, model: str | None) -> float:
    """usage와 _state.json의 단가로 비용 추정. 캐시 쓰기 1.25배, 캐시 읽기 0.1배."""
    if not usage or not model:
        return 0.0
    prices = json.loads(STATE.read_text()).get("prices", {})
    price = prices.get(model.split(",")[0])
    if not price:
        return 0.0
    p_in, p_out = price["in"], price["out"]
    return ((usage.get("input_tokens") or 0) * p_in + (usage.get("output_tokens") or 0) * p_out
            + (usage.get("cache_creation_input_tokens") or 0) * p_in * 1.25
            + (usage.get("cache_read_input_tokens") or 0) * p_in * 0.1) / 1e6


def already_spent(out_dir: Path) -> float:
    total = 0.0
    for name in ("results.jsonl", "errors.jsonl"):
        path = out_dir / name
        if path.exists():
            for line in path.read_text().splitlines():
                row = json.loads(line)
                total += cost_usd(row.get("usage"), row.get("model"))
    return total


def wilson(passes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = passes / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


# ------------------------------------------------------------------ 케이스 실행
async def run_case(case, rep, args, client, out_dir, sem, lock) -> None:
    gold = load_gold(case["id"])
    parsed = parse_case(case)
    file_label = Path(case["main"]).name
    prompt = build_user_message(parsed, file_label)
    base = {"prompt_id": case["id"], "rep": rep, "prompt": prompt, "tags": case["tags"]}

    if args.fake:
        report = oracle_report(gold) if args.fake == "oracle" else null_report(gold)
        scores, why = grade(report, gold)
        row = {**base, "status": "ok", "stop_reason": "fake", "grade": scores, "explanation": why,
               "model": f"fake-{args.fake}", "usage": {"input_tokens": 0, "output_tokens": 0}, "latency_s": 0, "tool_calls": 0}
        append_jsonl(out_dir / "results.jsonl", row, lock)
        return

    async with sem:
        if args.budget_usd is not None and SPENT["usd"] >= args.budget_usd:
            print(f"{case['id']} rep{rep}: skipped, budget ${args.budget_usd:.2f} reached (spent ${SPENT['usd']:.2f})", file=sys.stderr)
            return
        started = time.monotonic()
        try:
            run = await asyncio.wait_for(
                run_triage(parsed, file_label, model=args.model, effort=args.effort, client=client, validate=args.validate, tool_hints=args.tool_hints, cwe=args.cwe,
                           mcp_env={"VULNAGENT_OFFLINE": "1", "VULNAGENT_AS_OF": AS_OF.isoformat()}),
                timeout=args.timeout_s,
            )
        except asyncio.TimeoutError:
            append_jsonl(out_dir / "errors.jsonl", {**base, "failure_class": "timeout", "wall_s": args.timeout_s}, lock)
            return
        except anthropic.APIError as exc:
            append_jsonl(out_dir / "errors.jsonl", {**base, "failure_class": "api_error", "error": str(exc)[:500]}, lock)
            return
        except Exception as exc:  # MCP 서버 실패 등 하네스 문제는 모델 실패가 아니다
            append_jsonl(out_dir / "errors.jsonl", {**base, "failure_class": "harness_error", "error": repr(exc)[:500]}, lock)
            return
        wall = round(time.monotonic() - started, 2)

    (out_dir / "traces").mkdir(exist_ok=True)
    (out_dir / "traces" / f"{case['id']}_rep{rep}.json").write_text(json.dumps(run.trace, indent=1, ensure_ascii=False))
    usage = run.usage_total()
    served = sorted(set(run.models_served))
    perf = {"model": served[0] if len(served) == 1 else ",".join(served), "usage": usage,
            "latency_s": round(sum(c["latency_s"] for c in run.calls), 2), "wall_s": wall,
            "tool_calls": len(run.tool_calls), "turns": len(run.calls), "corrections": run.corrections}
    SPENT["usd"] += cost_usd(usage, perf["model"])

    # 요청한 모델이 아닌 모델이 답했으면(서버 fallback 포함) 이 비교에 쓸 수 없다 -> 오류로 분리
    if run.fallback_ran or any(m != args.model for m in served):
        append_jsonl(out_dir / "errors.jsonl", {**base, **perf, "failure_class": "served_model_mismatch",
                                                "fallback": run.fallback_ran}, lock)
        return

    meta = {"calls": run.calls, "tools": run.tool_calls, "agent_status": run.status,
            "validate": args.validate, "tool_hints": args.tool_hints, "cwe": args.cwe, "validation_log": run.validation_log}
    if run.status == "ok":
        scores, why = grade(run.report, gold)
        row = {**base, **perf, "status": "ok", "stop_reason": run.stop_reason, "grade": scores, "explanation": why, "meta": meta}
    elif run.status in ("truncated", "refusal"):
        # 잘린 답과 거절은 평균에 넣지 않고 따로 센다 (모델이 틀린 것과 구분)
        row = {**base, **perf, "status": run.status, "stop_reason": run.stop_reason, "grade": {}, "meta": meta}
    else:  # invalid_json, max_turns: 모델이 과제를 끝내지 못함 -> 0점
        zero = {m["id"]: 0 for m in METRICS}
        row = {**base, **perf, "status": "ok", "stop_reason": run.stop_reason, "grade": zero,
               "explanation": {"pass": f"agent did not finish: {run.status}"}, "meta": meta}
    append_jsonl(out_dir / "results.jsonl", row, lock)
    print(f"{case['id']} rep{rep}: {row['status']} pass={row['grade'].get('pass')} "
          f"tools={perf['tool_calls']} {perf['latency_s']}s  (spent so far ${SPENT['usd']:.2f})", file=sys.stderr)


def summarize(out_dir: Path) -> None:
    rows = [json.loads(l) for l in (out_dir / "results.jsonl").read_text().splitlines()] if (out_dir / "results.jsonl").exists() else []
    ok = [r for r in rows if r["status"] == "ok"]
    errors = (out_dir / "errors.jsonl").read_text().splitlines() if (out_dir / "errors.jsonl").exists() else []
    passes = sum(r["grade"]["pass"] for r in ok)
    lo, hi = wilson(passes, len(ok))
    print(f"\n{out_dir.name}: pass {passes}/{len(ok)} = {passes / max(len(ok), 1):.0%} (95% CI {lo:.0%}-{hi:.0%}), "
          f"not scored: {len(rows) - len(ok)} truncated/refused, {len(errors)} errors, "
          f"estimated spend ${already_spent(out_dir):.2f}")
    for m in METRICS[1:]:
        vals = [r["grade"][m["id"]] for r in ok]
        if vals:
            print(f"  {m['id']:13s} mean {sum(vals) / len(vals):.3f}")


async def main_async(args) -> int:
    cases = load_cases()
    if args.cases:
        wanted = set(args.cases.split(","))
        cases = [c for c in cases if c["id"] in wanted]
    if args.fake:
        out_dir = ROOT / "eval" / "selfcheck" / args.fake
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "results.jsonl").unlink(missing_ok=True)
        client = None
    else:
        check_harness(args.approve_harness)
        if args.variant == "pilot":
            out_dir = ROOT / "eval" / "pilot"  # 비용·형식 확인용. 기준 점수(baseline)와 섞지 않는다
        elif args.variant == "baseline" or re.fullmatch(r"v\d+[a-z]?", args.variant):
            out_dir = FLOW / args.variant  # v6a/v6b/v6c: 같은 버전의 실험군 (8주차 CWE 실험)
        elif re.fullmatch(r"pilot-[a-z0-9-]+", args.variant):
            out_dir = ROOT / "eval" / "pilot" / args.variant  # 실험군별 파일럿. 기준 점수와 섞지 않는다
        else:
            print("--variant must be 'pilot', 'pilot-<name>', 'baseline' or v<N>[a-z]", file=sys.stderr)
            return 2
        out_dir.mkdir(parents=True, exist_ok=True)
        client = anthropic.AsyncAnthropic(max_retries=4)  # SDK가 429/5xx를 지수 백오프로 재시도
        SPENT["usd"] = already_spent(out_dir)  # 지출 상한은 이 폴더의 누적 비용 기준 (이어 돌려도 합산)
        if args.budget_usd is not None:
            print(f"budget ${args.budget_usd:.2f}, already spent ${SPENT['usd']:.2f}", file=sys.stderr)
    done = read_done(out_dir / "results.jsonl")
    sem, lock = asyncio.Semaphore(args.concurrency), asyncio.Lock()
    jobs = [run_case(c, rep, args, client, out_dir, sem, lock)
            for rep in range(args.reps) for c in cases if (c["id"], rep) not in done]
    random.Random(0).shuffle(jobs)  # 같은 케이스 반복이 몰리지 않게 (고정 시드)
    await asyncio.gather(*jobs)
    summarize(out_dir)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--variant", default="baseline")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--effort", default="medium")
    p.add_argument("--tool-hints", action="store_true", help="v4: tool returns safe_upgrade and policy_rank")
    p.add_argument("--validate", action="store_true", help="v3: check the report against tool results and ask for corrections")
    p.add_argument("--cwe", choices=["memory", "labels", "search"], help="week 8: add CWE + workaround; where CWE info comes from")
    p.add_argument("--reps", type=int, default=1)
    p.add_argument("--timeout-s", type=float, default=900)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--cases", help="comma-separated case ids")
    p.add_argument("--fake", choices=["oracle", "null"], help="grade gold/empty reports without calling the model")
    p.add_argument("--approve-harness", action="store_true", help="(user) approve the current runner/agent/grader")
    p.add_argument("--budget-usd", type=float, help="stop starting new cases once this variant's estimated spend reaches it")
    args = p.parse_args()
    if not args.fake and not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        print("ANTHROPIC_API_KEY is not set", file=sys.stderr)
        return 2
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
