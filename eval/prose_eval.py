"""서술 사실 정확성 평가 (flow: triage-prose, 7주차). 채점기는 eval/prose_grade.py, 검증은 eval/prose/mutation_test.py.

트리아지 평가(run_eval.py)가 남긴 실행 기록(대화 기록)을 그대로 다시 채점한다. 새 API 호출이 없어 비용은 0이다.
같은 실행을 두 평가가 각자 채점하므로, 구조화된 필드(triage)와 서술(triage-prose)을 같은 표본에서 비교할 수 있다.

  python eval/prose_eval.py --from-variant v4 --variant baseline
"""

import argparse
import json
import math
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(Path(__file__).parent))

from prose_grade import METRICS, grade_prose, load_trace  # noqa: E402

TRIAGE = ROOT / ".claude" / "hillclimb" / "triage"
FLOW = ROOT / ".claude" / "hillclimb" / "triage-prose"
COPY = ("prompt_id", "rep", "prompt", "tags", "model", "usage", "latency_s", "tool_calls", "turns", "corrections",
        "status", "stop_reason")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    centre, half = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre - half) / (1 + z * z / n), (centre + half) / (1 + z * z / n)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-variant", required=True, help="triage variant whose runs to re-grade (e.g. v4)")
    ap.add_argument("--variant", required=True, help="baseline or v<N> under .claude/hillclimb/triage-prose/")
    args = ap.parse_args()
    if not (args.variant == "baseline" or (args.variant.startswith("v") and args.variant[1:].isdigit())):
        print("--variant must be 'baseline' or v<N>", file=sys.stderr)
        return 2
    src = TRIAGE / args.from_variant
    out = FLOW / args.variant
    out.mkdir(parents=True, exist_ok=True)
    traces = out / "traces"  # 리포트에서 대화 기록을 열 수 있게 복사한다 (원본은 triage/<variant>/traces, 저장소에는 올리지 않음)
    if traces.is_symlink():
        traces.unlink()
    shutil.copytree(src / "traces", traces, dirs_exist_ok=True)
    rows = [json.loads(line) for line in (src / "results.jsonl").read_text().splitlines() if line.strip()]
    graded = []
    for i, row in enumerate(rows):
        new = {k: row[k] for k in COPY if k in row}
        new["meta"] = {"source": f"triage/{args.from_variant}", "triage_pass": (row.get("grade") or {}).get("pass")}
        if row.get("status") == "ok":
            grade, why = grade_prose(*load_trace(src / "traces" / f"{row['prompt_id']}_rep{row['rep']}.json"))
            new["grade"], new["explanation"] = grade, why
            graded.append(grade)
        new.setdefault("grade", None)
        rows[i] = new
    (out / "results.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    n = len(graded)
    print(f"{args.variant} (from triage/{args.from_variant}): {n} graded runs")
    for m in METRICS:
        k = sum(g[m] for g in graded)
        lo, hi = wilson(k, n)
        print(f"  {m:15s} {k:3d}/{n} = {k / n:.0%}  (95% CI {lo:.0%}-{hi:.0%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
