"""개수 채점기(counts_ok) 변이 테스트: 사람 라벨 대신, 정답을 아는 오류를 일부러 만들어 넣고 검출률을 잰다 (비용 0).

원본: v4 보고서 60개 중 채점기가 counts_ok=1로 본 요약문. 요약문의 개수 표현(N개 / N건)을 하나씩 바꾼다.
원래 숫자가 맞았다면 다른 숫자로 바꾼 것은 반드시 오류다 (그 숫자가 가리키는 대상의 값은 하나뿐이므로).

오류 변이 (잡아야 함)
  unseen       사실표 어디에도 없는 값으로 (n±1, 2n+3)
  collides     사실표의 다른 항목 값으로 (예: 취약점 7건 -> 취약 패키지 수 4로 "취약점 4건"). 대상을 엉뚱하게 쓴 오류
  approx_out   "약 m"으로 바꾸되 m이 허용 범위(±10%, 최소 ±2) 밖
양성 변이 (통과시켜야 함)
  approx_in    맞는 숫자 앞에 "약 "만 붙임

  python eval/prose/mutation_test.py [--traces DIR] [--json OUT]
"""

import argparse
import glob
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))

from prose_grade import _allowed_numbers, count_claims, facts, grade_prose, load_trace  # noqa: E402


def fact_values(f: dict) -> set[int]:
    return {v for k, v in f.items() if isinstance(v, int)} | set(f["per_package"].values())


def mutations(summary: str, claim: dict, f: dict):
    n, (s, e) = claim["n"], claim["span"]
    swap = lambda v: summary[:s] + str(v) + summary[e:]  # noqa: E731
    allowed = _allowed_numbers(f)
    for v in sorted({n + 1, n - 1, 2 * n + 3}):
        if v >= 2 and v != n:
            yield ("unseen" if v not in allowed else "collides"), swap(v), True
    for v in sorted(fact_values(f)):
        if v >= 2 and v != n and v not in {n + 1, n - 1, 2 * n + 3}:
            yield "collides", swap(v), True
    m = n + max(3, -(-3 * n // 10))  # 30% 이상 또는 +3: 허용 범위 밖
    yield "approx_out", summary[:s] + f"약 {m}" + summary[e:], True
    yield "approx_in", summary[:s] + "약 " + summary[s:], False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", default=str(ROOT / ".claude/hillclimb/triage/v4/traces"))
    ap.add_argument("--json", help="write per-type results here")
    args = ap.parse_args()
    hit, total, base = Counter(), Counter(), Counter()
    missed = defaultdict(list)
    for path in sorted(glob.glob(f"{args.traces}/*.json")):
        payload, check, report = load_trace(Path(path))
        base["reports"] += 1
        if not grade_prose(payload, check, report)[0]["counts_ok"]:
            continue  # 원본이 이미 틀렸다고 판정되면 기준이 불명확하므로 쓰지 않는다
        base["usable"] += 1
        f = facts(payload, check, report)
        for claim in count_claims(report["summary"]):
            if claim["approx"] or claim["n"] < 2:
                continue
            base["claims"] += 1
            for kind, text, is_error in mutations(report["summary"], claim, f):
                flagged = not grade_prose(payload, check, {**report, "summary": text})[0]["counts_ok"]
                total[kind] += 1
                hit[kind] += int(flagged == is_error)
                if flagged != is_error and len(missed[kind]) < 3:
                    missed[kind].append({"case": Path(path).stem, "claim": claim["text"], "mutated": text[max(0, claim["span"][0] - 15): claim["span"][1] + 12]})
    print(f"reports {base['reports']}, usable (counts_ok=1) {base['usable']}, exact claims mutated {base['claims']}")
    rows = {}
    for kind in ("unseen", "collides", "approx_out", "approx_in"):
        label = "correctly passed" if kind == "approx_in" else "detected"
        rows[kind] = {"n": total[kind], "ok": hit[kind], "rate": round(hit[kind] / total[kind], 3) if total[kind] else None}
        print(f"  {kind:11s} {label:17s} {hit[kind]:4d}/{total[kind]:<4d} = {rows[kind]['rate']}")
        for m in missed[kind]:
            print(f"      e.g. {m['case']}: {m['claim']!r} -> {m['mutated']!r}")
    if args.json:
        Path(args.json).write_text(json.dumps({"base": dict(base), "types": rows}, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
