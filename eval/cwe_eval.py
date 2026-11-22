"""8주차 CWE 실험 집계: 실험군 폴더의 trace를 다시 채점해 한 표로 비교한다 (LLM 호출 없음, 비용 0).

  python eval/cwe_eval.py v6a v6b v6c                     # .claude/hillclimb/triage/<variant>/
  python eval/cwe_eval.py --pilot pilot-cwe-memory ...    # eval/pilot/<variant>/
결과: eval/cwe/results.json, eval/cwe/results.md (파일럿은 eval/cwe/pilot_results.*)

같은 실행을 세 채점기로 본다: CWE·완화책(cwe_grade), 구조화 필드(grade, 실행 때 기록한 값),
서술 사실(prose_grade). CWE를 더하느라 기존 품질이 떨어지지 않았는지를 같은 실행에서 확인하기 위해서다.
"""

import argparse
import json
import math
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from casefiles import load_gold  # noqa: E402
from cwe_grade import grade_cwe, load_reference  # noqa: E402
from prose_grade import grade_prose, load_trace  # noqa: E402
from run_eval import cost_usd  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FLOW = ROOT / ".claude" / "hillclimb" / "triage"
OUT = Path(__file__).resolve().parent / "cwe"
ARM_OF = {"memory": "기억만", "labels": "라벨 전달", "search": "검색"}


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)]


def ratio(k: int, n: int) -> float | None:
    return round(k / n, 3) if n else None


def arm(variant_dir: Path, labels, catalog) -> dict:
    rows = [json.loads(l) for l in (variant_dir / "results.jsonl").read_text().splitlines()]
    errors = (variant_dir / "errors.jsonl").read_text().splitlines() if (variant_dir / "errors.jsonl").exists() else []
    total = {}
    per_vuln: dict[str, bool] = {}
    runs, misses = [], []
    for row in rows:
        trace_path = variant_dir / "traces" / f"{row['prompt_id']}_rep{row['rep']}.json"
        run = {"case": row["prompt_id"], "rep": row["rep"], "status": row["status"],
               "pass": (row.get("grade") or {}).get("pass"), "cost": cost_usd(row.get("usage"), row.get("model")),
               "latency_s": row.get("latency_s"), "tool_calls": row.get("tool_calls"),
               "out_tokens": (row.get("usage") or {}).get("output_tokens"), "cwe_arm": (row.get("meta") or {}).get("cwe")}
        if row["status"] == "ok" and trace_path.exists() and (row.get("meta") or {}).get("agent_status") == "ok":
            trace = json.loads(trace_path.read_text())
            payload, check, report = load_trace(trace_path)
            gold = load_gold(row["prompt_id"])
            graded = grade_cwe(report, trace, gold, labels, catalog)
            for k, v in graded["counts"].items():
                total[k] = total.get(k, 0) + v
            run["cwe_acc"] = ratio(graded["counts"]["hit"], graded["counts"]["labeled"])
            per_vuln.update({f"{row['prompt_id']}|{row['rep']}|{k}": v for k, v in graded["per_vuln"].items()})
            misses += [f"{row['prompt_id']}: {m}" for m in graded["misses"][:3] + graded["wa_misses"][:3]]
            prose, _why = grade_prose(payload, check, report)
            run["prose_ok"], run["counts_ok"] = prose["prose_ok"], prose["counts_ok"]
        runs.append(run)

    scored = [r for r in runs if "cwe_acc" in r]
    t = {k: total.get(k, 0) for k in ("vulns", "labeled", "hit", "answered", "valid", "grounded",
                                      "wa_needed", "wa_present", "wa_relevant", "wa_grounded", "wa_extra")}
    macro = [r["cwe_acc"] for r in scored if r["cwe_acc"] is not None]
    return {
        "variant": variant_dir.name, "arm": next((r["cwe_arm"] for r in runs if r["cwe_arm"]), None),
        "runs": len(runs), "scored": len(scored), "errors": len(errors),
        "not_finished": [f"{r['case']} rep{r['rep']}: {r['status']}" for r in runs if "cwe_acc" not in r],
        "counts": t,
        "cwe_acc": ratio(t["hit"], t["labeled"]), "cwe_acc_ci": wilson(t["hit"], t["labeled"]),
        "cwe_acc_macro": round(statistics.mean(macro), 3) if macro else None,
        "answered": ratio(t["answered"], t["vulns"]), "valid": ratio(t["valid"], t["answered"]),
        "grounded": ratio(t["grounded"], t["answered"]),
        "wa_present": ratio(t["wa_present"], t["wa_needed"]), "wa_relevant": ratio(t["wa_relevant"], t["wa_present"]),
        "wa_grounded": ratio(t["wa_grounded"], t["wa_present"]),
        "pass": [sum(1 for r in scored if r["pass"]), len(scored)],
        "prose_ok": [sum(1 for r in scored if r["prose_ok"]), len(scored)],
        "counts_ok": [sum(1 for r in scored if r["counts_ok"]), len(scored)],
        "cost_total": round(sum(r["cost"] for r in runs), 4),
        "cost_per_run": round(statistics.mean(r["cost"] for r in runs), 4) if runs else None,
        "latency_median_s": statistics.median(r["latency_s"] for r in runs if r["latency_s"] is not None) if runs else None,
        "tool_calls_mean": round(statistics.mean(r["tool_calls"] or 0 for r in runs), 2) if runs else None,
        "out_tokens_mean": round(statistics.mean(r["out_tokens"] or 0 for r in runs)) if runs else None,
        "runs_detail": runs, "per_vuln": per_vuln, "example_misses": misses[:20],
    }


def paired(a: dict, b: dict) -> dict:
    """같은 (케이스, 반복, 취약점)에서 두 실험군의 정답 여부를 짝지어 센다."""
    keys = sorted(set(a["per_vuln"]) & set(b["per_vuln"]))
    both = sum(a["per_vuln"][k] and b["per_vuln"][k] for k in keys)
    only_a = sum(a["per_vuln"][k] and not b["per_vuln"][k] for k in keys)
    only_b = sum(b["per_vuln"][k] and not a["per_vuln"][k] for k in keys)
    return {"pair": f"{a['variant']} vs {b['variant']}", "n": len(keys), "both_right": both,
            f"only_{a['variant']}": only_a, f"only_{b['variant']}": only_b, "both_wrong": len(keys) - both - only_a - only_b}


def markdown(arms: list[dict], pairs: list[dict]) -> str:
    def pct(x):
        return "-" if x is None else f"{x:.0%}"
    lines = ["| 실험군 | CWE 정답률 (95% CI) | 케이스 평균 | 채움 | 카탈로그에 있음 | 도구 근거 | 완화책 작성 | 완화책 CWE 맞음 | 완화책 KB 근거 | 구조화 pass | 서술 prose_ok | 비용/실행 | 지연 중앙값 | 도구 호출 |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for a in arms:
        c = a["counts"]
        lines.append(
            f"| {a['variant']} {ARM_OF.get(a['arm'], a['arm'])} | {pct(a['cwe_acc'])} ({c['hit']}/{c['labeled']}, "
            f"{a['cwe_acc_ci'][0]:.0%}–{a['cwe_acc_ci'][1]:.0%}) | {pct(a['cwe_acc_macro'])} | {pct(a['answered'])} | "
            f"{pct(a['valid'])} | {pct(a['grounded'])} | {c['wa_present']}/{c['wa_needed']} | {c['wa_relevant']}/{c['wa_present']} | "
            f"{c['wa_grounded']}/{c['wa_present']} | {a['pass'][0]}/{a['pass'][1]} | {a['prose_ok'][0]}/{a['prose_ok'][1]} | "
            f"${a['cost_per_run']:.4f} | {a['latency_median_s']}s | {a['tool_calls_mean']} |")
    lines += ["", "짝지은 비교 (같은 케이스·취약점):", ""]
    lines += [f"- {p['pair']}: " + ", ".join(f"{k} {v}" for k, v in p.items() if k != "pair") for p in pairs]
    for a in arms:
        if a["not_finished"] or a["errors"]:
            lines.append(f"- {a['variant']}: 채점 못 한 실행 {a['not_finished']}, 오류 {a['errors']}건")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("variants", nargs="+")
    ap.add_argument("--pilot", action="store_true", help="variants live under eval/pilot/")
    args = ap.parse_args()
    labels, catalog = load_reference()
    base = ROOT / "eval" / "pilot" if args.pilot else FLOW
    arms = [arm(base / v, labels, catalog) for v in args.variants]
    pairs = [paired(arms[i], arms[j]) for i in range(len(arms)) for j in range(i + 1, len(arms))]
    stem = "pilot_results" if args.pilot else "results"
    slim = [{k: v for k, v in a.items() if k != "per_vuln"} for a in arms]
    (OUT / f"{stem}.json").write_text(json.dumps({"arms": slim, "paired": pairs}, indent=1, ensure_ascii=False) + "\n")
    md = markdown(arms, pairs)
    (OUT / f"{stem}.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
