"""진단 보고서 추출 평가.

  python eval/docs_eval.py                          # 결정적 추출기만 (무료)
  python eval/docs_eval.py --llm --budget-usd 0.3   # + Haiku 5.5 (유료, 상한까지)
  python eval/docs_eval.py --llm --docs a.pdf,b.docx # 일부 문서만 (파일럿)

지표 (문서 전체를 합친 micro 평균)
- pair recall / precision : (패키지, 취약점 ID) 쌍 기준
- finding recall          : (패키지, 버전) 기준 - 버전을 틀리면 트리아지에서 다른 결과가 나온다
- distractor FP           : 참고문헌·배경에만 나온 ID를 발견사항으로 뽑은 횟수
- exact docs              : 쌍과 버전이 정답과 완전히 같은 문서 수
결과: eval/docs/results/<방법>.jsonl, eval/docs/results.md
"""

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

from vulnagent.docs.extract import extract_deterministic, extract_llm

ROOT = Path(__file__).parent / "docs"
PRICES = {"claude-haiku-5-5": (0.10, 0.50), "claude-sonnet-5-5": (2.0, 10.0), "claude-opus-5-5": (4.0, 20.0)}


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def cost(usage: dict | None, model: str | None) -> float:
    if not usage or not model or model not in PRICES:
        return 0.0
    p_in, p_out = PRICES[model]
    return ((usage.get("input_tokens") or 0) * p_in + (usage.get("output_tokens") or 0) * p_out
            + (usage.get("cache_read_input_tokens") or 0) * p_in * 0.1
            + (usage.get("cache_creation_input_tokens") or 0) * p_in * 1.25) / 1e6


def score(extraction: dict, truth: dict) -> dict:
    gold_pairs = {(norm(f["package"]), i) for f in truth["findings"] for i in f["ids"]}
    gold_found = {(norm(f["package"]), f["version"]) for f in truth["findings"]}
    pred_pairs = {(norm(f["package"]), i) for f in extraction["findings"] for i in f["ids"]}
    pred_found = {(norm(f["package"]), f["version"].strip()) for f in extraction["findings"]}
    pred_ids = {i for _, i in pred_pairs}
    return {
        "tp": len(pred_pairs & gold_pairs), "fp": len(pred_pairs - gold_pairs), "fn": len(gold_pairs - pred_pairs),
        "found_hit": len(pred_found & gold_found), "found_total": len(gold_found),
        "distractor_fp": len(set(truth["distractors"]) & pred_ids),
        "exact": int(pred_pairs == gold_pairs and pred_found == gold_found),
        "missing": sorted(i for _, i in gold_pairs - pred_pairs)[:5],
        "extra": sorted(i for _, i in pred_pairs - gold_pairs)[:5],
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--llm", action="store_true")
    p.add_argument("--model", default="claude-haiku-5-5")
    p.add_argument("--effort", default="medium")
    p.add_argument("--budget-usd", type=float, default=0.3)
    p.add_argument("--docs", help="comma-separated file names (pilot)")
    p.add_argument("--results-dir", type=Path, default=ROOT / "results", help="where to write per-method results")
    args = p.parse_args()
    results_dir = args.results_dir

    truths = sorted((ROOT / "gold").glob("*.json"))
    if args.docs:
        wanted = set(args.docs.split(","))
        truths = [t for t in truths if json.loads(t.read_text())["doc"] in wanted]
    methods = ["deterministic"] + ([f"llm:{args.model}"] if args.llm else [])
    results_dir.mkdir(parents=True, exist_ok=True)
    spent = 0.0
    client = None
    if args.llm:
        import anthropic
        client = anthropic.Anthropic(max_retries=4)

    for method in methods:
        out = results_dir / f"{method.replace(':', '_')}.jsonl"
        done = {json.loads(l)["doc"] for l in out.read_text().splitlines()} if out.exists() else set()
        with out.open("a") as f:
            for path in truths:
                truth = json.loads(path.read_text())
                if truth["doc"] in done:
                    continue
                doc = ROOT / "files" / truth["doc"]
                if method == "deterministic":
                    ext = extract_deterministic(doc).to_dict()
                else:
                    if spent >= args.budget_usd:
                        print(f"budget ${args.budget_usd} reached, skipping {truth['doc']}", file=sys.stderr)
                        continue
                    try:
                        ext = extract_llm(doc, client, args.model, args.effort).to_dict()
                    except Exception as exc:  # API 오류는 점수에 섞지 않고 따로 기록
                        print(f"{truth['doc']}: error {exc}", file=sys.stderr)
                        continue
                    spent += cost(ext["usage"], ext["model"])
                row = {"doc": truth["doc"], "case": truth["case"], "layout": truth["layout"], "method": method,
                       **score(ext, truth), "latency_s": ext["latency_s"], "usage": ext["usage"], "model": ext["model"],
                       "cost_usd": round(cost(ext["usage"], ext["model"]), 6), "notes": ext["notes"][:3]}
                f.write(json.dumps(row) + "\n")
                f.flush()
                if method != "deterministic":
                    print(f"{truth['doc']}: tp={row['tp']} fp={row['fp']} fn={row['fn']} ${row['cost_usd']:.4f} "
                          f"{row['latency_s']}s (spent ${spent:.3f})", file=sys.stderr)

    # 요약 표 (모든 결과 파일 기준)
    lines = ["# 진단 보고서 추출 평가", "", "| 방법 | 양식 | 문서 | pair recall | pair precision | finding recall | "
             "distractor FP | 완전 일치 | 문서당 비용 | 문서당 시간 |", "|---|---|---|---|---|---|---|---|---|---|"]
    for res in sorted(results_dir.glob("*.jsonl")):
        rows = [json.loads(l) for l in res.read_text().splitlines()]
        groups = defaultdict(list)
        for r in rows:
            groups[r["layout"]].append(r)
        groups["(전체)"] = rows
        for layout, rs in groups.items():
            tp, fp, fn = (sum(r[k] for r in rs) for k in ("tp", "fp", "fn"))
            fh, ft = sum(r["found_hit"] for r in rs), sum(r["found_total"] for r in rs)
            lines.append(
                f"| {rs[0]['method']} | {layout} | {len(rs)} | {tp / max(tp + fn, 1):.3f} | {tp / max(tp + fp, 1):.3f} | "
                f"{fh / max(ft, 1):.3f} | {sum(r['distractor_fp'] for r in rs)} | {sum(r['exact'] for r in rs)}/{len(rs)} | "
                f"${sum(r['cost_usd'] for r in rs) / len(rs):.4f} | {sum(r['latency_s'] for r in rs) / len(rs):.2f}s |")
    if results_dir == ROOT / "results":
        (ROOT / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
