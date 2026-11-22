"""CWE 검색 평가 (LLM 호출 없음, 비용 0).

과제: CVE 설명 하나를 질의로 넣었을 때, 그 CVE에 매겨진 CWE가 검색 결과 상위에 나오는가.
정답: 1주차에 캐시한 NVD 레코드의 CWE 라벨 (NVD 또는 CNA가 매김). 사람이 새로 라벨링하지 않았다.

주의
- 라벨에 잡음이 있다. CNA가 붙인 라벨은 너무 넓거나(CWE-20 입력 검증) 사람마다 다르게 붙는다.
- 누수: CWE 항목의 '관찰 사례'에 바로 그 CVE의 설명이 실려 있을 수 있다. 기본 색인에서는 빼고,
  넣었을 때 점수가 얼마나 부풀려지는지 따로 잰다 (bm25+observed).

  python eval/retrieval_eval.py        # 결과: eval/retrieval/results.json, results.md
"""

import json
import math
import sys
import time
from collections import Counter
from pathlib import Path

from vulnagent.config import load_settings
from vulnagent.db import connect
from vulnagent.kb.search import MODELS, CweIndex, rrf

OUT = Path(__file__).parent / "retrieval"
KS = (1, 5, 10)


def wilson(p: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    phat = p / n
    centre = (phat + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return centre - half, centre + half


def evaluate(name: str, search, queries: list[dict]) -> dict:
    hits = {k: 0 for k in KS}
    rr = 0.0
    misses = []
    started = time.monotonic()
    for q in queries:
        ranked = [cid for cid, _ in search(q["text"], 10)]
        first = next((i for i, cid in enumerate(ranked, 1) if cid in q["gold"]), None)
        for k in KS:
            hits[k] += first is not None and first <= k
        rr += 1.0 / first if first else 0.0
        if first is None and len(misses) < 5:
            misses.append({"cve": q["cve"], "gold": sorted(q["gold"]), "top3": ranked[:3]})
    n = len(queries)
    lo, hi = wilson(hits[5], n)
    return {
        "method": name, "n": n,
        **{f"hit@{k}": round(hits[k] / n, 4) for k in KS},
        "hit@5_ci": [round(lo, 4), round(hi, 4)],
        "mrr@10": round(rr / n, 4),
        "ms_per_query": round(1000 * (time.monotonic() - started) / n, 1),
        "example_misses": misses,
    }


def main() -> int:
    conn = connect(load_settings().database_url)
    index = CweIndex(conn)
    leaky_index = CweIndex(conn, include_observed=True)
    observed = {cve for r in conn.execute("SELECT observed_cves FROM cwe_entry") for cve in r["observed_cves"]}

    queries, skipped = [], Counter()
    for r in conn.execute("SELECT cve_id, description, cwes FROM nvd_cve WHERE found AND description IS NOT NULL ORDER BY cve_id"):
        gold = {c for c in r["cwes"] if c in index}
        if not r["cwes"]:
            skipped["no CWE label"] += 1
        elif not gold:
            skipped["label not in catalog (deprecated/view)"] += 1
        else:
            queries.append({"cve": r["cve_id"], "text": r["description"], "gold": gold, "leaky": r["cve_id"] in observed})

    for model in MODELS.values():
        added = index.ensure_embeddings(model)
        print(f"embeddings {model}: +{added}", file=sys.stderr)

    methods = [
        ("bm25", lambda q, k: index.bm25_search(q, k)),
        ("dense:minilm", lambda q, k: index.dense_search(q, k, MODELS["minilm"])),
        ("dense:mpnet", lambda q, k: index.dense_search(q, k, MODELS["mpnet"])),
        ("hybrid:bm25+minilm", lambda q, k: index.hybrid_search(q, k, MODELS["minilm"])),
        ("hybrid:bm25+mpnet", lambda q, k: index.hybrid_search(q, k, MODELS["mpnet"])),
        ("bm25+observed (leak check)", lambda q, k: leaky_index.bm25_search(q, k)),
    ]
    results = [evaluate(name, fn, queries) for name, fn in methods]
    leaky = [q for q in queries if q["leaky"]]
    leak_split = {
        "queries_whose_cve_is_an_observed_example": len(leaky),
        "bm25_on_those": evaluate("bm25", methods[0][1], leaky) if leaky else None,
        "bm25+observed_on_those": evaluate("bm25+observed", methods[-1][1], leaky) if leaky else None,
    }

    # 관찰 사례를 색인하면 오르는 점수가 '누수'인지 '정당한 효과'인지 가르기:
    # 자기 CVE가 관찰 사례에 없는 질의만 쓰면 누수가 원천적으로 없다.
    clean = [q for q in queries if not q["leaky"]]
    minilm = MODELS["minilm"]

    def hybrid_with(idx):
        return lambda q, k: rrf([[c for c, _ in idx.bm25_search(q, 100)], [c for c, _ in index.dense_search(q, 100, minilm)]])[:k]

    leak_free = [evaluate(name, fn, clean) for name, fn in (
        ("bm25", methods[0][1]),
        ("bm25+observed", methods[-1][1]),
        ("hybrid:bm25+minilm", hybrid_with(index)),
        ("hybrid:(bm25+observed)+minilm", hybrid_with(leaky_index)),
    )]
    label_freq = Counter(c for q in queries for c in q["gold"]).most_common(8)

    OUT.mkdir(exist_ok=True)
    summary = {"n_queries": len(queries), "skipped": dict(skipped), "label_freq_top8": label_freq,
               "catalog_entries": len(index.ids), "results": results, "leak": leak_split, "leak_free": leak_free}
    (OUT / "results.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False))

    lines = [f"# CWE 검색 평가 (질의 {len(queries)}개, CWE 항목 {len(index.ids)}개)", "",
             "| 방법 | hit@1 | hit@5 (95% CI) | hit@10 | MRR@10 | ms/질의 |", "|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['method']} | {r['hit@1']:.3f} | {r['hit@5']:.3f} ({r['hit@5_ci'][0]:.2f}-{r['hit@5_ci'][1]:.2f}) "
                     f"| {r['hit@10']:.3f} | {r['mrr@10']:.3f} | {r['ms_per_query']} |")
    lines += ["", f"## 누수 없는 비교 (자기 CVE가 관찰 사례에 없는 질의 {len(clean)}개)", "",
              "| 방법 | hit@1 | hit@5 (95% CI) | hit@10 | MRR@10 |", "|---|---|---|---|---|"]
    for r in leak_free:
        lines.append(f"| {r['method']} | {r['hit@1']:.3f} | {r['hit@5']:.3f} ({r['hit@5_ci'][0]:.2f}-{r['hit@5_ci'][1]:.2f}) "
                     f"| {r['hit@10']:.3f} | {r['mrr@10']:.3f} |")
    lines += ["", f"제외한 질의: {dict(skipped)}", f"가장 흔한 정답 라벨: {label_freq}",
              f"질의 CVE가 CWE 관찰 사례에 실려 있는 경우: {len(leaky)}개"]
    (OUT / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
