"""8주차 사전 점검 (LLM 호출 없음, 비용 0): 평가 케이스의 취약점으로 CWE 검색을 다시 잰다.

4주차 검색 평가와 다른 점
- 질의: 에이전트가 실제로 받는 텍스트. check_packages는 OSV 요약(한 줄)만 주고, NVD 설명은
  get_vulnerability를 불러야 받는다. 두 질의를 모두 잰다.
- 정답: GHSA cwe_ids ∪ NVD cwes (둘 중 하나라도 맞으면 정답). 4주차는 NVD 라벨만 썼다.
- 같은 CVE가 여러 케이스에 반복되므로 취약점 ID로 중복을 없앤다 (pygoat 하나가 555건 중 190건).

이 점검의 목적: 라벨을 숨기고 검색으로 CWE를 고르게 하는 실험군을 돌릴 가치가 있는지 미리 본다.
에이전트가 후보 5개 중에서만 고른다면 hit@5가 그 실험군 정확도의 상한이다.

  python eval/cwe/retrieval_check.py      # 결과: eval/cwe/retrieval_check.json
"""

import json
import math
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from casefiles import load_cases, load_gold  # noqa: E402

from vulnagent.config import load_settings  # noqa: E402
from vulnagent.db import connect  # noqa: E402
from vulnagent.kb.search import CweIndex  # noqa: E402

OUT = Path(__file__).parent / "retrieval_check.json"
KS = (1, 3, 5, 10)


def wilson(p: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    phat = p / n
    centre = (phat + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(centre - half, 3), round(centre + half, 3)]


def labels_for(conn, aliases: list[str]) -> tuple[set[str], set[str], str | None, str | None]:
    """(GHSA 라벨, NVD 라벨, OSV 요약, NVD 설명). OSV 요약은 summarize_group과 같은 순서(GHSA 먼저)로 고른다."""
    ghsa, nvd = set(), set()
    rows = conn.execute("SELECT id, summary, raw FROM osv_vuln WHERE id = ANY(%s)", (aliases,)).fetchall()
    rows.sort(key=lambda r: (not r["id"].startswith("GHSA-"), r["id"]))
    summary = next((r["summary"] for r in rows if r["summary"]), None)
    for r in rows:
        ghsa |= set((r["raw"].get("database_specific") or {}).get("cwe_ids") or [])
    desc = None
    for r in conn.execute("SELECT cve_id, description, cwes FROM nvd_cve WHERE found AND cve_id = ANY(%s)", (aliases,)):
        nvd |= set(r["cwes"] or [])
        desc = desc or r["description"]
    return ghsa, nvd, summary, desc


def evaluate(index: CweIndex, queries: list[dict], field: str) -> dict:
    hits = Counter()
    usable = [q for q in queries if q[field]]
    for q in usable:
        ranked = [cid for cid, _ in index.bm25_search(q[field], 10)]
        first = next((i for i, cid in enumerate(ranked, 1) if cid in q["gold"]), None)
        for k in KS:
            hits[k] += first is not None and first <= k
    n = len(usable)
    return {"n": n, **{f"hit@{k}": round(hits[k] / n, 3) if n else None for k in KS},
            "hit@1_ci": wilson(hits[1], n), "hit@5_ci": wilson(hits[5], n)}


def main() -> int:
    conn = connect(load_settings().database_url)
    index = CweIndex(conn, include_observed=True)  # security-kb 서버 기본값 (4주차 채택)
    observed = {c for r in conn.execute("SELECT observed_cves FROM cwe_entry") for c in r["observed_cves"]}

    seen, queries, skipped = set(), [], Counter()
    agree = Counter()
    for case in load_cases():
        for v in load_gold(case["id"])["vulns"]:
            if v["id"] in seen:
                continue
            seen.add(v["id"])
            ghsa, nvd, summary, desc = labels_for(conn, v["aliases"])
            gold = {c for c in ghsa | nvd if c in index}
            if not ghsa | nvd:
                skipped["no label"] += 1
                continue
            if not gold:
                skipped["label not in catalog"] += 1
                continue
            if ghsa and nvd:
                agree["same set" if ghsa == nvd else "overlap" if ghsa & nvd else "disjoint"] += 1
            queries.append({"id": v["id"], "gold": gold, "osv_summary": summary, "nvd_description": desc,
                            "leaky": any(a in observed for a in v["aliases"])})

    clean = [q for q in queries if not q["leaky"]]
    result = {
        "unique_vulnerabilities": len(seen), "queries": len(queries), "skipped": dict(skipped),
        "ghsa_vs_nvd_when_both": dict(agree),
        "label_freq_top10": Counter(c for q in queries for c in q["gold"]).most_common(10),
        "all": {f: evaluate(index, queries, f) for f in ("osv_summary", "nvd_description")},
        "leak_free": {f: evaluate(index, clean, f) for f in ("osv_summary", "nvd_description")},
        "leaky_queries": len(queries) - len(clean),
    }
    OUT.write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps(result, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
