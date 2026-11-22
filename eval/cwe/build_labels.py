"""8주차 CWE 채점용 정답 라벨과 카탈로그를 만든다 (LLM 호출 없음, 비용 0).

정답 라벨 = GHSA cwe_ids ∪ NVD cwes. 새로 라벨링하지 않았다. 두 출처가 같은 취약점에 다른 CWE를 붙이는
일이 있어서(고유 취약점 432건 중 73건이 일부만 겹치거나 아예 다름) 둘 중 하나라도 맞으면 정답으로 본다.
라벨은 eval/snapshot(CI가 쓰는 데이터 사본)에서 읽어 누구나 같은 결과를 얻는다.
카탈로그(CWE id -> 이름)는 서버 DB의 cwe_entry에서 한 번 내보낸다. DB가 없으면 기존 catalog.json을 쓴다.

  python eval/cwe/build_labels.py          # eval/cwe/labels.json, eval/cwe/catalog.json
"""

import gzip
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent
sys.path.insert(0, str(EVAL))

from casefiles import load_cases, load_gold  # noqa: E402

SNAPSHOT = EVAL / "snapshot"


def _rows(name: str):
    with gzip.open(SNAPSHOT / f"{name}.jsonl.gz", "rt") as f:
        for line in f:
            yield json.loads(line)


def export_catalog() -> dict:
    path = HERE / "catalog.json"
    try:
        from vulnagent.config import load_settings
        from vulnagent.db import connect

        conn = connect(load_settings().database_url)
        rows = conn.execute("SELECT cwe_id, name, catalog_version FROM cwe_entry").fetchall()
    except Exception as exc:  # DB가 없는 곳(CI, 노트북)에서는 커밋된 파일을 그대로 쓴다
        print(f"catalog: using {path.name} ({exc.__class__.__name__})", file=sys.stderr)
        return json.loads(path.read_text())
    number = lambda c: int(c.split("-")[1])
    catalog = {"version": rows[0]["catalog_version"],
               "names": {r["cwe_id"]: r["name"] for r in sorted(rows, key=lambda r: number(r["cwe_id"]))}}
    path.write_text(json.dumps(catalog, indent=0, ensure_ascii=False) + "\n")
    return catalog


def build() -> dict:
    ghsa = {r["id"]: set((r["raw"].get("database_specific") or {}).get("cwe_ids") or []) for r in _rows("osv_vuln")}
    nvd = {r["cve_id"]: set(r.get("cwes") or []) for r in _rows("nvd_cve") if r.get("found")}
    labels = {}
    for case in load_cases():
        for v in load_gold(case["id"])["vulns"]:
            if v["id"] in labels:
                continue
            g = set().union(*(ghsa.get(a, set()) for a in v["aliases"]))
            n = set().union(*(nvd.get(a, set()) for a in v["aliases"]))
            labels[v["id"]] = {"ghsa": sorted(g), "nvd": sorted(n)}
    return dict(sorted(labels.items()))


def main() -> int:
    catalog = export_catalog()
    labels = build()
    (HERE / "labels.json").write_text(json.dumps({"catalog_version": catalog["version"], "labels": labels},
                                                 indent=0, ensure_ascii=False) + "\n")
    known = sum(1 for v in labels.values() if any(c in catalog["names"] for c in v["ghsa"] + v["nvd"]))
    print(f"labels: {len(labels)} vulnerabilities, {known} with a label in CWE {catalog['version']} "
          f"({len(catalog['names'])} entries)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
