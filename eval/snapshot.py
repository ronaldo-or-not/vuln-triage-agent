"""평가 데이터 스냅샷: 평가에 필요한 DB 행만 작은 파일로 내보내고, 빈 DB에 다시 넣는다.

지금까지 평가는 서버 DB(OSV/NVD 캐시, 고정된 KEV/EPSS 스냅샷)에 묶여 있었다. 이 파일들이 있으면
어떤 PostgreSQL에서도 VULNAGENT_OFFLINE=1로 같은 도구 결과가 나와, 정답 재계산과 에이전트 평가를 재현할 수 있다.

  python eval/snapshot.py export     # 서버에서: eval/snapshot/*.jsonl.gz
  python eval/snapshot.py load       # 빈 DB에: 스키마 생성 후 적재 (CI가 이걸로 정답을 다시 계산해 비교한다)

내보내는 것
- osv_package_query / osv_vuln: 케이스 패키지의 질의 결과와 그 레코드 (CVE 형식 OSV 레코드 포함)
- nvd_cve: 정답에 나온 CVE
- kev_snapshot / kev_entry, epss_snapshot / epss_score: 고정 날짜 스냅샷 중 정답 CVE에 해당하는 행만
  (스냅샷 전체는 크다. 평가 도구는 결과에 나온 CVE만 조회하므로 이걸로 충분하다)
"""

import gzip
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from casefiles import AS_OF, load_cases, parse_case  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402

from vulnagent.config import load_settings  # noqa: E402
from vulnagent.db import apply_schema, connect  # noqa: E402
from vulnagent.ids import normalize_cve, normalize_package_name  # noqa: E402

OUT = Path(__file__).parent / "snapshot"
TABLES = {  # 테이블 -> JSONB 열
    "osv_vuln": ["raw"], "osv_package_query": [], "nvd_cve": ["raw"],
    "kev_snapshot": [], "kev_entry": ["raw"], "epss_snapshot": [], "epss_score": [],
}


def _gold_cves() -> list[str]:
    cves = set()
    for path in (Path(__file__).parent / "gold").glob("*.json"):
        for v in json.loads(path.read_text())["vulns"]:
            cves |= {c for c in [v["id"], *v["aliases"]] if normalize_cve(c)}
    return sorted(cves)


def _write(name: str, rows: list[dict]) -> None:
    with gzip.open(OUT / f"{name}.jsonl.gz", "wt", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")


def export() -> int:
    conn = connect(load_settings().database_url)
    OUT.mkdir(exist_ok=True)
    keys = sorted({(d.ecosystem, normalize_package_name(d.ecosystem, d.name), d.version)
                   for case in load_cases() for d in parse_case(case).dependencies})
    eco, names, vers = (list(c) for c in zip(*keys))
    queries = conn.execute(
        "SELECT q.* FROM osv_package_query q JOIN unnest(%s::text[], %s::text[], %s::text[]) AS k(ecosystem, name, version) "
        "USING (ecosystem, name, version)", (eco, names, vers)).fetchall()
    cves = _gold_cves()
    vuln_ids = sorted({i for q in queries for i in q["vuln_ids"]})
    vulns = conn.execute("SELECT * FROM osv_vuln WHERE id = ANY(%s) OR cve_ids && %s", (vuln_ids, cves)).fetchall()
    nvd = conn.execute("SELECT * FROM nvd_cve WHERE cve_id = ANY(%s)", (cves,)).fetchall()
    kev_snap = conn.execute("SELECT * FROM kev_snapshot WHERE pinned").fetchall()
    kev = conn.execute("SELECT * FROM kev_entry WHERE catalog_version = ANY(%s) AND cve_id = ANY(%s)",
                       ([r["catalog_version"] for r in kev_snap], cves)).fetchall()
    epss_snap = conn.execute("SELECT * FROM epss_snapshot WHERE pinned").fetchall()
    epss = conn.execute("SELECT * FROM epss_score WHERE score_date = ANY(%s) AND cve_id = ANY(%s)",
                        ([r["score_date"] for r in epss_snap], cves)).fetchall()
    data = {"osv_package_query": queries, "osv_vuln": vulns, "nvd_cve": nvd, "kev_snapshot": kev_snap,
            "kev_entry": kev, "epss_snapshot": epss_snap, "epss_score": epss}
    for name, rows in data.items():
        _write(name, rows)
        print(f"{name}: {len(rows)} rows", file=sys.stderr)
    (OUT / "README.md").write_text(
        f"평가 데이터 스냅샷 (기준일 {AS_OF}). `python eval/snapshot.py load`로 빈 DB에 적재. "
        "KEV/EPSS는 정답 CVE에 해당하는 행만 담았다.\n", encoding="utf-8")
    return 0


def load() -> int:
    conn = connect(load_settings().database_url)
    apply_schema(conn)
    order = ["kev_snapshot", "kev_entry", "epss_snapshot", "epss_score", "osv_vuln", "osv_package_query", "nvd_cve"]
    with conn.transaction():
        for name in order:
            path = OUT / f"{name}.jsonl.gz"
            with gzip.open(path, "rt", encoding="utf-8") as f:
                rows = [json.loads(line) for line in f]
            if not rows:
                continue
            cols = list(rows[0])
            values = [[Jsonb(r[c]) if c in TABLES[name] and r[c] is not None else r[c] for c in cols] for r in rows]
            placeholders = ", ".join(["%s"] * len(cols))
            with conn.cursor() as cur:
                cur.executemany(f"INSERT INTO {name} ({', '.join(cols)}) VALUES ({placeholders}) ON CONFLICT DO NOTHING", values)
            print(f"{name}: {len(rows)} rows", file=sys.stderr)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("export", "load"):
        print(__doc__)
        sys.exit(2)
    sys.exit(export() if sys.argv[1] == "export" else load())
