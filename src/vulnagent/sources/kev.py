"""CISA KEV (Known Exploited Vulnerabilities): 실제 공격에 쓰인 것이 확인된 CVE 목록.

수집 방식: 벌크 스냅샷. 전체가 약 1,800건(약 1.8MB)이라 통째로 받는 게 가장 단순하고 정확하다.
catalogVersion(예: 2026.11.20)을 스냅샷 키로 쓴다. 이미 있는 버전이면 다시 넣지 않는다(멱등).

주의: KEV에 없다고 "악용되지 않는다"는 뜻이 아니다. CISA가 확인해서 등재한 것만 있다.
"""

import httpx
import psycopg
from psycopg.types.json import Jsonb

from ..errors import SourceError
from ..http import request
from ..ids import normalize_cve, parse_ts

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_catalog(client: httpx.Client) -> dict:
    r = request(client, "GET", URL)
    if r.status_code >= 400:
        raise SourceError(f"KEV HTTP {r.status_code}")
    return r.json()


def load_snapshot(conn: psycopg.Connection, catalog: dict) -> bool:
    """새 스냅샷이면 적재하고 True. 스냅샷 헤더와 항목을 한 트랜잭션으로 넣는다
    (중간에 실패하면 반쪽짜리 스냅샷이 남지 않는다)."""
    version = catalog["catalogVersion"]
    entries = catalog.get("vulnerabilities", [])
    with conn.transaction():
        inserted = conn.execute(
            """
            INSERT INTO kev_snapshot (catalog_version, date_released, entry_count)
            VALUES (%s, %s, %s) ON CONFLICT DO NOTHING RETURNING catalog_version
            """,
            (version, parse_ts(catalog.get("dateReleased")), len(entries)),
        ).fetchone()
        if not inserted:
            # 같은 버전을 다시 받았다 = 아직 새 카탈로그가 안 나왔다. "마지막 확인 시각"만 갱신해서
            # 갱신 주기 판단(service.ensure_bulk_data)이 매번 다시 내려받지 않게 한다.
            conn.execute("UPDATE kev_snapshot SET fetched_at = now() WHERE catalog_version = %s", (version,))
            return False
        rows = []
        for e in entries:
            cve = normalize_cve(e.get("cveID", ""))
            if not cve:
                continue
            rows.append(
                (
                    version, cve, e.get("vendorProject"), e.get("product"), e.get("vulnerabilityName"),
                    e.get("dateAdded") or None, e.get("dueDate") or None,
                    e.get("knownRansomwareCampaignUse"), e.get("requiredAction"), Jsonb(e),
                )
            )
        # 약 1,800행은 executemany로 충분하다. 40만 행인 EPSS는 COPY를 쓴다 (epss.py).
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO kev_entry (catalog_version, cve_id, vendor_project, product, vulnerability_name,
                                       date_added, due_date, known_ransomware, required_action, raw)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                rows,
            )
    return True


def lookup(conn: psycopg.Connection, catalog_version: str, cve_ids: list[str]) -> dict[str, dict]:
    rows = conn.execute(
        """
        SELECT cve_id, vulnerability_name, date_added, due_date, known_ransomware, required_action
        FROM kev_entry WHERE catalog_version = %s AND cve_id = ANY(%s)
        """,
        (catalog_version, cve_ids),
    )
    return {r["cve_id"]: r for r in rows}
