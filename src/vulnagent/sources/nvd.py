"""NVD (NIST): CVE 상세 - 설명, CVSS 점수, CWE.

수집 방식: 요청 시 조회 + 캐시. 전체 CVE가 수십만 건인데 키 없이 30초에 5회라서
벌크 미러링은 비현실적이다. 필요한 CVE만, 그것도 상세 조회 때만 부른다.

데이터 함정 (실제 응답에서 확인한 것)
- NVD 자체 점수(Primary)가 없는 CVE가 많다. 2026-10-01~03 공개 CVE 200건 표본에서
  NVD Primary 점수는 3건뿐, 170건이 'Deferred'. 대신 199건은 CNA가 낸 Secondary 점수가 있다.
  -> Primary만 보면 거의 다 "점수 없음"이 된다. Secondary로 대체하고 출처를 함께 돌려준다.
- metrics 안에 CVSS가 아닌 항목(ssvcV203: CISA의 SSVC 판단)이 섞여 있다. cvssMetric* 키만 본다.
- 없는 CVE를 물어도 404가 아니라 200 + 빈 배열이 온다.
"""

from datetime import datetime, timedelta, timezone

import httpx
import psycopg
from psycopg.types.json import Jsonb

from ..errors import SourceError
from ..http import RETRYABLE, RateLimiter, request
from ..ids import parse_ts

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 점수 선택 우선순위: 버전 먼저, 같은 버전 안에서는 Primary(NVD) 먼저.
# v3.1을 먼저 보는 이유: 가장 많은 CVE가 가지고 있어서 CVE끼리 비교가 된다.
# v4.0은 점수 체계가 달라 v3 점수와 같은 잣대로 비교하면 안 된다.
VERSION_PREFERENCE = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]

# 아직 분석이 끝나지 않은 상태 -> 곧 점수/CWE가 붙을 수 있으니 캐시를 짧게.
PENDING_STATUSES = {"Received", "Awaiting Analysis", "Undergoing Analysis"}

# metrics.source에는 이메일이나 UUID가 온다. 사람이 읽을 수 있게 알려진 것만 이름을 붙인다.
KNOWN_SOURCES = {
    "nvd@nist.gov": "NVD",
    "134c704f-9b21-4f2e-91b3-4a467353bcc0": "CISA-ADP",  # CISA Vulnrichment
}


def make_limiter(api_key: str | None) -> RateLimiter:
    return RateLimiter(50 if api_key else 5, 30.0)


# ---------------------------------------------------------------- 네트워크
def fetch_cve(client: httpx.Client, limiter: RateLimiter, api_key: str | None, cve_id: str) -> dict | None:
    headers = {"apiKey": api_key} if api_key else {}
    # 2025년 5월 전에는 한도 초과를 403으로 줬다. 둘 다 재시도 대상으로 둔다.
    r = request(
        client, "GET", API, params={"cveId": cve_id}, headers=headers,
        limiter=limiter, retryable=RETRYABLE | {403},
    )
    if r.status_code >= 400:
        raise SourceError(f"NVD HTTP {r.status_code}: {r.text[:200]}")
    vulns = r.json().get("vulnerabilities", [])
    return vulns[0]["cve"] if vulns else None


# ---------------------------------------------------------------- 정규화 (순수 함수)
def source_name(source: str | None) -> str | None:
    if source is None:
        return None
    return KNOWN_SOURCES.get(source, source)


def pick_cvss(metrics: dict) -> dict | None:
    for key in VERSION_PREFERENCE:
        entries = metrics.get(key) or []
        if not entries:
            continue
        best = sorted(entries, key=lambda m: m.get("type") != "Primary")[0]
        data = best.get("cvssData", {})
        return {
            "score": data.get("baseScore"),
            # v2는 baseSeverity가 cvssData가 아니라 바깥에 있다.
            "severity": data.get("baseSeverity") or best.get("baseSeverity"),
            "version": data.get("version"),
            "vector": data.get("vectorString"),
            "source": source_name(best.get("source")),
            "type": best.get("type"),
        }
    return None


def normalize(cve: dict) -> dict:
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    cwes = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")  # NVD-CWE-Other / NVD-CWE-noinfo 제외
        }
    )
    return {
        "cve_id": cve["id"],
        "vuln_status": cve.get("vulnStatus"),
        "published": parse_ts(cve.get("published")),
        "last_modified": parse_ts(cve.get("lastModified")),
        "description": description,
        "cvss": pick_cvss(cve.get("metrics", {})),
        "cwes": cwes,
    }


def top_references(cve: dict, limit: int = 3) -> list[dict]:
    """인용용 참고 링크 몇 개. 패치/벤더 권고 태그가 붙은 것을 우선한다."""
    def rank(ref: dict) -> int:
        tags = set(ref.get("tags", []))
        return 0 if "Patch" in tags else 1 if "Vendor Advisory" in tags else 2

    unique = {r["url"]: r for r in cve.get("references", [])}  # 같은 URL이 출처별로 중복 등록된다
    refs = sorted(unique.values(), key=rank)[:limit]
    return [{"url": r["url"], "tags": r.get("tags", [])} for r in refs]


# ---------------------------------------------------------------- 캐시 (DB)
def store(conn: psycopg.Connection, cve_id: str, cve: dict | None) -> None:
    if cve is None:
        conn.execute(
            """
            INSERT INTO nvd_cve (cve_id, found, fetched_at) VALUES (%s, false, now())
            ON CONFLICT (cve_id) DO UPDATE SET found = false, raw = NULL, fetched_at = now()
            """,
            (cve_id,),
        )
        return
    n = normalize(cve)
    cvss = n["cvss"] or {}
    conn.execute(
        """
        INSERT INTO nvd_cve (cve_id, found, vuln_status, published, last_modified, description,
                             cvss_score, cvss_severity, cvss_version, cvss_vector, cvss_source, cvss_type,
                             cwes, raw, fetched_at)
        VALUES (%s, true, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
        ON CONFLICT (cve_id) DO UPDATE SET
            found = true, vuln_status = EXCLUDED.vuln_status, published = EXCLUDED.published,
            last_modified = EXCLUDED.last_modified, description = EXCLUDED.description,
            cvss_score = EXCLUDED.cvss_score, cvss_severity = EXCLUDED.cvss_severity,
            cvss_version = EXCLUDED.cvss_version, cvss_vector = EXCLUDED.cvss_vector,
            cvss_source = EXCLUDED.cvss_source, cvss_type = EXCLUDED.cvss_type,
            cwes = EXCLUDED.cwes, raw = EXCLUDED.raw, fetched_at = now()
        """,
        (
            cve_id, n["vuln_status"], n["published"], n["last_modified"], n["description"],
            cvss.get("score"), cvss.get("severity"), cvss.get("version"), cvss.get("vector"),
            cvss.get("source"), cvss.get("type"), n["cwes"], Jsonb(cve),
        ),
    )


def is_fresh(row: dict, ttl_hours: int, pending_ttl_hours: int, notfound_ttl_hours: int) -> bool:
    if not row["found"]:
        ttl = notfound_ttl_hours
    elif row["vuln_status"] in PENDING_STATUSES:
        ttl = pending_ttl_hours
    else:
        ttl = ttl_hours
    return row["fetched_at"] > datetime.now(timezone.utc) - timedelta(hours=ttl)


def get_cached(conn: psycopg.Connection, cve_id: str) -> dict | None:
    return conn.execute("SELECT * FROM nvd_cve WHERE cve_id = %s", (cve_id,)).fetchone()
