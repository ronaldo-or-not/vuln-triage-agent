"""OSV (osv.dev): "이 패키지의 이 버전에 알려진 취약점이 있나?"

수집 방식: 요청 시 조회 + 캐시.
- querybatch로 여러 패키지를 한 번에 물으면 각 패키지의 (취약점 ID, modified)만 온다.
- 캐시에 없거나 modified가 바뀐 레코드만 /vulns/{id}로 상세를 받는다.
  -> 같은 의존성 목록을 다시 검사하면 상세 요청이 거의 0이 된다.

데이터 함정 (실제 응답에서 확인한 것)
- 같은 취약점을 여러 DB가 각자 기록한다. jinja2 2.10 조회 결과는 12건이지만
  GHSA와 PYSEC가 같은 CVE를 중복 기록한 것이라 실제로는 6건이다 -> group_records()
- 결과가 없으면 `{}`가 온다(vulns 키 자체가 없음). "모르는 패키지"와 "취약점 없음"이 구분되지 않는다.
- 심각도(severity)는 점수가 아니라 CVSS 벡터 문자열이고, PYSEC 레코드에는 아예 없다.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import psycopg
from psycopg.types.json import Jsonb

from ..errors import InvalidInput, SourceError
from ..http import request
from ..ids import normalize_cve, normalize_package_name, parse_ts

API = "https://api.osv.dev/v1"
BATCH_LIMIT = 1000  # querybatch 한 번에 넣을 수 있는 최대 질의 수

PackageKey = tuple[str, str, str]  # (ecosystem, 정규화된 이름, version)


# ---------------------------------------------------------------- 네트워크
def fetch_batch(client: httpx.Client, keys: list[PackageKey]) -> dict[PackageKey, list[dict]]:
    """패키지마다 [{id, modified}, ...]를 돌려준다."""
    out: dict[PackageKey, list[dict]] = {}
    for start in range(0, len(keys), BATCH_LIMIT):
        chunk = keys[start : start + BATCH_LIMIT]
        queries = [_query(k) for k in chunk]
        r = request(client, "POST", f"{API}/querybatch", json={"queries": queries})
        if r.status_code == 400:
            raise InvalidInput(f"OSV rejected the query: {r.json().get('message', r.text)}")
        _raise_for_status(r)
        for key, query, result in zip(chunk, queries, r.json().get("results", [])):
            vulns = [{"id": v["id"], "modified": v["modified"]} for v in result.get("vulns", [])]
            token = result.get("next_page_token")
            while token:  # 결과가 많은 패키지는 페이지가 나뉜다
                page = request(client, "POST", f"{API}/query", json={**query, "page_token": token})
                _raise_for_status(page)
                body = page.json()
                vulns += [{"id": v["id"], "modified": v["modified"]} for v in body.get("vulns", [])]
                token = body.get("next_page_token")
            out[key] = vulns
    return out


def fetch_vuln(client: httpx.Client, vuln_id: str) -> dict | None:
    r = request(client, "GET", f"{API}/vulns/{vuln_id}")
    if r.status_code == 404:
        return None
    _raise_for_status(r)
    return r.json()


def _query(key: PackageKey) -> dict:
    ecosystem, name, version = key
    return {"package": {"ecosystem": ecosystem, "name": name}, "version": version}


def _raise_for_status(r: httpx.Response) -> None:
    if r.status_code >= 400:
        raise SourceError(f"OSV HTTP {r.status_code}: {r.text[:200]}")


# ---------------------------------------------------------------- 정규화 (순수 함수)
def cve_ids_of(record: dict) -> list[str]:
    ids = {normalize_cve(a) for a in [record.get("id", ""), *record.get("aliases", [])]}
    return sorted(i for i in ids if i)


def group_records(records: list[dict]) -> list[list[dict]]:
    """같은 취약점을 가리키는 레코드끼리 묶는다 (별칭 그래프의 연결 요소, union-find).

    GHSA-462w-v97r-4m45 의 aliases = [CVE-2019-10906, PYSEC-2019-217]
    PYSEC-2019-217      의 aliases = [CVE-2019-10906, GHSA-462w-v97r-4m45]
    -> 둘은 한 그룹. 대표 ID는 CVE (KEV/EPSS/NVD가 전부 CVE 기준이라서).
    """
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for rec in records:
        for alias in rec.get("aliases", []):
            parent[find(rec["id"])] = find(alias)
        find(rec["id"])

    groups: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        groups[find(rec["id"])].append(rec)
    return list(groups.values())


def package_fix_info(record: dict, ecosystem: str, name: str) -> dict:
    """레코드에서 '조회한 그 패키지'에 해당하는 affected 항목만 보고 수정 버전을 뽑는다.

    한 레코드가 여러 패키지를 다루기도 하므로 다른 패키지의 범위를 섞으면 안 된다.
    GIT 범위는 커밋 해시라 버전 업그레이드 안내에 쓸 수 없어서 제외한다.
    """
    fixed: set[str] = set()
    last_affected: set[str] = set()
    open_ended = False  # 수정 버전이 없는 범위가 있음 = 아직 패치 없음
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] != ecosystem:
            continue
        if normalize_package_name(ecosystem, pkg.get("name", "")) != name:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") == "GIT":
                continue
            fixes = [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
            # last_affected: "이 버전까지 영향". 수정 버전은 없지만 그보다 높은 버전은 영향이 없다는 뜻.
            # 2주차 파일럿에서 이 정보를 버려 에이전트가 'pyjwt는 고칠 수 없다'고 잘못 결론 낸 일이 있었다.
            lasts = [e["last_affected"] for e in rng.get("events", []) if "last_affected" in e]
            fixed.update(fixes)
            last_affected.update(lasts)
            if not fixes:
                open_ended = True
    return {"fixed": fixed, "open_ended": open_ended, "last_affected": last_affected}


def summarize_group(group: list[dict], ecosystem: str, name: str) -> dict:
    """한 그룹(=취약점 하나)을 에이전트에게 줄 작은 dict로 만든다.

    수정 버전이 레코드끼리 다르면 고르지 않고 전부 보여주고 disagree 플래그를 켠다.
    어느 쪽이 맞는지 판단하려면 생태계별 버전 비교 규칙이 필요하다 (이후 주차에서).
    """
    # GHSA 레코드가 보통 요약·심각도 라벨이 가장 충실해서 앞에 둔다.
    group = sorted(group, key=lambda r: (not r["id"].startswith("GHSA-"), r["id"]))
    cves = sorted({c for r in group for c in cve_ids_of(r)})
    fix_infos = [package_fix_info(r, ecosystem, name) for r in group]
    fix_sets = {frozenset(f["fixed"]) for f in fix_infos}
    fixed = sorted(set().union(*(f["fixed"] for f in fix_infos)))
    last_affected = sorted(set().union(*(f["last_affected"] for f in fix_infos)))

    label, vector = None, None
    for r in group:
        label = label or (r.get("database_specific") or {}).get("severity")
        for sev in r.get("severity", []):
            if sev.get("type") == "CVSS_V3" or (sev.get("type") == "CVSS_V4" and not vector):
                vector = sev.get("score")

    summary = {
        "id": cves[0] if cves else group[0]["id"],
        "cve_ids": cves,
        "osv_ids": [r["id"] for r in group],
        "summary": next((r.get("summary") for r in group if r.get("summary")), None),
        "fixed_versions": fixed,
        "fix_available": bool(fixed),
        "fixed_versions_disagree": len(fix_sets) > 1,
        "severity_label": {"value": label, "source": "GHSA"} if label else None,
        "cvss_vector": vector,
        "withdrawn": all(r.get("withdrawn") for r in group),
    }
    if last_affected:  # 있을 때만 넣는다 (대부분의 취약점에는 없어서 토큰 절약)
        summary["last_affected"] = last_affected
    return summary


# ---------------------------------------------------------------- 캐시 (DB)
def store_vuln(conn: psycopg.Connection, record: dict) -> None:
    conn.execute(
        """
        INSERT INTO osv_vuln (id, modified, published, withdrawn, summary, aliases, cve_ids, raw, fetched_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
        ON CONFLICT (id) DO UPDATE SET
            modified = EXCLUDED.modified, published = EXCLUDED.published,
            withdrawn = EXCLUDED.withdrawn, summary = EXCLUDED.summary,
            aliases = EXCLUDED.aliases, cve_ids = EXCLUDED.cve_ids,
            raw = EXCLUDED.raw, fetched_at = now()
        """,
        (
            record["id"],
            parse_ts(record["modified"]),
            parse_ts(record.get("published")),
            parse_ts(record.get("withdrawn")),
            record.get("summary"),
            record.get("aliases", []),
            cve_ids_of(record),
            Jsonb(record),
        ),
    )


def store_package_query(conn: psycopg.Connection, key: PackageKey, vuln_ids: list[str]) -> None:
    conn.execute(
        """
        INSERT INTO osv_package_query (ecosystem, name, version, vuln_ids, fetched_at)
        VALUES (%s, %s, %s, %s, now())
        ON CONFLICT (ecosystem, name, version) DO UPDATE SET
            vuln_ids = EXCLUDED.vuln_ids, fetched_at = now()
        """,
        (*key, sorted(vuln_ids)),
    )


def lookup_packages(
    conn: psycopg.Connection,
    client: httpx.Client | None,
    keys: list[PackageKey],
    ttl_hours: int,
) -> dict[PackageKey, dict[str, Any]]:
    """패키지마다 {"records": [...], "fetched_at": datetime | None}.

    client가 None이면 오프라인: 캐시에 없는 패키지는 records=None으로 돌려준다.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    cached = _select_queries(conn, keys)
    stale = [k for k in keys if k not in cached or cached[k]["fetched_at"] < cutoff]

    if stale and client is not None:
        found = fetch_batch(client, stale)
        wanted = {v["id"]: parse_ts(v["modified"]) for vulns in found.values() for v in vulns}
        have = {
            row["id"]: row["modified"]
            for row in conn.execute("SELECT id, modified FROM osv_vuln WHERE id = ANY(%s)", (list(wanted),))
        }
        for vuln_id, modified in wanted.items():
            if vuln_id not in have or have[vuln_id] < modified:
                record = fetch_vuln(client, vuln_id)
                if record:
                    store_vuln(conn, record)
        for key, vulns in found.items():
            store_package_query(conn, key, [v["id"] for v in vulns])
        cached.update(_select_queries(conn, stale))

    all_ids = sorted({i for k in keys if k in cached for i in cached[k]["vuln_ids"]})
    raws = {row["id"]: row["raw"] for row in conn.execute("SELECT id, raw FROM osv_vuln WHERE id = ANY(%s)", (all_ids,))}
    out: dict[PackageKey, dict[str, Any]] = {}
    for key in keys:
        row = cached.get(key)
        if row is None:
            out[key] = {"records": None, "fetched_at": None}
        else:
            out[key] = {"records": [raws[i] for i in row["vuln_ids"] if i in raws], "fetched_at": row["fetched_at"]}
    return out


def _select_queries(conn: psycopg.Connection, keys: list[PackageKey]) -> dict[PackageKey, dict]:
    """(생태계, 이름, 버전) 여러 개를 한 번의 쿼리로 조회. 세 배열을 unnest해서 조인한다."""
    if not keys:
        return {}
    ecosystems, names, versions = (list(col) for col in zip(*keys))
    rows = conn.execute(
        """
        SELECT q.* FROM osv_package_query q
        JOIN unnest(%s::text[], %s::text[], %s::text[]) AS k(ecosystem, name, version)
          USING (ecosystem, name, version)
        """,
        (ecosystems, names, versions),
    )
    return {(r["ecosystem"], r["name"], r["version"]): r for r in rows}


def get_vuln(conn: psycopg.Connection, client: httpx.Client | None, vuln_id: str) -> dict | None:
    row = conn.execute("SELECT raw FROM osv_vuln WHERE id = %s", (vuln_id,)).fetchone()
    if row:
        return row["raw"]
    if client is None:
        return None
    record = fetch_vuln(client, vuln_id)
    if record:
        store_vuln(conn, record)
    return record


def records_for_cve(conn: psycopg.Connection, cve_id: str) -> list[dict]:
    """캐시에 있는 OSV 레코드 중 이 CVE를 별칭으로 가진 것 (GIN 인덱스 사용)."""
    return [row["raw"] for row in conn.execute("SELECT raw FROM osv_vuln WHERE cve_ids @> %s", ([cve_id],))]
