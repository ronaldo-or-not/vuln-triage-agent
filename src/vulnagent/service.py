"""소스 4개를 합쳐 에이전트가 쓸 두 가지 기능을 제공한다.

- check_packages: 패키지 목록 -> 패키지별 취약점 + KEV/EPSS (빠름: OSV + 로컬 스냅샷만 사용)
- get_vulnerability: 취약점 하나 -> NVD 상세(설명, CVSS, CWE) + KEV/EPSS + OSV 수정 버전

설계 원칙
- 데이터 레이어는 판단하지 않는다. 우선순위를 매기거나 정렬하지 않고 사실과 출처만 돌려준다.
  우선순위 판단은 에이전트(LLM)의 일이고, 2주차 평가에서 그 판단을 KEV/EPSS와 비교해 채점한다.
- "없음"과 "모름"을 구분한다. KEV 스냅샷이 아예 없으면 kev=None(모름), 스냅샷은 있는데
  목록에 없으면 kev=False(등재 안 됨). EPSS 점수가 없으면 0이 아니라 None.
- check_packages에서는 NVD를 부르지 않는다. 패키지 50개에 CVE 100개면 NVD 한도(30초에 5회)로
  10분이 걸린다. NVD는 상세 조회(get_vulnerability)에서 CVE 하나씩만 부른다.
"""

import logging
from datetime import date, datetime, timedelta, timezone

import httpx
import psycopg

from .config import Settings
from .errors import InvalidInput, SourceError
from .http import make_client
from .ids import ECOSYSTEMS, normalize_cve, normalize_ecosystem, normalize_package_name, normalize_vuln_id
from .sources import epss, kev, nvd, osv
from .versions import min_safe_upgrade

log = logging.getLogger(__name__)

MAX_PACKAGES = 200
RANGE_CHARS = set("<>=^~*, ")

NO_VULNS_NOTE = (
    "OSV returned no known vulnerabilities. This does not prove the package is safe: "
    "OSV gives the same empty answer for a misspelled or unknown package name."
)
STATUS_NOTES = {
    "Deferred": "NVD deferred its own analysis; an NVD score is not expected. Any score shown comes from the CNA or CISA.",
    "Rejected": "This CVE was rejected (duplicate or not a vulnerability). Do not treat it as a real vulnerability.",
}
PENDING_NOTE = "NVD analysis is not finished; the score and CWEs may still change."


def _iso(value: datetime | date | None) -> str | None:
    return value.isoformat() if value else None


class VulnService:
    def __init__(self, conn: psycopg.Connection, settings: Settings, client: httpx.Client | None = None):
        self.conn = conn
        self.settings = settings
        self.client = None if settings.offline else (client or make_client(settings.user_agent))
        self.nvd_limiter = nvd.make_limiter(settings.nvd_api_key)

    # ------------------------------------------------------------ 벌크 스냅샷 관리
    def sync_bulk(self, force: bool = False) -> dict:
        """KEV/EPSS 스냅샷을 새로 받는다. force=False면 갱신 주기가 지난 것만."""
        if self.client is None:
            raise SourceError("offline mode: cannot download snapshots")
        report = {}
        for name, table, refresh in (
            ("kev", "kev_snapshot", self._refresh_kev),
            ("epss", "epss_snapshot", self._refresh_epss),
        ):
            if force or self._is_stale(table):
                report[name] = refresh()
            else:
                report[name] = "fresh"
        report["pruned"] = self.prune()
        return report

    def ensure_bulk_data(self) -> list[str]:
        """도구 호출마다 실행: 스냅샷이 오래됐으면 갱신을 시도하고, 실패해도 멈추지 않고 경고만 남긴다."""
        warnings = []
        for name, table, refresh in (
            ("KEV", "kev_snapshot", self._refresh_kev),
            ("EPSS", "epss_snapshot", self._refresh_epss),
        ):
            has_any = self.conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None
            if self._is_stale(table) and self.client is not None:
                try:
                    refresh()
                except SourceError as exc:
                    log.warning("%s refresh failed: %s", name, exc)
                    warnings.append(
                        f"{name} refresh failed; using the older snapshot." if has_any else f"{name} data unavailable: {exc}"
                    )
            elif not has_any:
                warnings.append(f"{name} data unavailable (offline mode and no snapshot loaded).")
        return warnings

    def _is_stale(self, table: str) -> bool:
        latest = self.conn.execute(f"SELECT max(fetched_at) AS t FROM {table}").fetchone()["t"]
        return latest is None or latest < datetime.now(timezone.utc) - timedelta(hours=self.settings.bulk_refresh_hours)

    def _refresh_kev(self) -> str:
        catalog = kev.fetch_catalog(self.client)
        new = kev.load_snapshot(self.conn, catalog)
        return f"{'loaded' if new else 'unchanged'} {catalog['catalogVersion']} ({len(catalog.get('vulnerabilities', []))} entries)"

    def _refresh_epss(self) -> str:
        meta, rows = epss.parse_csv(epss.fetch_current(self.client))
        new = epss.load_snapshot(self.conn, meta, rows)
        return f"{'loaded' if new else 'unchanged'} {meta['score_date']} ({len(rows)} rows, {meta['model_version']})"

    def prune(self) -> int:
        """pinned가 아닌 스냅샷은 최근 keep_snapshots개만 남긴다 (EPSS는 하루 41만 행이라 계속 쌓으면 커진다)."""
        deleted = 0
        for table, key in (("kev_snapshot", "catalog_version"), ("epss_snapshot", "score_date")):
            cur = self.conn.execute(
                f"""
                DELETE FROM {table} WHERE NOT pinned AND {key} NOT IN (
                    SELECT {key} FROM {table} WHERE NOT pinned ORDER BY {key} DESC LIMIT %s)
                """,
                (self.settings.keep_snapshots,),
            )
            deleted += cur.rowcount
        return deleted

    def snapshots(self, as_of: date | None = None) -> dict:
        """as_of 시점에 쓸 수 있었던 가장 최근 스냅샷. None이면 설정(VULNAGENT_AS_OF), 그것도 없으면 최신."""
        as_of = as_of or self.settings.as_of
        # date_released는 UTC 기준으로 날짜를 뽑는다. 세션 시간대(KST)로 자르면
        # 2026-11-20T17:48Z 카탈로그가 11-21이 되어 as_of=11-20에서 빠지는 버그가 있었다.
        kev_row = self.conn.execute(
            """
            SELECT catalog_version, date_released FROM kev_snapshot
            WHERE %(d)s::date IS NULL OR (date_released AT TIME ZONE 'UTC')::date <= %(d)s::date
            ORDER BY catalog_version DESC LIMIT 1
            """,
            {"d": as_of},
        ).fetchone()
        epss_row = self.conn.execute(
            """
            SELECT score_date, model_version FROM epss_snapshot
            WHERE %(d)s::date IS NULL OR score_date <= %(d)s::date
            ORDER BY score_date DESC LIMIT 1
            """,
            {"d": as_of},
        ).fetchone()
        return {
            "kev_catalog": kev_row["catalog_version"] if kev_row else None,
            "kev_released": _iso(kev_row["date_released"]) if kev_row else None,
            "epss_date": epss_row["score_date"] if epss_row else None,
            "epss_model": epss_row["model_version"] if epss_row else None,
        }

    # ------------------------------------------------------------ 보강 (KEV / EPSS / 캐시된 NVD 점수)
    def _enrich(self, cve_ids: list[str], snaps: dict) -> dict[str, dict]:
        kev_hits = kev.lookup(self.conn, snaps["kev_catalog"], cve_ids) if snaps["kev_catalog"] else None
        epss_hits = epss.lookup(self.conn, snaps["epss_date"], cve_ids) if snaps["epss_date"] else {}
        nvd_rows = {
            r["cve_id"]: r
            for r in self.conn.execute(
                "SELECT cve_id, cvss_score, cvss_version, cvss_source, cvss_type FROM nvd_cve WHERE found AND cve_id = ANY(%s)",
                (cve_ids,),
            )
        }
        out = {}
        for cve in cve_ids:
            hit = kev_hits.get(cve) if kev_hits is not None else None
            kev_value = None if kev_hits is None else (
                {
                    "date_added": _iso(hit["date_added"]),
                    "known_ransomware_use": hit["known_ransomware"],
                }
                if hit else False
            )
            row = nvd_rows.get(cve)
            out[cve] = {
                "kev": kev_value,
                "epss": epss_hits.get(cve),
                "cvss": (
                    {"score": float(row["cvss_score"]), "version": row["cvss_version"], "source": row["cvss_source"]}
                    if row and row["cvss_score"] is not None else None
                ),
            }
        return out

    # ------------------------------------------------------------ 기능 1: 패키지 검사
    def check_packages(self, packages: list[dict], as_of: date | None = None) -> dict:
        if not packages:
            raise InvalidInput("packages is empty. Pass at least one {ecosystem, name, version}.")
        if len(packages) > MAX_PACKAGES:
            raise InvalidInput(f"Too many packages ({len(packages)}). Split into calls of at most {MAX_PACKAGES}.")
        keys = [self._package_key(p) for p in packages]

        warnings = self.ensure_bulk_data()
        found = osv.lookup_packages(self.conn, self.client, list(dict.fromkeys(keys)), self.settings.osv_query_ttl_hours)
        snaps = self.snapshots(as_of)

        results = []
        for key in keys:
            label = f"{key[0]}/{key[1]}@{key[2]}"
            entry = found[key]
            if entry["records"] is None:
                results.append({"package": label, "status": "not_in_cache",
                                "note": "Offline mode and this package was never fetched."})
                continue
            vulns = [osv.summarize_group(g, key[0], key[1]) for g in osv.group_records(entry["records"])]
            vulns = sorted((v for v in vulns if not v["withdrawn"]), key=lambda v: v["id"])
            for v in vulns:
                del v["withdrawn"]
            result = {"package": label, "checked_at": _iso(entry["fetched_at"])}
            if vulns:
                result.update(status="vulnerable", vulnerabilities=vulns)
            else:
                result.update(status="no_known_vulns", note=NO_VULNS_NOTE)
            results.append(result)

        cves = sorted({c for r in results for v in r.get("vulnerabilities", []) for c in v["cve_ids"]})
        enrichment = self._enrich(cves, snaps)
        for r in results:
            for v in r.get("vulnerabilities", []):
                primary = v["cve_ids"][0] if v["cve_ids"] else None
                v.update(enrichment.get(primary, {"kev": None, "epss": None, "cvss": None}))
        if self.settings.tool_hints:
            self._add_tool_hints(results, keys, found)

        return {"as_of": {**snaps, "epss_date": _iso(snaps["epss_date"])}, "results": results, "warnings": warnings}

    @staticmethod
    def _add_tool_hints(results: list[dict], keys: list[osv.PackageKey], found: dict) -> None:
        """v4: 코드로 정확히 계산할 수 있는 두 가지를 도구가 미리 계산해 준다.

        - safe_upgrade (패키지별): 이 패키지의 모든 취약점을 벗어나는 가장 낮은 수정 버전 (없으면 null)
        - policy_rank (취약점별): KEV 먼저, 그다음 EPSS 높은 순의 전체 순위
        3주차 분석에서 모델이 190건을 손으로 정렬하느라 생각 토큰과 시간을 쓰고, 그래도 순서가 조금씩
        어긋났다(order_tau < 1). 판단이 아니라 계산이라 LLM에게 맡길 이유가 없다.
        """
        everything = []
        for key, result in zip(keys, results):
            vulns = result.get("vulnerabilities")
            if not vulns:
                continue
            ecosystem, name, version = key
            wanted = {i for v in vulns for i in v["osv_ids"]}
            records = [r for r in (found[key]["records"] or []) if r["id"] in wanted]
            matches = lambda n, e=ecosystem, want=name: normalize_package_name(e, n) == want
            result["safe_upgrade"] = min_safe_upgrade(version, ecosystem, records, matches)
            everything += [(v, result["package"]) for v in vulns]
        order = sorted(everything, key=lambda item: (not item[0]["kev"], -((item[0]["epss"] or {}).get("epss", -1)),
                                                     item[0]["id"], item[1]))
        for rank, (vuln, _package) in enumerate(order, 1):
            vuln["policy_rank"] = rank

    @staticmethod
    def _package_key(p: dict) -> osv.PackageKey:
        ecosystem = normalize_ecosystem(str(p.get("ecosystem", "")))
        if not ecosystem:
            raise InvalidInput(
                f"Unknown ecosystem {p.get('ecosystem')!r}. Use one of: {', '.join(ECOSYSTEMS.values())}."
            )
        name = str(p.get("name", "")).strip()
        version = str(p.get("version", "")).strip()
        if not name:
            raise InvalidInput("Package name is empty.")
        if not version or RANGE_CHARS & set(version):
            raise InvalidInput(
                f"{name}: version must be one exact installed version like '2.10', not a range ({version!r})."
            )
        return ecosystem, normalize_package_name(ecosystem, name), version

    # ------------------------------------------------------------ 기능 2: 취약점 상세
    def get_vulnerability(self, vuln_id: str, as_of: date | None = None) -> dict:
        vid = normalize_vuln_id(vuln_id)
        if not vid:
            raise InvalidInput(
                f"{vuln_id!r} is not a vulnerability ID. Use a CVE ID (CVE-2021-44228) "
                "or an OSV ID (GHSA-xxxx-xxxx-xxxx, PYSEC-2021-66)."
            )
        warnings = self.ensure_bulk_data()

        osv_records: list[dict] = []
        if normalize_cve(vid):
            cve = vid
        else:
            record = osv.get_vuln(self.conn, self.client, vid)
            if record is None:
                raise InvalidInput(f"{vid} was not found in OSV" + (" (offline cache)." if self.client is None else "."))
            osv_records.append(record)
            cves = osv.cve_ids_of(record)
            cve = cves[0] if cves else None
        if cve:
            seen = {r["id"] for r in osv_records}
            osv_records += [r for r in osv.records_for_cve(self.conn, cve) if r["id"] not in seen]
            if not osv_records and self.client is not None:
                osv_records = self._osv_records_by_cve(cve)

        snaps = self.snapshots(as_of)
        result: dict = {"id": cve or vid, "nvd": self._nvd_detail(cve, warnings) if cve else None}
        if cve:
            enrichment = self._enrich([cve], snaps)[cve]
            result["kev"] = enrichment["kev"]
            result["epss"] = enrichment["epss"]
            if result["kev"]:
                hit = kev.lookup(self.conn, snaps["kev_catalog"], [cve])[cve]
                result["kev"].update(name=hit["vulnerability_name"], required_action=hit["required_action"])
        else:
            result.update(kev=None, epss=None)
            warnings.append("No CVE alias, so KEV/EPSS/NVD cannot be looked up for this ID.")
        result["osv"] = self._osv_detail(osv_records)
        result["as_of"] = {**snaps, "epss_date": _iso(snaps["epss_date"])}
        result["warnings"] = warnings
        return result

    def _nvd_detail(self, cve: str, warnings: list[str]) -> dict:
        s = self.settings
        row = nvd.get_cached(self.conn, cve)
        if (row is None or not nvd.is_fresh(row, s.nvd_ttl_hours, s.nvd_pending_ttl_hours, s.nvd_notfound_ttl_hours)) \
                and self.client is not None:
            try:
                nvd.store(self.conn, cve, nvd.fetch_cve(self.client, self.nvd_limiter, s.nvd_api_key, cve))
                row = nvd.get_cached(self.conn, cve)
            except SourceError as exc:
                warnings.append(f"NVD lookup failed; showing cached data if any. ({exc})")
        if row is None:
            return {"status": "not_cached"}
        if not row["found"]:
            return {"status": "not_found_in_nvd", "checked_at": _iso(row["fetched_at"])}
        status = row["vuln_status"]
        detail = {
            "status": status,
            "description": row["description"],
            "cvss": (
                {"score": float(row["cvss_score"]), "severity": row["cvss_severity"], "version": row["cvss_version"],
                 "vector": row["cvss_vector"], "source": row["cvss_source"], "source_type": row["cvss_type"]}
                if row["cvss_score"] is not None else None
            ),
            "cwes": row["cwes"],
            "published": _iso(row["published"]),
            "references": nvd.top_references(row["raw"]),
            "checked_at": _iso(row["fetched_at"]),
        }
        note = STATUS_NOTES.get(status) or (PENDING_NOTE if status in nvd.PENDING_STATUSES else None)
        if note:
            detail["status_note"] = note
        return detail

    def _osv_records_by_cve(self, cve: str) -> list[dict]:
        """OSV는 CVE 번호로 된 레코드도 갖고 있다(NVD에서 변환). 그 레코드에는 패키지 정보가 없는
        경우가 많지만 aliases에 GHSA ID가 있어서, GHSA 레코드를 따라가면 패키지별 수정 버전을 얻는다.
        예: CVE-2021-44228 -> GHSA-jfh8-c2jp-5v3q -> Maven log4j-core 수정 버전들."""
        records = []
        cve_record = osv.get_vuln(self.conn, self.client, cve)
        if cve_record:
            records.append(cve_record)
            for alias in [a for a in cve_record.get("aliases", []) if a.startswith("GHSA-")][:3]:
                if (rec := osv.get_vuln(self.conn, self.client, alias)) is not None:
                    records.append(rec)
        return records

    @staticmethod
    def _osv_detail(records: list[dict], limit: int = 10) -> dict | None:
        """영향받는 패키지와 수정 버전만 추린다. affected[].versions(버전 나열)와 references는
        한 건에 수십 KB라 에이전트에게 넘기지 않는다."""
        if not records:
            return None
        packages: dict[tuple[str, str], set[str]] = {}
        cwes: set[str] = set()
        for rec in records:
            cwes.update((rec.get("database_specific") or {}).get("cwe_ids") or [])
            for aff in rec.get("affected", []):
                pkg = aff.get("package", {})
                if not pkg.get("ecosystem"):  # 패키지 없는 항목(git 저장소 범위 등)은 버전 안내에 못 쓴다
                    continue
                key = (pkg["ecosystem"], pkg.get("name", ""))
                fixes = packages.setdefault(key, set())
                for rng in aff.get("ranges", []):
                    if rng.get("type") != "GIT":
                        fixes.update(e["fixed"] for e in rng.get("events", []) if "fixed" in e)
        records = sorted(records, key=lambda r: (not r["id"].startswith("GHSA-"), r["id"]))
        return {
            "ids": [r["id"] for r in records],
            "summary": next((r.get("summary") for r in records if r.get("summary")), None),
            # NVD에 CWE가 없을 때(NVD-CWE-Other 등) GHSA의 CWE가 대안이 된다. 출처가 다르니 따로 둔다.
            "cwes_from_ghsa": sorted(cwes),
            "affected_packages": [
                {"ecosystem": eco, "name": name, "fixed_versions": sorted(fixes)}
                for (eco, name), fixes in sorted(packages.items())[:limit]
            ],
        }

    # ------------------------------------------------------------ 상태
    def status(self) -> dict:
        counts = {
            t: self.conn.execute(f"SELECT count(*) AS n FROM {t}").fetchone()["n"]
            for t in ("osv_vuln", "osv_package_query", "nvd_cve", "kev_snapshot", "kev_entry", "epss_snapshot", "epss_score")
        }
        snaps = self.snapshots()
        return {"offline": self.settings.offline, "rows": counts, "latest": {**snaps, "epss_date": _iso(snaps["epss_date"])}}
