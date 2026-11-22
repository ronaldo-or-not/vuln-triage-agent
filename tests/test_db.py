"""DB 테스트: 캐시, 스냅샷, 멱등성, 오프라인 동작. 네트워크 대신 httpx.MockTransport로 응답을 흉내 낸다."""

import json
from dataclasses import replace
from datetime import date, timedelta

import httpx
import pytest
from conftest import load

from vulnagent.errors import InvalidInput
from vulnagent.service import VulnService
from vulnagent.sources import epss, kev, osv


def test_kev_snapshot_load_is_idempotent(db):
    catalog = load("kev_sample.json")
    assert kev.load_snapshot(db, catalog) is True
    assert kev.load_snapshot(db, catalog) is False  # 같은 버전을 두 번 넣어도 중복이 생기지 않는다
    assert db.execute("SELECT count(*) AS n FROM kev_entry").fetchone()["n"] == len(catalog["vulnerabilities"])


def test_epss_copy_and_lookup(db):
    meta, rows = epss.parse_csv(load("epss_sample.csv"))
    assert epss.load_snapshot(db, meta, rows)
    hit = epss.lookup(db, meta["score_date"], ["CVE-2021-44228", "CVE-2099-0001"])
    assert set(hit) == {"CVE-2021-44228"}  # 점수 없는 CVE는 0이 아니라 아예 없음
    assert hit["CVE-2021-44228"]["epss"] > 0.99


def _epss_snapshot(db, day: date) -> None:
    epss.load_snapshot(db, {"score_date": day, "model_version": "test"}, [("CVE-2021-44228", 0.5, 0.5)])


def test_snapshot_selection_by_as_of_date(db, offline_settings):
    _epss_snapshot(db, date(2026, 11, 1))
    _epss_snapshot(db, date(2026, 11, 20))
    service = VulnService(db, offline_settings)
    assert service.snapshots(date(2026, 11, 10))["epss_date"] == date(2026, 11, 1)
    assert service.snapshots()["epss_date"] == date(2026, 11, 20)


def test_timestamps_are_reported_in_utc_regardless_of_server_timezone(db, offline_settings):
    # 서버 기본 시간대와 상관없이 같은 문자열이 나와야 정답이 환경 간에 재현된다
    assert db.execute("SHOW TimeZone").fetchone()["TimeZone"] == "UTC"
    kev.load_snapshot(db, load("kev_sample.json"))
    released = VulnService(db, offline_settings).snapshots(date(2026, 11, 20))["kev_released"]
    assert released.startswith("2026-11-20T17:48") and released.endswith("+00:00")


def test_kev_as_of_uses_utc_date(db, offline_settings):
    # 실제 카탈로그 2026.11.20의 dateReleased는 2026-11-20T17:48Z (KST로는 11-21 새벽)
    db.execute("SET TIME ZONE 'Asia/Seoul'")
    kev.load_snapshot(db, load("kev_sample.json"))
    service = VulnService(db, offline_settings)
    assert service.snapshots(date(2026, 11, 20))["kev_catalog"] == "2026.11.20"
    assert service.snapshots(date(2026, 11, 19))["kev_catalog"] is None


def test_prune_keeps_pinned_snapshots(db, offline_settings):
    days = [date(2026, 11, 1) + timedelta(days=i) for i in range(3)]
    for d in days:
        _epss_snapshot(db, d)
    db.execute("UPDATE epss_snapshot SET pinned = true WHERE score_date = %s", (days[0],))
    VulnService(db, replace(offline_settings, keep_snapshots=1)).prune()
    left = [r["score_date"] for r in db.execute("SELECT score_date FROM epss_snapshot ORDER BY 1")]
    assert left == [days[0], days[2]]  # 고정한 가장 오래된 것 + 최신 1개
    assert db.execute("SELECT count(*) AS n FROM epss_score").fetchone()["n"] == 2  # CASCADE


def test_check_packages_offline_merges_and_enriches(seeded_db, offline_settings):
    service = VulnService(seeded_db, offline_settings)
    out = service.check_packages([
        {"ecosystem": "pypi", "name": "Jinja2", "version": "2.10"},
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.15"},
    ])
    jinja, lodash = out["results"]
    assert jinja["status"] == "vulnerable" and len(jinja["vulnerabilities"]) == 6
    first = jinja["vulnerabilities"][0]
    assert first["id"] == "CVE-2019-10906" and first["kev"] is False and first["epss"]["epss"] > 0
    assert lodash["status"] == "not_in_cache"  # 오프라인이고 받아 둔 적 없음
    assert out["as_of"]["kev_catalog"] == "2026.11.20" and out["warnings"] == []


def test_tool_hints_compute_safe_upgrade_and_policy_rank(seeded_db, offline_settings):
    plain = VulnService(seeded_db, offline_settings).check_packages([{"ecosystem": "PyPI", "name": "jinja2", "version": "2.10"}])
    assert "safe_upgrade" not in plain["results"][0]  # 플래그가 꺼져 있으면 v1~v3와 같은 출력

    hinted = VulnService(seeded_db, replace(offline_settings, tool_hints=True)).check_packages(
        [{"ecosystem": "PyPI", "name": "jinja2", "version": "2.10"}])
    result = hinted["results"][0]
    assert result["safe_upgrade"] == "3.1.6"  # 픽스처의 수정 버전 중 6건을 모두 벗어나는 가장 낮은 버전
    ranks = sorted((v["policy_rank"], v["epss"]["epss"]) for v in result["vulnerabilities"])
    assert [r for r, _ in ranks] == list(range(1, 7))
    assert [e for _, e in ranks] == sorted((e for _, e in ranks), reverse=True)  # KEV 없음 -> EPSS 내림차순


def test_kev_unknown_is_null_not_false(db, offline_settings):
    for record in load("osv_query_jinja2.json")["vulns"]:
        osv.store_vuln(db, record)
    osv.store_package_query(db, ("PyPI", "jinja2", "2.10"), [r["id"] for r in load("osv_query_jinja2.json")["vulns"]])
    out = VulnService(db, offline_settings).check_packages([{"ecosystem": "PyPI", "name": "jinja2", "version": "2.10"}])
    assert all(v["kev"] is None for v in out["results"][0]["vulnerabilities"])
    assert any("KEV data unavailable" in w for w in out["warnings"])


def test_get_vulnerability_offline(seeded_db, offline_settings):
    out = VulnService(seeded_db, offline_settings).get_vulnerability("cve-2021-44228")
    assert out["nvd"]["cvss"]["score"] == 10.0 and out["nvd"]["cvss"]["source"] == "NVD"
    assert out["kev"]["known_ransomware_use"] == "Known"
    assert out["epss"]["epss"] > 0.99


def test_invalid_inputs_have_actionable_messages(seeded_db, offline_settings):
    service = VulnService(seeded_db, offline_settings)
    with pytest.raises(InvalidInput, match="Use one of: PyPI"):
        service.check_packages([{"ecosystem": "pip", "name": "x", "version": "1"}])
    with pytest.raises(InvalidInput, match="not a range"):
        service.check_packages([{"ecosystem": "PyPI", "name": "x", "version": "^1.0"}])
    with pytest.raises(InvalidInput, match="CVE ID"):
        service.get_vulnerability("log4shell")


def test_osv_cache_refetches_only_what_changed(db):
    """1회차: batch 1번 + 상세 12번. 2회차(TTL 안): 0번. TTL 만료 후: batch 1번, 상세 0번(modified 그대로)."""
    batch = load("osv_batch_jinja2.json")
    records = {v["id"]: v for v in load("osv_query_jinja2.json")["vulns"]}
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/querybatch"):
            assert json.loads(request.content)["queries"][0]["package"] == {"ecosystem": "PyPI", "name": "jinja2"}
            return httpx.Response(200, json=batch)
        return httpx.Response(200, json=records[request.url.path.rsplit("/", 1)[-1]])

    client = httpx.Client(transport=httpx.MockTransport(handler))
    key = ("PyPI", "jinja2", "2.10")

    out = osv.lookup_packages(db, client, [key], ttl_hours=24)
    assert len(out[key]["records"]) == 12 and len(calls) == 13

    calls.clear()
    osv.lookup_packages(db, client, [key], ttl_hours=24)
    assert calls == []

    calls.clear()
    osv.lookup_packages(db, client, [key], ttl_hours=0)
    assert calls == ["/v1/querybatch"]
