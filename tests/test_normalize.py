"""순수 함수 테스트: 네트워크도 DB도 없이 돈다. 실제 응답에서 발견한 함정을 하나씩 고정한다."""

from datetime import date, datetime, timedelta, timezone

from conftest import load

from vulnagent.cli import parse_package
from vulnagent.ids import normalize_cve, normalize_ecosystem, normalize_package_name, normalize_vuln_id, parse_ts
from vulnagent.sources import epss, nvd, osv


def test_cve_ids_can_have_more_than_four_digits():
    assert normalize_cve("cve-2026-129448") == "CVE-2026-129448"  # 실제 KEV 항목
    assert normalize_cve("CVE-2021-123") is None


def test_vuln_id_normalization():
    assert normalize_vuln_id(" ghsa-462W-V97R-4M45 ") == "GHSA-462w-v97r-4m45"
    assert normalize_vuln_id("PYSEC-2021-66") == "PYSEC-2021-66"
    assert normalize_vuln_id("log4shell") is None


def test_ecosystem_is_normalized_because_osv_is_case_sensitive():
    assert normalize_ecosystem("pypi") == "PyPI"
    assert normalize_ecosystem("pip") is None


def test_pypi_names_follow_pep503():
    assert normalize_package_name("PyPI", "Jinja2") == normalize_package_name("PyPI", "jinja2")
    assert normalize_package_name("PyPI", "zope.interface") == "zope-interface"


def test_osv_modified_precision_differs_between_endpoints_but_parses_equal():
    batch = {v["id"]: v["modified"] for v in load("osv_batch_jinja2.json")["results"][0]["vulns"]}
    full = {v["id"]: v["modified"] for v in load("osv_query_jinja2.json")["vulns"]}
    assert any(batch[i] != full[i] for i in batch), "the raw strings really differ (the trap)"
    assert all(parse_ts(batch[i]) == parse_ts(full[i]) for i in batch)


def test_nvd_timestamps_without_timezone_are_utc():
    assert parse_ts("2021-12-10T10:15:09.143").tzinfo == timezone.utc


def test_duplicate_osv_records_are_grouped_by_alias():
    records = load("osv_query_jinja2.json")["vulns"]
    groups = osv.group_records(records)
    assert len(records) == 12 and len(groups) == 6
    summaries = [osv.summarize_group(g, "PyPI", "jinja2") for g in groups]
    assert all(s["id"].startswith("CVE-") and len(s["osv_ids"]) == 2 for s in summaries)


def test_summarize_group_extracts_fix_and_severity():
    records = load("osv_query_jinja2.json")["vulns"]
    group = next(g for g in osv.group_records(records) if "CVE-2019-10906" in osv.cve_ids_of(g[0]))
    s = osv.summarize_group(group, "PyPI", "jinja2")
    assert s["fixed_versions"] == ["2.10.1"] and s["fix_available"]
    assert s["severity_label"] == {"value": "HIGH", "source": "GHSA"}
    assert s["cvss_vector"].startswith("CVSS:3")
    assert s["osv_ids"][0].startswith("GHSA-")  # GHSA 레코드를 대표로


def test_fix_info_only_looks_at_the_queried_package():
    record = {
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "other"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]},
            {"package": {"ecosystem": "PyPI", "name": "Jinja2"}, "ranges": [
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]},
            ]},
        ]
    }
    assert osv.package_fix_info(record, "PyPI", "jinja2") == {"fixed": {"2.10.1"}, "open_ended": False, "last_affected": set()}


def test_last_affected_is_surfaced_to_the_agent():
    # 실제 PYSEC-2025-183 (pyjwt): 수정 버전은 없지만 2.10.1까지만 영향
    record = {"id": "PYSEC-2025-183", "aliases": ["CVE-2025-45768"], "affected": [
        {"package": {"ecosystem": "PyPI", "name": "pyjwt"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "2.10.1"}]}]}]}
    s = osv.summarize_group([record], "PyPI", "pyjwt")
    assert s["fixed_versions"] == [] and s["last_affected"] == ["2.10.1"]


def test_pick_cvss_prefers_nvd_primary_and_ignores_ssvc():
    metrics = load("nvd_log4shell.json")["vulnerabilities"][0]["cve"]["metrics"]
    assert "ssvcV203" in metrics
    assert nvd.pick_cvss(metrics) == {
        "score": 10.0, "severity": "CRITICAL", "version": "3.1",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "source": "NVD", "type": "Primary",
    }


def test_pick_cvss_falls_back_to_cna_secondary_score():
    metrics = load("nvd_recent_cna_only.json")["vulnerabilities"][0]["cve"]["metrics"]
    picked = nvd.pick_cvss(metrics)
    assert (picked["score"], picked["source"], picked["type"]) == (9.8, "security@apache.org", "Secondary")


def test_nvd_normalize_drops_placeholder_cwes():
    cve = {"id": "CVE-2000-0001", "weaknesses": [{"description": [{"value": "NVD-CWE-Other"}, {"value": "CWE-79"}]}]}
    assert nvd.normalize(cve)["cwes"] == ["CWE-79"]


def test_nvd_ttl_is_shorter_for_pending_and_missing():
    now = datetime.now(timezone.utc)
    two_days_old = {"found": True, "vuln_status": "Analyzed", "fetched_at": now - timedelta(days=2)}
    assert nvd.is_fresh(two_days_old, 168, 24, 24)
    assert not nvd.is_fresh({**two_days_old, "vuln_status": "Awaiting Analysis"}, 168, 24, 24)
    assert not nvd.is_fresh({**two_days_old, "found": False}, 168, 24, 24)


def test_epss_csv_header_comment_is_parsed():
    meta, rows = epss.parse_csv(load("epss_sample.csv"))
    assert meta == {"model_version": "v2026.06.15", "score_date": date(2026, 11, 20)}
    assert len(rows) == 8 and all(r[0].startswith("CVE-") for r in rows)


def test_cli_package_spec_handles_npm_scope_and_maven_colon():
    assert parse_package("npm/@babel/core@7.0.0") == {"ecosystem": "npm", "name": "@babel/core", "version": "7.0.0"}
    assert parse_package("Maven/org.apache.logging.log4j:log4j-core@2.14.1")["name"] == "org.apache.logging.log4j:log4j-core"
