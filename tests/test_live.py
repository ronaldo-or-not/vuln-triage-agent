"""실제 외부 API를 부르는 테스트. 기본은 건너뛰고 VULNAGENT_LIVE=1일 때만 돈다.

목적: 소스의 응답 형식이 바뀌었는지(우리 파서가 깨졌는지) 조기에 발견. 하루 1회 CI에서 돌리면 좋다.
"""

import os

import pytest

from vulnagent.http import make_client
from vulnagent.sources import epss, kev, nvd, osv

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("VULNAGENT_LIVE") != "1", reason="set VULNAGENT_LIVE=1 to hit real APIs"),
]


@pytest.fixture(scope="module")
def client():
    with make_client("vuln-triage-agent/0.1") as c:
        yield c


def test_osv_batch_and_detail(client):
    found = osv.fetch_batch(client, [("PyPI", "jinja2", "2.10")])
    ids = [v["id"] for v in found[("PyPI", "jinja2", "2.10")]]
    records = [osv.fetch_vuln(client, i) for i in ids]
    assert len(osv.group_records(records)) >= 6


def test_nvd_log4shell(client):
    cve = nvd.fetch_cve(client, nvd.make_limiter(os.environ.get("NVD_API_KEY")), os.environ.get("NVD_API_KEY"), "CVE-2021-44228")
    assert nvd.normalize(cve)["cvss"]["score"] == 10.0


def test_kev_catalog_shape(client):
    catalog = kev.fetch_catalog(client)
    assert catalog["count"] > 1000 and {"cveID", "dateAdded"} <= set(catalog["vulnerabilities"][0])


def test_epss_current_file(client):
    meta, rows = epss.parse_csv(epss.fetch_current(client))
    assert meta["score_date"] is not None and len(rows) > 300_000
