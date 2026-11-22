"""테스트 공통.

- 픽스처 파일(tests/fixtures)은 실제 API 응답을 잘라서 만든 것이다. 테스트는 기본적으로
  네트워크를 쓰지 않는다. 실제 API를 부르는 테스트는 VULNAGENT_LIVE=1일 때만 돈다.
- DB 테스트는 TEST_DATABASE_URL(기본 postgresql:///vulnagent_test)을 쓰고, 매 테스트마다
  스키마를 지우고 다시 만든다. 실수로 운영 DB를 지우지 않도록 DB 이름이 _test로 끝나야 한다.
"""

import json
import os
from dataclasses import replace
from pathlib import Path

import psycopg
import pytest

from vulnagent.config import load_settings
from vulnagent.db import apply_schema, connect
from vulnagent.ids import normalize_package_name
from vulnagent.sources import epss, kev, nvd, osv

FIXTURES = Path(__file__).parent / "fixtures"
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "postgresql:///vulnagent_test")


def load(name: str):
    path = FIXTURES / name
    return json.loads(path.read_text()) if path.suffix == ".json" else path.read_text()


@pytest.fixture
def db():
    try:
        conn = connect(TEST_DATABASE_URL)
    except psycopg.OperationalError as exc:
        pytest.skip(f"test database not available: {exc}")
    name = conn.info.dbname
    assert name.endswith("_test"), f"refusing to reset non-test database {name!r}"
    conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    apply_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def offline_settings():
    return replace(load_settings(), database_url=TEST_DATABASE_URL, offline=True)


def seed(conn) -> None:
    """픽스처로 DB를 채운다: KEV/EPSS 스냅샷, jinja2 2.10의 OSV 결과, Log4Shell의 NVD 상세."""
    kev.load_snapshot(conn, load("kev_sample.json"))
    meta, rows = epss.parse_csv(load("epss_sample.csv"))
    epss.load_snapshot(conn, meta, rows)
    records = load("osv_query_jinja2.json")["vulns"]
    for record in records:
        osv.store_vuln(conn, record)
    osv.store_package_query(conn, ("PyPI", normalize_package_name("PyPI", "jinja2"), "2.10"), [r["id"] for r in records])
    nvd.store(conn, "CVE-2021-44228", load("nvd_log4shell.json")["vulnerabilities"][0]["cve"])


@pytest.fixture
def seeded_db(db):
    seed(db)
    return db
