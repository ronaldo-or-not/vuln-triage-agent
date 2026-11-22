"""식별자·시각·패키지 이름 정규화. 소스마다 표기가 달라서 조인 전에 반드시 통일해야 한다."""

import re
from datetime import datetime, timezone

# CVE 번호의 뒷자리는 4자리 "이상"이다. KEV에 CVE-2026-129448 같은 6자리가 실제로 있다.
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# OSV ID: GHSA-xxxx-xxxx-xxxx, PYSEC-2021-66, GO-2022-0001, RUSTSEC-2021-0001 ...
OSV_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-[A-Za-z0-9._:-]+$")

# OSV가 지원하는 생태계 중 자주 쓰는 것. OSV는 대소문자를 구분한다 ("pypi"를 보내면 400 invalid ecosystem).
ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
    "crates.io": "crates.io",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
}


def normalize_cve(value: str) -> str | None:
    v = value.strip().upper()
    return v if CVE_RE.match(v) else None


def normalize_vuln_id(value: str) -> str | None:
    """CVE면 대문자 CVE로, OSV ID면 원래 표기(GHSA 뒷부분은 소문자)로 돌려준다."""
    v = value.strip()
    if cve := normalize_cve(v):
        return cve
    if v.upper().startswith("GHSA-"):
        return "GHSA-" + v[5:].lower()
    return v if OSV_ID_RE.match(v) else None


def normalize_ecosystem(value: str) -> str | None:
    return ECOSYSTEMS.get(value.strip().lower())


def normalize_package_name(ecosystem: str, name: str) -> str:
    """같은 패키지를 같은 키로 만든다. PyPI는 PEP 503 규칙 (Jinja2 == jinja2, a_b == a-b)."""
    name = name.strip()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        return name.lower()
    return name


_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_ts(value: str | None) -> datetime | None:
    """ISO 시각을 UTC datetime으로.

    OSV는 같은 레코드의 modified를 querybatch에서는 마이크로초(…756181Z),
    상세 조회에서는 나노초(…756181700Z)로 준다. 문자열 그대로 비교하면 캐시가 영원히
    "바뀌었다"고 판단하므로, 마이크로초까지만 잘라서 통일한다(PostgreSQL 정밀도와도 같다).
    NVD 시각은 시간대 표기가 없는데 UTC다.
    """
    if not value:
        return None
    v = _FRACTION.sub(r"\1", value.strip()).replace("Z", "+00:00")
    dt = datetime.fromisoformat(v)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
