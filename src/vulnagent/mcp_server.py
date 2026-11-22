"""vuln-data MCP 서버 (stdio).

도구는 의도 단위로 딱 두 개만 둔다. 소스별 도구(osv_query, nvd_get, kev_check, epss_get)를
따로 주면 모델이 순서와 조합을 매번 스스로 짜야 하고, 그만큼 틀릴 곳이 늘어난다.

도구 설명(description)은 모델이 읽는 프롬프트라서 영어로 쓰고, 다음을 꼭 담는다:
언제 쓰는지, 입력 형식(예시 포함), 결과를 어떻게 해석해야 하는지(특히 "없음 != 안전").

실행:  python -m vulnagent.mcp_server
"""

import logging
import sys
from datetime import date
from functools import cache
from typing import Any

from pydantic import BaseModel, Field

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .config import load_settings
from .db import apply_schema, connect
from .errors import InvalidInput, SourceError
from .service import VulnService

INSTRUCTIONS = """Vulnerability data for dependency triage. Sources: OSV (package -> vulnerabilities),
NVD (CVE details, CVSS, CWE), CISA KEV (confirmed exploitation), FIRST EPSS (exploitation probability).
Typical flow: call check_packages once with every dependency, then call get_vulnerability only for the
vulnerabilities you need to explain in detail. Tools return facts and sources, not priorities.
Cite the `as_of` dates when you report KEV or EPSS values."""

server = MCPServer(name="vuln-data", instructions=INSTRUCTIONS)
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=True)


class PackageRef(BaseModel):
    ecosystem: str = Field(description="One of: PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist, Pub, Hex")
    name: str = Field(description="Package name as published. Maven uses 'groupId:artifactId'.")
    version: str = Field(description="The exact installed version, e.g. '2.10'. Not a range like '>=2.0'.")


@cache
def _service() -> VulnService:
    settings = load_settings()
    conn = connect(settings.database_url)
    apply_schema(conn)
    return VulnService(conn, settings)


def _call(fn, *args):
    """서비스 예외를 모델이 읽고 회복할 수 있는 ToolError로 바꾼다 (is_error=True로 전달됨)."""
    try:
        return fn(*args)
    except InvalidInput as exc:
        raise ToolError(f"Invalid input: {exc}") from exc
    except SourceError as exc:
        raise ToolError(f"Upstream data source failed, try again later: {exc}") from exc


def _parse_as_of(as_of: str | None) -> date | None:
    if not as_of:
        return None
    try:
        return date.fromisoformat(as_of)
    except ValueError as exc:
        raise ToolError(f"as_of must be a date like 2026-11-20, got {as_of!r}") from exc


@server.tool(annotations=READ_ONLY)
def check_packages(packages: list[PackageRef], as_of: str | None = None) -> dict[str, Any]:
    """Check exact package versions for known vulnerabilities (OSV), enriched with CISA KEV and EPSS.

    Pass every dependency in one call (up to 200). For each package you get status:
    - "vulnerable": one entry per vulnerability. Duplicate records from different databases
      (GHSA, PYSEC, ...) are already merged; `id` is the CVE when one exists. Each entry has
      fixed_versions, kev (object if listed in CISA KEV, false if not listed, null if KEV data
      is unavailable), epss (probability of exploitation in 30 days, null if not scored), and
      cvss (only if NVD details were fetched before; use get_vulnerability for scores).
      last_affected (when present): versions up to and including these are affected and no fix
      was published for that line, but versions above them are not affected.
    When present, safe_upgrade (per package) is the lowest fixed version not affected by any of
    that package's vulnerabilities (null if none exists), and policy_rank (per vulnerability)
    orders every vulnerability in the response by KEV status, then EPSS. Both are computed in code.
    - "no_known_vulns": OSV knows no vulnerability. NOT proof of safety: a misspelled package
      name gives the same answer.
    Results are not sorted by priority. `as_of` (YYYY-MM-DD) replays older KEV/EPSS snapshots.
    """
    return _call(_service().check_packages, [p.model_dump() for p in packages], _parse_as_of(as_of))


@server.tool(annotations=READ_ONLY)
def get_vulnerability(vuln_id: str, as_of: str | None = None) -> dict[str, Any]:
    """Get details for one vulnerability: NVD description, CVSS score, CWE, KEV and EPSS status,
    and fixed versions per affected package.

    vuln_id: a CVE ID (CVE-2021-44228) or an OSV ID (GHSA-xxxx-xxxx-xxxx, PYSEC-2021-66).
    nvd.cvss.source tells who scored it: NVD itself, or a CNA / CISA-ADP when NVD has not analyzed
    the CVE (common for recent CVEs). Read nvd.status_note when present. This call may take a few
    seconds because NVD is rate limited; call it only for vulnerabilities you need to explain.
    """
    return _call(_service().get_vulnerability, vuln_id, _parse_as_of(as_of))


def main() -> None:
    # stdio 서버에서 stdout은 프로토콜 전용이다. 로그는 반드시 stderr로.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")
    server.run("stdio")


if __name__ == "__main__":
    main()
