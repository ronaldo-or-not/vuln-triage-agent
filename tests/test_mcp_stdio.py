"""MCP 서버를 실제 클라이언트로 검증한다: 서브프로세스로 띄우고 stdio로 대화.

함수를 직접 부르는 테스트는 통과해도, 서버가 stdout에 로그를 찍는다거나 스키마가 깨지는
문제는 실제 프로토콜로 붙어 봐야 잡힌다.
"""

import asyncio
import os
import sys

from mcp import Client
from mcp.client.stdio import StdioServerParameters

from conftest import TEST_DATABASE_URL


def _server() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "vulnagent.mcp_server"],
        env={"DATABASE_URL": TEST_DATABASE_URL, "VULNAGENT_OFFLINE": "1", "PATH": os.environ.get("PATH", "")},
    )


async def _session_checks() -> dict:
    async with Client(_server()) as client:
        tools = await client.list_tools()
        ok = await client.call_tool("check_packages", {"packages": [{"ecosystem": "PyPI", "name": "jinja2", "version": "2.10"}]})
        bad = await client.call_tool("get_vulnerability", {"vuln_id": "log4shell"})
        return {"tools": tools.tools, "ok": ok, "bad": bad}


def test_mcp_server_over_stdio(seeded_db):
    result = asyncio.run(_session_checks())

    tools = {t.name: t for t in result["tools"]}
    assert set(tools) == {"check_packages", "get_vulnerability"}
    assert tools["check_packages"].annotations.read_only_hint is True
    assert "NOT proof of safety" in tools["check_packages"].description

    ok = result["ok"]
    assert not ok.is_error
    package = ok.structured_content["results"][0]
    assert package["status"] == "vulnerable" and len(package["vulnerabilities"]) == 6

    bad = result["bad"]
    assert bad.is_error and "CVE ID" in bad.content[0].text  # 모델이 읽고 고칠 수 있는 메시지
