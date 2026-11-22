"""security-kb MCP 서버를 실제 클라이언트로 검증 (pgvector와 받아 둔 임베딩 모델이 있는 서버에서만)."""

import asyncio
import importlib.util
import os
import sys

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from conftest import TEST_DATABASE_URL

from vulnagent.kb.cwe import apply_schema, load, parse
from vulnagent.kb.search import MODELS, CweIndex

XML = b"""<?xml version="1.0"?>
<Weakness_Catalog Name="CWE" Version="test" xmlns="http://cwe.mitre.org/cwe-8"><Weaknesses>
 <Weakness ID="89" Name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')" Abstraction="Base" Status="Stable">
  <Description>The product constructs all or part of an SQL command using externally-influenced input without neutralizing special elements.</Description>
  <Potential_Mitigations><Mitigation><Description>Use parameterized queries.</Description></Mitigation></Potential_Mitigations></Weakness>
 <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" Abstraction="Base" Status="Stable">
  <Description>The product does not neutralize user-controllable input before it is placed in output that is used as a web page.</Description></Weakness>
 <Weakness ID="502" Name="Deserialization of Untrusted Data" Abstraction="Base" Status="Draft">
  <Description>The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.</Description></Weakness>
</Weaknesses></Weakness_Catalog>"""


def _available() -> bool:
    if importlib.util.find_spec("sentence_transformers") is None:
        return False
    try:
        import psycopg
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            return conn.execute("SELECT 1 FROM pg_available_extensions WHERE name = 'vector'").fetchone() is not None
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _available(), reason="needs pgvector and sentence-transformers (server only)")


async def _calls():
    params = StdioServerParameters(command=sys.executable, args=["-m", "vulnagent.kb_server"],
                                   env={"DATABASE_URL": TEST_DATABASE_URL, "PATH": os.environ.get("PATH", ""),
                                        "HOME": os.environ.get("HOME", "")})
    async with Client(params) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        found = await client.call_tool("search_weaknesses", {"query": "attacker injects SQL through the login form", "k": 3})
        entry = await client.call_tool("get_weakness", {"cwe_id": "89"})
        bad = await client.call_tool("get_weakness", {"cwe_id": "XSS"})
        many = await client.call_tool("search_weaknesses_many", {"queries": [
            {"key": "CVE-1", "text": "attacker injects SQL through the login form"},
            {"key": "CVE-2", "text": "untrusted serialized object leads to code execution"}], "k": 2})
        return names, found, entry, bad, many


def test_kb_server_search_and_get(db):
    apply_schema(db)
    version, entries = parse(XML)
    load(db, version, entries)
    CweIndex(db).ensure_embeddings(MODELS["minilm"])

    names, found, entry, bad, many = asyncio.run(_calls())
    assert names == {"search_weaknesses", "search_weaknesses_many", "get_weakness"}
    assert found.structured_content["results"][0]["cwe_id"] == "CWE-89"
    assert "parameterized queries" in entry.structured_content["mitigations"]
    assert bad.is_error and "CWE-79" in bad.content[0].text
    batch = many.structured_content["results"]
    assert [r["key"] for r in batch] == ["CVE-1", "CVE-2"]  # 질의 순서대로, key를 그대로 돌려준다
    assert batch[0]["candidates"][0]["cwe_id"] == "CWE-89" and len(batch[0]["candidates"]) <= 2
    assert batch[1]["candidates"][0]["cwe_id"] == "CWE-502" and "summary" not in batch[1]["candidates"][0]
