"""security-kb MCP 서버 (stdio): CWE 지식베이스 검색.

vuln-data 서버와 따로 둔 이유: 임베딩 모델(torch)을 올리는 무거운 서버라, 가벼운 데이터 서버와 수명·의존성을
분리한다. 에이전트는 두 MCP 서버에 동시에 붙을 수 있다.

검색 방식은 4주차 평가 결과로 정했다 (eval/retrieval/results.md, 질의 433~438개):
  기본 = BM25 + 관찰 사례 색인 (hit@5 0.47). 관찰 사례 없는 BM25 0.33, 하이브리드(+MiniLM) 0.41,
  범용 임베딩 단독 0.17~0.20. 관찰 사례는 CVE 설명과 같은 문체라 질의와 잘 맞는다. 평가에서는 자기 CVE가
  관찰 사례에 실린 질의를 빼고도 같은 결과가 나와 누수가 아님을 확인했다. 실제 사용에서는 자기 CVE가
  관찰 사례에 있으면 그걸로 찾는 것이 오히려 맞는 동작이다.
  VULNAGENT_KB_METHOD=bm25|dense|hybrid, VULNAGENT_KB_OBSERVED=0|1 로 바꿀 수 있다.
  기본값(bm25)에서는 임베딩 모델을 올리지 않아 서버가 바로 뜬다.

실행:  python -m vulnagent.kb_server
"""

import logging
import os
import re
import sys
from functools import cache
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .config import load_settings
from .db import connect
from .kb.search import MODELS, CweIndex

INSTRUCTIONS = """CWE (Common Weakness Enumeration) knowledge base. Use it to name the weakness class behind a
vulnerability and to suggest mitigations, especially when NVD gives no CWE or only a generic one.
search_weaknesses finds candidate CWEs for a free-text description; get_weakness returns one entry.
Search results are candidates, not facts: confirm against the vulnerability description before citing them."""

server = MCPServer(name="security-kb", instructions=INSTRUCTIONS)
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
CWE_RE = re.compile(r"^(?:CWE-)?(\d+)$", re.IGNORECASE)


@cache
def _index() -> CweIndex:
    observed = os.environ.get("VULNAGENT_KB_OBSERVED", "1") == "1"
    return CweIndex(connect(load_settings().database_url), include_observed=observed)


def _method() -> tuple[str, str]:
    return os.environ.get("VULNAGENT_KB_METHOD", "bm25"), MODELS[os.environ.get("VULNAGENT_KB_MODEL", "minilm")]


def _short(text: str | None, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


@server.tool(annotations=READ_ONLY)
def search_weaknesses(query: str, k: int = 5) -> dict[str, Any]:
    """Find candidate CWE entries for a free-text description of a vulnerability
    (for example an NVD description or your own summary of the bug).

    Returns up to k (max 10) candidates with id, name, abstraction level and a short summary.
    On CVE descriptions the top candidate matches the NVD label about 1 time in 5, and a matching
    CWE is in the top 5 about half the time, so read the summaries and pick the one that fits.
    """
    if not query.strip():
        raise ToolError("query is empty; pass a description of the vulnerability")
    method, model = _method()
    index = _index()
    hits = index.search(query, k=max(1, min(k, 10)), method=method, model=model)
    return {
        "method": method,
        "results": [
            {"cwe_id": cid, "name": index.rows[cid]["name"], "kind": index.rows[cid]["kind"],
             "abstraction": index.rows[cid]["abstraction"], "summary": _short(index.rows[cid]["description"], 300)}
            for cid, _score in hits
        ],
    }


@server.tool(annotations=READ_ONLY)
def get_weakness(cwe_id: str) -> dict[str, Any]:
    """Get one CWE entry by id (CWE-79 or 79): name, description, consequences and mitigations."""
    m = CWE_RE.match(cwe_id.strip())
    if not m:
        raise ToolError(f"{cwe_id!r} is not a CWE id. Use the form CWE-79.")
    key = f"CWE-{m.group(1)}"
    row = _index().conn.execute(
        "SELECT cwe_id, kind, name, abstraction, status, description, raw, catalog_version, "
        "cardinality(observed_cves) AS observed FROM cwe_entry WHERE cwe_id = %s", (key,)).fetchone()
    if row is None:
        raise ToolError(f"{key} is not in the catalog (it may be deprecated or a view id).")
    raw = row["raw"]
    return {
        "cwe_id": row["cwe_id"], "name": row["name"], "kind": row["kind"], "abstraction": row["abstraction"],
        "status": row["status"], "description": row["description"],
        "extended_description": _short(raw.get("extended_description"), 1200),
        "consequences": _short(raw.get("consequences"), 800),
        "mitigations": _short(raw.get("mitigations"), 1500),
        "observed_examples": row["observed"], "catalog_version": row["catalog_version"],
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")
    server.run("stdio")


if __name__ == "__main__":
    main()
