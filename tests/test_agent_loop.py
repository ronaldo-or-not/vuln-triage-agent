"""에이전트 루프를 가짜 LLM으로 끝까지 검증한다 (API 비용 없음).

가짜 클라이언트가 1턴에 check_packages 호출을, 2턴에 최종 JSON을 낸다. 도구는 진짜 MCP 서버를
서브프로세스로 띄워 테스트 DB에 붙는다. 확인하는 것:
- 도구 결과가 진짜로 MCP를 거쳐 오는지, tool_result가 tool_use_id와 짝이 맞는지
- 요청에 구조화 출력, fallback, thinking 설정이 들어가는지
- trace가 리포트 형식(system/user/tool_call/tool_result/assistant)으로 쌓이는지
"""

import asyncio
import json
from types import SimpleNamespace

from conftest import TEST_DATABASE_URL

from vulnagent.agent import FALLBACK_BETA, REPORT_SCHEMA, run_triage
from vulnagent.depfiles import parse_requirements


def _msg(blocks, stop_reason):
    usage = SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=0,
                            cache_creation_input_tokens=0, iterations=None)
    return SimpleNamespace(content=blocks, stop_reason=stop_reason, model="claude-opus-5-5", usage=usage)


class FakeStream:
    def __init__(self, message):
        self.message = message

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_final_message(self):
        return self.message


class FakeClient:
    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    def _stream(self, **kwargs):
        self.requests.append(kwargs)
        return FakeStream(self.script.pop(0)(kwargs))


def test_agent_loop_calls_mcp_tool_and_returns_structured_report(seeded_db):
    final_report = {"summary": "s", "packages": [], "unchecked": [], "notes": []}
    seen_tool_result = {}

    def turn1(_kwargs):
        return _msg([
            SimpleNamespace(type="thinking", thinking="check all packages first"),
            SimpleNamespace(type="tool_use", id="toolu_1", name="check_packages",
                            input={"packages": [{"ecosystem": "PyPI", "name": "jinja2", "version": "2.10"}]}),
        ], "tool_use")

    def turn2(kwargs):
        seen_tool_result.update(kwargs["messages"][-1]["content"][0])
        return _msg([SimpleNamespace(type="text", text=json.dumps(final_report))], "end_turn")

    client = FakeClient([turn1, turn2])
    parsed = parse_requirements("Jinja2==2.10\nflask>=2\n")
    run = asyncio.run(run_triage(parsed, "requirements.txt", client=client,
                                 mcp_env={"DATABASE_URL": TEST_DATABASE_URL, "VULNAGENT_OFFLINE": "1"}))

    assert run.status == "ok" and run.report == final_report
    assert [t["name"] for t in run.tool_calls] == ["check_packages"] and not run.tool_calls[0]["is_error"]
    assert seen_tool_result["tool_use_id"] == "toolu_1" and "CVE-2019-10906" in seen_tool_result["content"]

    first = client.requests[0]
    assert first["output_config"]["format"]["schema"] == REPORT_SCHEMA
    assert first["fallbacks"] == "default" and FALLBACK_BETA in first["betas"]
    assert {t["name"] for t in first["tools"]} == {"check_packages", "get_vulnerability"}
    assert "flask>=2" in first["messages"][0]["content"]  # 검사 불가 항목도 모델에게 전달

    # v3: 잘못 옮겨 적은 ID가 든 보고서 -> 검증기가 찾아서 교정 턴 -> 고친 보고서를 최종으로 채택
    bad = {"summary": "s", "packages": [{"package": "PyPI/jinja2@2.10", "upgrade_to": None, "reason": "",
                                         "vulnerabilities": [{"id": "CVE-2099-10906", "rank": 1, "priority": "high", "kev": False}]}],
           "unchecked": [], "notes": []}
    feedback_seen = {}

    def corrected(kwargs):
        feedback_seen["text"] = kwargs["messages"][-1]["content"]
        tool_out = json.loads(kwargs["messages"][2]["content"][0]["content"])  # 1턴의 check_packages 결과
        res = tool_out["results"][0]
        good = {"summary": "s", "unchecked": [], "notes": [], "packages": [{
            "package": res["package"], "upgrade_to": None, "reason": "",
            "vulnerabilities": [{"id": x["id"], "rank": i + 1, "priority": "high", "kev": bool(x["kev"])}
                                for i, x in enumerate(res["vulnerabilities"])]}]}
        return _msg([SimpleNamespace(type="text", text=json.dumps(good))], "end_turn")

    v3_client = FakeClient([turn1, lambda _k: _msg([SimpleNamespace(type="text", text=json.dumps(bad))], "end_turn"), corrected])
    v3 = asyncio.run(run_triage(parsed, "requirements.txt", client=v3_client, validate=True,
                                mcp_env={"DATABASE_URL": TEST_DATABASE_URL, "VULNAGENT_OFFLINE": "1"}))
    assert v3.corrections == 1 and len(v3_client.requests) == 3 and v3.status == "ok"
    assert "CVE-2099-10906" in feedback_seen["text"] and "missing" in feedback_seen["text"]
    assert {x["id"] for x in v3.report["packages"][0]["vulnerabilities"]} >= {"CVE-2019-10906"}

    # 같은 루프를 Haiku로: fallback을 지원하지 않으므로 보내지 않아야 한다
    haiku = FakeClient([lambda _k: _msg([SimpleNamespace(type="text", text=json.dumps(final_report))], "end_turn")])
    asyncio.run(run_triage(parsed, "requirements.txt", model="claude-haiku-5-5", client=haiku,
                           mcp_env={"DATABASE_URL": TEST_DATABASE_URL, "VULNAGENT_OFFLINE": "1"}))
    assert "fallbacks" not in haiku.requests[0] and "betas" not in haiku.requests[0]

    roles = [t["role"] for t in run.trace]
    assert roles == ["system", "user", "tool_call", "tool_result", "assistant"]
    assert run.trace[2]["thinking"] == "check all packages first"
    assert run.usage_total()["input_tokens"] == 200


def test_user_message_carries_input_counts_only_with_hints():
    import json as _json

    from vulnagent.agent import build_user_message
    from vulnagent.depfiles import Dependency, ParseResult, Unchecked

    parsed = ParseResult("requirements.txt", "PyPI", [Dependency("PyPI", "flask", "2.0.0")],
                         [Unchecked("requests", "not pinned"), Unchecked("click", "not pinned")])
    payload = lambda text: _json.loads(text.split("```json\n", 1)[1].split("\n```", 1)[0])  # noqa: E731
    assert "counts" not in payload(build_user_message(parsed, "requirements.txt"))
    assert payload(build_user_message(parsed, "requirements.txt", counts=True))["counts"] == \
        {"dependencies": 1, "unchecked": 2, "total_entries": 3}


def test_report_schema_adds_cwe_fields_without_touching_the_base_schema():
    from vulnagent.agent import report_schema

    before = json.dumps(REPORT_SCHEMA, sort_keys=True)
    schema = report_schema(cwe=True)
    pkg = schema["properties"]["packages"]["items"]
    vuln = pkg["properties"]["vulnerabilities"]["items"]
    assert "workaround" in pkg["required"] and "cwe" in vuln["required"]
    assert report_schema(cwe=False) is REPORT_SCHEMA and json.dumps(REPORT_SCHEMA, sort_keys=True) == before


def test_cwe_arms_choose_tools_and_label_visibility(seeded_db):
    """8주차 세 실험군: 같은 보고서 형식에 CWE 정보의 출처만 다르다.
    labels는 security-kb 서버(두 번째 MCP 서버)의 get_weakness/search_weaknesses를 받고, check_packages 결과에
    cwes가 붙는다. memory는 지식베이스 도구도 라벨도 없다. 없는 도구 이름은 오류 결과로 돌려준다."""
    parsed = parse_requirements("Jinja2==2.10\n")
    seen = {}

    def turn1(_kwargs):
        return _msg([
            SimpleNamespace(type="tool_use", id="toolu_1", name="check_packages",
                            input={"packages": [{"ecosystem": "PyPI", "name": "jinja2", "version": "2.10"}]}),
            SimpleNamespace(type="tool_use", id="toolu_2", name="no_such_tool", input={}),
        ], "tool_use")

    def turn2(kwargs):
        seen["results"] = kwargs["messages"][-1]["content"]
        return _msg([SimpleNamespace(type="text", text=json.dumps({"summary": "s", "packages": [], "unchecked": [], "notes": []}))], "end_turn")

    env = {"DATABASE_URL": TEST_DATABASE_URL, "VULNAGENT_OFFLINE": "1"}
    labels = FakeClient([turn1, turn2])
    run = asyncio.run(run_triage(parsed, "requirements.txt", client=labels, cwe="labels", mcp_env=env))
    first = labels.requests[0]
    assert {t["name"] for t in first["tools"]} == {"check_packages", "get_vulnerability", "get_weakness", "search_weaknesses"}
    assert "cwe" in first["output_config"]["format"]["schema"]["properties"]["packages"]["items"]["properties"]["vulnerabilities"]["items"]["properties"]
    assert "returns `cwes`" in first["system"]
    check_result, unknown = seen["results"]
    assert '"cwes":[{"id":"CWE-693"' in check_result["content"] and not check_result["is_error"]
    assert unknown["is_error"] and "unknown tool" in unknown["content"]
    assert [t["is_error"] for t in run.tool_calls] == [False, True]

    memory = FakeClient([turn1, turn2])
    asyncio.run(run_triage(parsed, "requirements.txt", client=memory, cwe="memory", mcp_env=env))
    assert {t["name"] for t in memory.requests[0]["tools"]} == {"check_packages", "get_vulnerability"}
    assert "own knowledge" in memory.requests[0]["system"]
    assert '"cwes"' not in seen["results"][0]["content"]
