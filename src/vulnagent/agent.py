"""트리아지 에이전트 v0: 의존성 파일 -> 우선순위 보고서.

흐름
  1. 파싱 (코드, depfiles.py)          -> 검사할 패키지 / 검사 불가 목록
  2. 도구 호출 루프 (LLM + MCP)        -> check_packages, 필요하면 get_vulnerability
  3. 구조화 출력 (JSON 스키마로 강제)   -> 패키지별 업그레이드, 취약점 순위, 검사 불가 목록

도구 호출 루프를 SDK의 tool runner 대신 직접 구현한 이유: 평가에서 호출마다 토큰·지연·응답 모델을
기록하고(served-model 확인), 대화 전체를 trace로 남겨야 하기 때문이다.

MCP 서버(vulnagent.mcp_server)는 서브프로세스로 띄우고 stdio로 붙는다. 즉 에이전트는 1주차에 만든
도구를 실제 MCP 프로토콜로 쓴다.
"""

import copy
import json
import os
import sys
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anthropic
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from .depfiles import ParseResult, parse_file
from .validate import validate_report

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# 서버 측 fallback을 지원하는 모델만. Haiku 5.5는 지원하지 않는다 (보내면 요청이 거부될 수 있음).
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-1", "claude-fable-5-2"}
MAX_TURNS = 8
MAX_CORRECTIONS = 2  # v3 검증 교정 최대 횟수 (교정마다 보고서 전체를 다시 쓰므로 비용이 든다)
MAX_TOKENS = 64000  # 취약점 190건짜리 보고서도 잘리지 않게. 이 크기는 스트리밍이 필요하다.

SYSTEM_PROMPT = """You are a dependency vulnerability triage agent. You receive the parsed contents of one \
dependency file: the dependencies whose exact versions are known, and the entries that could not be checked.

Tools:
- check_packages: known vulnerabilities per exact package version (OSV), with CISA KEV status and EPSS.
- get_vulnerability: NVD details for one vulnerability. Slow (rate limited); use it only when you need details.

Process:
1. Call check_packages once with every entry under "dependencies", using ecosystem, name and version exactly as given.
2. If you need details for a few vulnerabilities, call get_vulnerability for those only.
3. Return the final report as JSON that follows the response schema.

Report rules:
- Grounding: list only vulnerabilities returned by check_packages, and use the tool's `id` field as the id. \
Never add vulnerabilities from memory. Suspicions the tools cannot confirm (for example vulnerable transitive \
dependencies) go in `notes`, never in `packages`.
- Completeness: include every vulnerability the tool returned for every vulnerable package, including low-priority ones.
- Ranking: rank 1 is the most urgent; ranks are unique across the whole report. Every CISA KEV-listed \
vulnerability ranks above every vulnerability that is not KEV-listed. Within each group, higher EPSS ranks \
higher; use severity to break ties.
- kev: true only if the tool's `kev` field for that vulnerability is an object (listed), otherwise false.
- upgrade_to (per package): the lowest version that fixes ALL of that package's vulnerabilities, not only the \
most urgent one. Choose it from the fixed versions the tool returned for that package. Fixed versions often \
belong to different release lines (for example 2.3.1 / 2.12.2 / 2.15.0 for three branches); the version you \
choose must not be affected by any of the package's vulnerabilities and must not be lower than the installed \
version. Use null when no single version fixes all of them, and say why in `reason`.
- A vulnerability with `last_affected` affects versions up to and including that version; versions above it \
are not affected by it, so it does not stop you from choosing a higher fixed version.
- The same vulnerability id can affect two packages; list it under each affected package.
- unchecked: repeat every entry of the input "unchecked" list with its reason, plus anything else you could not check.
- Do not list packages that have no vulnerabilities.
- Write `summary`, `reason` and `notes` in Korean."""

HINTS_ADDENDUM = """

Computed fields: check_packages also returns `safe_upgrade` for each vulnerable package and `policy_rank` for \
each vulnerability. Code computes them with the same rules as above (lowest fixed version not affected by any of \
the package's vulnerabilities; KEV first, then EPSS). Use `safe_upgrade` as upgrade_to and `policy_rank` as rank. \
Do not recompute them; spend your effort on the summary, reasons and notes.

Counts: check_packages also returns `counts` (packages_checked, vulnerable_packages, no_known_vulns_packages, vulnerabilities, unique_vulnerabilities, kev_listed) and `vulnerability_count` for each vulnerable package; the input carries `counts` for dependencies and unchecked entries. Every number you write in summary, reason or notes must be copied from one of these fields. Never count or add up by hand. `vulnerabilities` counts one per package, so an id listed under two packages counts twice; use unique_vulnerabilities when you mean distinct vulnerabilities."""

REPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "packages": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "package": {"type": "string", "description": "ecosystem/name@installed_version as returned by check_packages"},
                    "upgrade_to": {"type": ["string", "null"]},
                    "reason": {"type": "string"},
                    "vulnerabilities": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "rank": {"type": "integer"},
                                "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                                "kev": {"type": "boolean"},
                            },
                            "required": ["id", "rank", "priority", "kev"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["package", "upgrade_to", "reason", "vulnerabilities"],
                "additionalProperties": False,
            },
        },
        "unchecked": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"spec": {"type": "string"}, "reason": {"type": "string"}},
                "required": ["spec", "reason"],
                "additionalProperties": False,
            },
        },
        "notes": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "packages", "unchecked", "notes"],
    "additionalProperties": False,
}


# 8주차: CWE 연결 실험. 세 실험군은 보고서 형식과 공통 지시가 같고, CWE를 어디서 얻는지만 다르다.
#   memory  CWE 데이터 없음 (get_vulnerability의 CWE 필드도 숨김). 모델의 기억만으로 고른다
#   labels  check_packages가 GHSA/NVD 라벨을 붙여 준다. 완화책은 security-kb의 get_weakness로 찾는다
#   search  라벨을 숨기고 security-kb 검색 후보 중에서 고른다 (4주차 검색기를 에이전트에 연결)
CWE_ARMS = ("memory", "labels", "search")
CWE_MODE_FOR_ARM = {"memory": "hidden", "labels": "labels", "search": "hidden"}
KB_TOOLS_FOR_ARM = {"memory": set(), "labels": {"get_weakness", "search_weaknesses"},
                    "search": {"get_weakness", "search_weaknesses_many"}}

CWE_COMMON = """

Weakness types and workarounds: for each vulnerability set `cwe` to the one CWE id (form CWE-<number>) that best \
describes its weakness, or null if you cannot tell. For each package whose upgrade_to is null, or that has a \
vulnerability with no fixed version, write `workaround` in Korean: concrete mitigations to apply until an upgrade \
is possible, citing the CWE ids they address in parentheses, for example (CWE-502). Set workaround to null for \
every other package."""

CWE_ARM_TEXT = {
    "memory": " No tool provides CWE ids or mitigations; use your own knowledge.",
    "labels": " check_packages returns `cwes` for each vulnerability: the CWE labels GHSA and NVD assigned. Use one "
              "of them as `cwe`; when `cwes` is empty, you may look for a candidate with search_weaknesses or leave "
              "cwe null. Before writing a workaround, call get_weakness for the CWE ids involved and base the "
              "mitigations on its `mitigations` field.",
    "search": " No tool returns CWE labels. Call search_weaknesses_many once with one query per vulnerability "
              "(key = the vulnerability id, text = its summary), then for each vulnerability choose the candidate "
              "that fits its summary, or null if none fits. Before writing a workaround, call get_weakness for the "
              "CWE ids involved and base the mitigations on its `mitigations` field.",
}


def report_schema(cwe: bool = False) -> dict[str, Any]:
    """cwe=True면 취약점마다 cwe, 패키지마다 workaround 필드를 더한다 (구조화 출력이라 필수 필드로)."""
    if not cwe:
        return REPORT_SCHEMA
    schema = copy.deepcopy(REPORT_SCHEMA)
    pkg = schema["properties"]["packages"]["items"]
    vuln = pkg["properties"]["vulnerabilities"]["items"]
    vuln["properties"]["cwe"] = {"type": ["string", "null"], "description": "CWE-<number> or null"}
    vuln["required"].append("cwe")
    pkg["properties"]["workaround"] = {"type": ["string", "null"]}
    pkg["required"].append("workaround")
    return schema


def system_prompt(tool_hints: bool = False, cwe: str | None = None) -> str:
    return SYSTEM_PROMPT + (HINTS_ADDENDUM if tool_hints else "") + (CWE_COMMON + CWE_ARM_TEXT[cwe] if cwe else "")


@dataclass
class TriageRun:
    status: str  # ok | truncated | refusal | invalid_json | max_turns
    report: dict | None
    model_requested: str
    models_served: list[str] = field(default_factory=list)
    fallback_ran: bool = False
    calls: list[dict] = field(default_factory=list)  # 모델 호출마다 usage / latency / stop_reason
    tool_calls: list[dict] = field(default_factory=list)  # 도구 호출마다 이름 / 소요 시간 / 오류 여부
    trace: list[dict] = field(default_factory=list)  # 평가 리포트용 대화 기록
    stop_reason: str | None = None
    corrections: int = 0  # v3: 검증 실패로 모델에게 다시 고치게 한 횟수
    validation_log: list[list[str]] = field(default_factory=list)  # 교정마다 발견한 문제
    cwe: str | None = None  # 8주차: CWE 정보 출처 (None이면 보고서에 cwe/workaround 없음)

    def usage_total(self) -> dict:
        keys = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
        return {k: sum(c["usage"].get(k) or 0 for c in self.calls) for k in keys}


def build_user_message(parsed: ParseResult, file_label: str, context: str | None = None, counts: bool = False) -> str:
    payload = {
        "file": file_label,
        "ecosystem": parsed.ecosystem,
        "dependencies": [
            {"ecosystem": d.ecosystem, "name": d.name, "version": d.version, **({"scope": d.scope} if d.scope else {})}
            for d in parsed.dependencies
        ],
        "unchecked": [{"spec": u.spec, "reason": u.reason} for u in parsed.unchecked],
        "parser_notes": parsed.notes,
    }
    if counts:  # v5: 입력 쪽 개수도 미리 세어 준다 (검사하지 못한 항목 수는 도구가 모른다)
        payload["counts"] = {"dependencies": len(parsed.dependencies), "unchecked": len(parsed.unchecked),
                             "total_entries": len(parsed.dependencies) + len(parsed.unchecked)}
    text = "Triage this dependency file.\n\n```json\n" + json.dumps(payload, indent=1, ensure_ascii=False) + "\n```"
    if context:
        text += f"\n\nDeployment context from the user: {context}"
    return text


def server_params(env_overrides: dict[str, str] | None = None) -> StdioServerParameters:
    """에이전트가 띄울 vuln-data MCP 서버. DB 접속 정보와 평가용 고정값만 넘긴다."""
    passthrough = ("DATABASE_URL", "VULNAGENT_OFFLINE", "VULNAGENT_AS_OF", "NVD_API_KEY", "PATH", "HOME")
    env = {k: os.environ[k] for k in passthrough if k in os.environ}
    env.update(env_overrides or {})
    return StdioServerParameters(command=sys.executable, args=["-m", "vulnagent.mcp_server"], env=env)


def kb_server_params() -> StdioServerParameters:
    """security-kb MCP 서버 (CWE 지식베이스). 기본 검색은 BM25 + 관찰 사례라 torch를 올리지 않는다."""
    passthrough = ("DATABASE_URL", "PATH", "HOME", "VULNAGENT_KB_METHOD", "VULNAGENT_KB_OBSERVED", "VULNAGENT_KB_MODEL")
    env = {k: os.environ[k] for k in passthrough if k in os.environ}
    return StdioServerParameters(command=sys.executable, args=["-m", "vulnagent.kb_server"], env=env)


def _blocks_to_trace(content, trace: list[dict]) -> None:
    pending_thinking = None
    for block in content:
        if block.type == "thinking":
            pending_thinking = (pending_thinking or "") + (block.thinking or "")
        elif block.type == "text":
            trace.append({"role": "assistant", "content": block.text, **({"thinking": pending_thinking} if pending_thinking else {})})
            pending_thinking = None
        elif block.type == "tool_use":
            trace.append({"role": "tool_call", "name": block.name, "content": json.dumps(block.input, indent=2, ensure_ascii=False),
                          **({"thinking": pending_thinking} if pending_thinking else {})})
            pending_thinking = None


def _tool_result_text(result) -> tuple[str, bool]:
    if result.structured_content is not None:
        text = json.dumps(result.structured_content, ensure_ascii=False, separators=(",", ":"))
    else:
        text = "\n".join(getattr(c, "text", "") for c in result.content)
    return text, bool(result.is_error)


async def run_triage(
    parsed: ParseResult,
    file_label: str,
    *,
    model: str = DEFAULT_MODEL,
    effort: str = "medium",
    context: str | None = None,
    client: anthropic.AsyncAnthropic | None = None,
    mcp_env: dict[str, str] | None = None,
    validate: bool = False,
    tool_hints: bool = False,
    cwe: str | None = None,
) -> TriageRun:
    """validate=True (v3): 최종 보고서를 이번 실행의 check_packages 결과와 코드로 대조하고,
    문제가 있으면 목록을 알려 주며 최대 MAX_CORRECTIONS번 다시 쓰게 한다.
    tool_hints=True (v4): 도구가 safe_upgrade / policy_rank를 계산해 주고, 모델은 그 값을 쓴다.
    v5부터는 개수(counts)도 도구와 입력에 미리 계산해 넣는다 (요약문 개수 오류 대응).
    cwe (8주차): None이면 이전과 같다. memory / labels / search 중 하나면 보고서에 cwe와 workaround를 더하고,
    CWE 정보를 어디서 얻는지만 실험군마다 다르게 한다 (CWE_ARMS 주석 참고)."""
    if cwe is not None and cwe not in CWE_ARMS:
        raise ValueError(f"cwe must be one of {CWE_ARMS} or None, got {cwe!r}")
    client = client or anthropic.AsyncAnthropic()
    check_outputs: list[dict] = []
    user_message = build_user_message(parsed, file_label, context, counts=tool_hints)
    run = TriageRun(status="max_turns", report=None, model_requested=model, cwe=cwe)
    system = system_prompt(tool_hints, cwe)
    mcp_env = {**(mcp_env or {}), **({"VULNAGENT_TOOL_HINTS": "1"} if tool_hints else {}),
               **({"VULNAGENT_CWE_MODE": CWE_MODE_FOR_ARM[cwe]} if cwe else {})}
    run.trace += [{"role": "system", "content": system}, {"role": "user", "content": user_message}]
    messages: list[dict] = [{"role": "user", "content": user_message}]

    async with AsyncExitStack() as stack:
        # 도구 이름 -> 그 도구를 가진 MCP 클라이언트. 에이전트는 vuln-data와 security-kb 두 서버에 동시에 붙는다
        route: dict[str, Client] = {}
        tools: list[dict] = []
        servers = [(server_params(mcp_env), None)]
        if cwe and KB_TOOLS_FOR_ARM[cwe]:
            servers.append((kb_server_params(), KB_TOOLS_FOR_ARM[cwe]))
        for params, allowed in servers:
            client_ = await stack.enter_async_context(Client(params))
            for t in (await client_.list_tools()).tools:
                if allowed is None or t.name in allowed:
                    route[t.name] = client_
                    tools.append({"name": t.name, "description": t.description or "", "input_schema": t.input_schema})

        request: dict[str, Any] = {
            "model": model,
            "max_tokens": MAX_TOKENS,
            "system": system,
            "tools": tools,
            "thinking": {"type": "adaptive", "display": "summarized"},
            "output_config": {"effort": effort, "format": {"type": "json_schema", "schema": report_schema(bool(cwe))}},
            "cache_control": {"type": "ephemeral"},
        }
        if model in FALLBACK_MODELS:
            # 안전 분류기가 거절하면 서버가 다른 모델로 같은 요청을 이어서 처리
            request.update(betas=[FALLBACK_BETA], fallbacks="default")

        for _turn in range(MAX_TURNS):
            started = time.monotonic()
            async with client.beta.messages.stream(**request, messages=messages) as stream:
                response = await stream.get_final_message()
            fallback = any(getattr(it, "type", "") == "fallback_message" for it in (response.usage.iterations or []))
            run.fallback_ran = run.fallback_ran or fallback
            run.models_served.append(response.model)
            run.calls.append({
                "model": response.model,
                "stop_reason": response.stop_reason,
                "latency_s": round(time.monotonic() - started, 2),
                "fallback": fallback,
                "usage": {k: getattr(response.usage, k, None) for k in
                          ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")},
            })
            run.stop_reason = response.stop_reason
            _blocks_to_trace(response.content, run.trace)
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "tool_use":
                results = []
                for block in (b for b in response.content if b.type == "tool_use"):
                    t0 = time.monotonic()
                    try:
                        if block.name not in route:
                            raise ValueError(f"unknown tool {block.name!r}")
                        result = await route[block.name].call_tool(block.name, block.input)
                        text, is_error = _tool_result_text(result)
                    except Exception as exc:  # 도구 장애도 모델이 읽고 대응할 수 있게 오류 결과로 돌려준다
                        text, is_error = f"Tool call failed: {exc}", True
                    run.tool_calls.append({"name": block.name, "latency_s": round(time.monotonic() - t0, 2), "is_error": is_error})
                    run.trace.append({"role": "tool_result", "content": text})
                    if block.name == "check_packages" and not is_error:
                        try:
                            check_outputs.append(json.loads(text))
                        except json.JSONDecodeError:
                            pass
                    results.append({"type": "tool_result", "tool_use_id": block.id, "content": text, "is_error": is_error})
                messages.append({"role": "user", "content": results})  # 병렬 호출 결과는 한 메시지에 모아서
                continue
            if response.stop_reason == "pause_turn":
                continue
            if response.stop_reason == "max_tokens":
                run.status = "truncated"
            elif response.stop_reason == "refusal":
                run.status = "refusal"
            else:
                text = "".join(b.text for b in response.content if b.type == "text")
                try:
                    run.report = json.loads(text)
                    run.status = "ok"
                    problems = validate_report(run.report, check_outputs) if validate else []
                    if problems and run.corrections < MAX_CORRECTIONS:
                        run.corrections += 1
                        run.validation_log.append(problems)
                        feedback = (
                            "Your report does not match the check_packages results:\n- " + "\n- ".join(problems[:30])
                            + "\n\nReturn the complete corrected report in the same schema: every vulnerable package and "
                            "every vulnerability, using only ids that check_packages returned, under the package it returned them for."
                        )
                        run.trace.append({"role": "user", "content": feedback})
                        messages.append({"role": "user", "content": feedback})
                        continue
                except json.JSONDecodeError:
                    run.status = "invalid_json"
            break
    return run


async def triage_file(path: str, companion: str | None = None, **kwargs) -> tuple[ParseResult, TriageRun]:
    parsed = parse_file(path, companion)
    run = await run_triage(parsed, Path(path).name, **kwargs)
    return parsed, run
