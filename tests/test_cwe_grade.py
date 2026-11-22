"""8주차 CWE 채점기 테스트 (DB·API 없음)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))

from cwe_grade import grade_cwe, oracle_cwe_report, tool_evidence  # noqa: E402

GOLD = {
    "ecosystem": "npm",
    "vulns": [
        {"id": "CVE-2017-5941", "aliases": ["CVE-2017-5941", "GHSA-q4v7-4rhw-9hqm"], "package": "npm/node-serialize@0.0.4",
         "fix_status": "no_fix"},
        {"id": "CVE-2021-23337", "aliases": ["CVE-2021-23337"], "package": "npm/lodash@4.17.15", "fix_status": "fixed"},
        {"id": "CVE-2020-8203", "aliases": ["CVE-2020-8203"], "package": "npm/lodash@4.17.15", "fix_status": "fixed"},
        {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["GHSA-xxxx-yyyy-zzzz"], "package": "npm/lodash@4.17.15", "fix_status": "fixed"},
    ],
    "packages": [
        {"package": "npm/node-serialize@0.0.4", "min_safe_upgrade": None},
        {"package": "npm/lodash@4.17.15", "min_safe_upgrade": "4.17.21"},
        # 이 줄에는 수정이 없지만(no_fix) 더 높은 버전으로 올리면 벗어난다 -> 완화책 불필요 (파일럿에서 찾은 정의 오류)
        {"package": "npm/qs@6.5.0", "min_safe_upgrade": "6.14.1"},
    ],
}
GOLD["vulns"].append({"id": "CVE-2025-15284", "aliases": ["CVE-2025-15284"], "package": "npm/qs@6.5.0", "fix_status": "no_fix"})
LABELS = {"CVE-2017-5941": {"CWE-502"}, "CVE-2021-23337": {"CWE-94", "CWE-77"}, "CVE-2020-8203": {"CWE-1321"},
          "GHSA-xxxx-yyyy-zzzz": set(), "CVE-2025-15284": set()}  # 라벨 없음 -> 정답률 분모에서 빠진다
CATALOG = {c: c for c in ("CWE-502", "CWE-94", "CWE-77", "CWE-1321", "CWE-79", "CWE-790")}


def report(cwes: dict, workaround: dict) -> dict:
    pkgs = {}
    for v in GOLD["vulns"]:
        pkg = pkgs.setdefault(v["package"], {"package": v["package"], "vulnerabilities": [],
                                             "workaround": workaround.get(v["package"])})
        pkg["vulnerabilities"].append({"id": v["id"], "cwe": cwes.get(v["id"])})
    return {"packages": list(pkgs.values())}


def call(name, args, result):
    return [{"role": "tool_call", "name": name, "content": json.dumps(args)},
            {"role": "tool_result", "content": json.dumps(result)}]


def test_oracle_report_gets_everything_right():
    rep, trace = oracle_cwe_report(GOLD, LABELS)
    c = grade_cwe(rep, trace, GOLD, LABELS, CATALOG)["counts"]
    assert c["labeled"] == 3 and c["hit"] == 3 and c["valid"] == c["answered"]
    assert c["wa_needed"] == 1 and c["wa_present"] == c["wa_relevant"] == c["wa_grounded"] == 1 and c["wa_extra"] == 0


def test_wrong_null_and_invented_ids():
    rep = report({"CVE-2017-5941": "CWE-79", "CVE-2021-23337": "cwe-77", "CVE-2020-8203": "CWE-99999"}, {})
    g = grade_cwe(rep, [], GOLD, LABELS, CATALOG)
    c = g["counts"]
    assert c["hit"] == 1  # 소문자 cwe-77도 정답 (두 라벨 중 하나)
    assert c["answered"] == 3 and c["valid"] == 2  # CWE-99999는 카탈로그에 없다
    assert c["grounded"] == 0  # 도구 결과가 없으면 전부 기억에서 나온 것
    assert any("CVE-2017-5941" in m for m in g["misses"])
    assert c["wa_needed"] == 1 and c["wa_present"] == 0


def test_missing_vulnerability_counts_as_a_miss():
    rep = report({"CVE-2017-5941": "CWE-502"}, {})
    rep["packages"] = [p for p in rep["packages"] if "lodash" not in p["package"]]
    c = grade_cwe(rep, [], GOLD, LABELS, CATALOG)["counts"]
    assert (c["hit"], c["labeled"]) == (1, 3)


def test_grounding_uses_tool_results_and_get_weakness_pairing():
    # 병렬 호출: tool_call 두 개 뒤에 결과 두 개가 같은 순서로 온다
    trace = [
        {"role": "tool_call", "name": "search_weaknesses_many", "content": "{}"},
        {"role": "tool_call", "name": "get_weakness", "content": json.dumps({"cwe_id": "CWE-502"})},
        {"role": "tool_result", "content": json.dumps({"results": [{"key": "CVE-2021-23337", "candidates": [{"cwe_id": "CWE-94"}]}]})},
        {"role": "tool_result", "content": json.dumps({"cwe_id": "CWE-502", "mitigations": "..."})},
    ] + call("get_weakness", {"cwe_id": "CWE-1"}, "not a dict")
    trace[-1]["content"] = "Tool call failed: CWE-1 is not in the catalog"
    anywhere, detailed = tool_evidence(trace)
    assert anywhere == {"CWE-94", "CWE-502", "CWE-1"} and detailed == {"CWE-502"}

    rep = report({"CVE-2017-5941": "CWE-502", "CVE-2021-23337": "CWE-94", "CVE-2020-8203": "CWE-1321"},
                 {"npm/node-serialize@0.0.4": "신뢰할 수 없는 데이터를 역직렬화하지 않는다 (CWE-502)"})
    c = grade_cwe(rep, trace, GOLD, LABELS, CATALOG)["counts"]
    assert c["grounded"] == 2  # CWE-1321은 어느 도구 결과에도 없었다
    assert c["wa_relevant"] == 1 and c["wa_grounded"] == 1


def test_cwe_id_boundaries():
    anywhere, _ = tool_evidence(call("search_weaknesses", {}, {"results": [{"cwe_id": "CWE-790"}]}))
    assert anywhere == {"CWE-790"}  # CWE-79가 CWE-790 안에 들어 있다고 보지 않는다


def test_workaround_relevance_and_extra():
    rep = report({}, {"npm/node-serialize@0.0.4": "입력 검증을 강화한다 (CWE-20)",
                      "npm/lodash@4.17.15": "업그레이드 전까지 merge 사용을 피한다 (CWE-1321)"})
    g = grade_cwe(rep, [], GOLD, LABELS, CATALOG)
    c = g["counts"]
    assert c["wa_present"] == 1 and c["wa_relevant"] == 0 and c["wa_grounded"] == 0
    assert c["wa_extra"] == 1  # lodash는 안전한 업그레이드가 있어 완화책이 필요 없다
    assert any("CWE-20" in m for m in g["wa_misses"])


def test_package_whose_no_fix_line_can_be_escaped_needs_no_workaround():
    rep = report({}, {"npm/qs@6.5.0": "입력 크기를 제한한다 (CWE-20)"})
    c = grade_cwe(rep, [], GOLD, LABELS, CATALOG)["counts"]
    assert c["wa_needed"] == 1 and c["wa_extra"] == 1  # node-serialize만 필요, qs에 쓴 것은 참고용으로만 센다
