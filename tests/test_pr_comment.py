"""PR 코멘트 테스트 (API·DB·GitHub 없음). 에이전트·데이터 레이어·GitHub API를 가짜로 바꾼다."""

import vulnagent.agent
from vulnagent import pr_comment as pc
from vulnagent.agent import TriageRun


def test_select_files_matches_names_excludes_eval_and_pairs_lockfiles():
    picked, skipped = pc.select_files([
        "eval/cases/npm-x/package-lock.json", "tests/fixtures/requirements.txt",  # 평가·테스트 파일은 제외
        "docs/notes.txt", "README.md",                                           # 의존성 파일 아님
        "web/package.json", "web/package-lock.json",                             # lockfile만, package.json은 함께 읽기
        "api/requirements-dev.txt", "svc/core/pom.xml", "build.gradle",
    ])
    assert picked == [("api/requirements-dev.txt", None), ("build.gradle", None), ("svc/core/pom.xml", "svc/pom.xml")]
    assert skipped == ["web/package-lock.json"]  # 최대 3개


def _check(vulns_by_pkg):
    """가짜 check_packages: {(ecosystem, name, version): [vuln ids]}."""
    def check(packages):
        results = []
        for p in packages:
            ids = vulns_by_pkg.get((p["ecosystem"], p["name"].lower(), p["version"]), [])
            results.append({"package": f"{p['ecosystem']}/{p['name'].lower()}@{p['version']}",
                            "status": "vulnerable" if ids else "no_known_vulns",
                            "safe_upgrade": "9.9", "vulnerabilities": [
                                {"id": i, "cve_ids": [i], "osv_ids": [f"GHSA-{i[-4:]}-aaaa-bbbb"], "kev": False,
                                 "policy_rank": n + 1} for n, i in enumerate(ids)]})
        return {"results": results}
    return check


DATA = {("PyPI", "django", "3.2.0"): ["CVE-2021-1111"], ("PyPI", "pyyaml", "5.3.1"): ["CVE-2020-14343"]}


def _report(*packages):
    return {"summary": "@octocat 님, PyYAML 5.3.1의 CVE-2020-14343을 먼저 고치세요. 표 | 깨짐 ![x](http://t)",
            "unchecked": [{"spec": "flask>=2", "reason": "not pinned"}], "notes": [], "packages": list(packages)}


PYYAML = {"package": "PyPI/pyyaml@5.3.1", "upgrade_to": "5.4", "reason": "5.4에서 수정", "workaround": None,
          "vulnerabilities": [{"id": "CVE-2020-14343", "rank": 1, "priority": "critical", "kev": False, "cwe": "CWE-20"}]}
DJANGO = {"package": "PyPI/django@3.2.0", "upgrade_to": None, "reason": "a|b", "workaround": "@admin 입력을 검증한다 (CWE-89)",
          "vulnerabilities": [{"id": "CVE-2021-1111", "rank": 2, "priority": "high", "kev": True, "cwe": "CWE-89"}]}


def test_triage_one_marks_only_vulnerabilities_new_in_this_pr(monkeypatch):
    seen = {}

    async def fake_run(parsed, label, **kwargs):
        seen.update(kwargs)
        return TriageRun(status="ok", report=_report(PYYAML, DJANGO), model_requested=kwargs["model"],
                         models_served=["claude-haiku-5-5"], calls=[{"model": "claude-haiku-5-5", "usage": {
                             "input_tokens": 1000, "output_tokens": 1000, "cache_read_input_tokens": 0,
                             "cache_creation_input_tokens": 0}}])
    monkeypatch.setattr(vulnagent.agent, "run_triage", fake_run)

    result = pc.triage_one("app/requirements.txt", "Django==3.2.0\nPyYAML==5.3.1\nflask>=2\n", "Django==3.2.0\n",
                           None, None, _check(DATA))
    assert seen == {"model": "claude-haiku-5-5", "validate": True, "tool_hints": True, "cwe": "labels"}  # CLI와 같은 설정
    assert result.is_new("PyPI/pyyaml@5.3.1", "CVE-2020-14343") is True
    assert result.is_new("PyPI/Django@3.2.0", "GHSA-1111-aaaa-bbbb") is False  # 이름 대소문자·별칭이 달라도 같은 취약점
    assert round(result.cost_usd, 6) == 0.0006

    body = pc.render([result], [], "abc1234def")
    assert body.startswith(pc.MARKER) and "이 PR에서 새로 생김 **1건**" in body
    new_section = body.split("#### 이 PR에서 새로 생긴 취약점")[1].split("####")[0]
    assert "CVE-2020-14343" in new_section and "CVE-2021-1111" not in new_section
    assert "[CWE-20](https://cwe.mitre.org/data/definitions/20.html)" in body
    assert "`PyPI/pyyaml@5.3.1`" in body and "커밋 abc1234" in body
    # 파일·모델에서 온 문장이 사람을 호출하거나 표·이미지를 만들지 못한다
    assert "@octocat" not in body and "@admin" not in body and "![x]" not in body
    assert "| a\\|b |" in body  # 표 칸 안의 '|'는 이스케이프 (요약은 인용문이라 표가 되지 않는다)


def test_scoped_npm_names_stay_inside_code_spans():
    res = pc.FileResult(path="web/package-lock.json", is_new_file=True, report={
        "summary": "s", "unchecked": [], "notes": [], "packages": [
            {"package": "npm/@babel/traverse@7.0.0", "upgrade_to": "7.23.2", "reason": "r", "workaround": None,
             "vulnerabilities": [{"id": "CVE-2023-45133", "rank": 1, "priority": "critical", "kev": False, "cwe": "CWE-184"}]}]})
    body = pc.render([res], [])
    assert "@babel" not in body.replace("`npm/@babel/traverse@7.0.0`", "")


def test_oversized_report_is_compacted_then_truncated():
    vulns = [{"id": f"CVE-2024-{i:05d}", "rank": i, "priority": "low", "kev": False, "cwe": "CWE-400"} for i in range(1, 900)]
    packages = [{"package": f"PyPI/pkg{i}@1.0", "upgrade_to": "2.0", "reason": "긴 이유 " * 60, "workaround": None,
                 "vulnerabilities": vulns[i * 9:(i + 1) * 9]} for i in range(100)]
    res = pc.FileResult(path="requirements.txt", report={"summary": "s", "packages": packages, "notes": ["n"] * 200,
                                                         "unchecked": [{"spec": f"x{i}", "reason": "r"} for i in range(500)]},
                        new_keys=set())
    body = pc.render([res], [])
    assert len(body) <= pc.MAX_BODY and body.startswith(pc.MARKER)


def test_agent_failure_falls_back_to_the_data_layer_table(monkeypatch):
    async def failing(parsed, label, **kwargs):
        raise TimeoutError
    monkeypatch.setattr(vulnagent.agent, "run_triage", failing)
    result = pc.triage_one("requirements.txt", "PyYAML==5.3.1\n", None, None, None, _check(DATA))
    assert result.status == "timeout" and result.report["packages"][0]["upgrade_to"] == "9.9"
    assert "에이전트가 끝내지 못했습니다" in pc.render([result], [])


def test_broken_file_is_reported_not_raised():
    result = pc.triage_one("package-lock.json", "{not json", None, None, None, _check({}))
    assert result.error and "검사하지 못했습니다" in pc.render([result], [])


def test_upsert_updates_the_bot_comment_with_the_marker_across_pages():
    calls = []

    def fake(method, url, token, body=None):
        calls.append((method, url.split("/repos/o/r")[1], body))
        if method == "GET" and url.endswith("&page=1"):  # 'per_page=100'에도 'page=1'이 들어 있다
            return [{"id": i, "body": "hi", "user": {"type": "User"}} for i in range(100)]
        if method == "GET":
            return [{"id": 501, "body": f"{pc.MARKER} old", "user": {"type": "User"}},  # 사람이 표식을 흉내 낸 댓글은 무시
                    {"id": 502, "body": f"{pc.MARKER} old", "user": {"type": "Bot"}}]
        return {}
    assert pc.upsert_comment("o/r", 7, "new body", "t", request=fake) == "updated"
    assert calls[-1] == ("PATCH", "/issues/comments/502", {"body": "new body"})

    calls.clear()
    assert pc.upsert_comment("o/r", 7, "b", "t", request=lambda m, u, t, b=None: calls.append((m, u)) or []) == "created"
    assert calls[-1][0] == "POST" and calls[-1][1].endswith("/issues/7/comments")


def test_missing_api_key_exits_green(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert pc.main([]) == 0
    assert "::notice::" in capsys.readouterr().out
