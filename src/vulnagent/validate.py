"""보고서를 이번 실행의 도구 결과와 대조하는 결정적 검사 (v3).

3주차 오류 분석에서 Haiku 실패 3건이 모두 '도구 목록을 옮겨 적는 과정의 실수'였다:
  - 옮겨 적기 오류: CVE-2020-25626 -> CVE-2025-25626
  - 다른 패키지에 붙이기: node-serialize의 CVE-2017-5941을 mathjs 아래에도 기록
  - 누락: 77건 중 1건 빠뜨림
이런 실수는 판단 문제가 아니라 기록 문제라서, 실행 중에 코드로 찾아 모델에게 고치게 할 수 있다.
정답(gold)은 쓰지 않는다. 에이전트가 실행 중에 받은 도구 결과만 기준으로 삼는다.
"""

from .ids import ECOSYSTEMS, normalize_package_name, normalize_vuln_id


def _canon(vuln_id: str) -> str:
    return (normalize_vuln_id(vuln_id) or vuln_id.strip()).upper()


def _split(label: str) -> tuple[str | None, str]:
    ecosystem, sep, rest = label.strip().partition("/")
    if not sep or ecosystem.lower() not in ECOSYSTEMS:
        ecosystem, rest = None, label.strip()
    name, at, _version = rest.rpartition("@")
    return (ECOSYSTEMS.get(ecosystem.lower()) if ecosystem else None), (name if at and name else rest)


def validate_report(report: dict, check_outputs: list[dict]) -> list[str]:
    """문제 목록을 돌려준다. 비어 있으면 통과."""
    expected: dict[str, dict[str, dict]] = {}  # 패키지키 -> {대표ID: 취약점}
    alias: dict[tuple[str, str], str] = {}
    label_of: dict[str, str] = {}
    ecosystems = set()
    for out in check_outputs:
        for res in out.get("results", []):
            if res.get("status") != "vulnerable":
                continue
            eco, name = _split(res["package"])
            ecosystems.add(eco)
            key = normalize_package_name(eco, name).lower()
            label_of[key] = res["package"]
            for v in res.get("vulnerabilities", []):
                expected.setdefault(key, {})[v["id"]] = v
                for a in {v["id"], *v.get("cve_ids", []), *v.get("osv_ids", [])}:
                    alias[(key, _canon(a))] = v["id"]
    default_eco = next(iter(ecosystems)) if len(ecosystems) == 1 else None

    problems: list[str] = []
    reported: dict[str, set[str]] = {}
    for pkg in report.get("packages", []):
        eco, name = _split(pkg.get("package", ""))
        key = normalize_package_name(eco or default_eco or "", name).lower()
        if key not in expected:
            problems.append(f"{pkg.get('package')}: check_packages returned no vulnerabilities for this package; remove it")
            continue
        seen = reported.setdefault(key, set())
        for v in pkg.get("vulnerabilities", []):
            vid = alias.get((key, _canon(v.get("id", ""))))
            if vid is None:
                elsewhere = [label_of[k] for (k, a), _ in alias.items() if a == _canon(v.get("id", "")) and k != key]
                if elsewhere:
                    problems.append(f"{v.get('id')} is listed under {pkg.get('package')}, but check_packages returned it "
                                    f"only for {', '.join(sorted(set(elsewhere)))}")
                else:
                    problems.append(f"{v.get('id')} (under {pkg.get('package')}) was not returned by check_packages; "
                                    "check the id for typos")
                continue
            if vid in seen:
                problems.append(f"{vid} is listed twice under {pkg.get('package')}")
            seen.add(vid)
            tool_kev = bool(expected[key][vid].get("kev"))
            if bool(v.get("kev")) != tool_kev:
                problems.append(f"{vid}: kev should be {str(tool_kev).lower()} (from the check_packages result)")
    for key, vulns in expected.items():
        missing = sorted(set(vulns) - reported.get(key, set()))
        if missing:
            problems.append(f"{label_of[key]}: missing {len(missing)} vulnerabilities returned by check_packages: {', '.join(missing)}")
    return problems
