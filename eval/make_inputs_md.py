"""검토용 문서 eval/inputs.md 생성: 케이스마다 에이전트가 받는 입력 전문 + 코드로 계산한 정답 요약."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from casefiles import AS_OF, load_cases, load_gold, parse_case  # noqa: E402

from vulnagent.agent import build_user_message  # noqa: E402

FENCE = "````"  # 입력 안에 ``` 가 들어 있어서 더 긴 펜스를 쓴다


def main() -> int:
    cases = load_cases()
    lines = [
        "# 평가 입력 검토 (2주차, v0)",
        "",
        f"- 케이스 {len(cases)}개, 모두 공개 저장소의 실제 파일 (커밋 고정). 스냅샷 기준일 {AS_OF} (KEV·EPSS 고정)",
        "- 정답은 1주차 DB에서 코드로 계산 (`eval/build_gold.py`). 사람이나 모델이 쓴 정답이 아님",
        "- 에이전트 입력 = 파서 결과(검사할 패키지 + 검사 불가 목록). 원본 파일 대신 이것을 받는다",
        "",
        "| id | 태그 | 출처 | 검사 | 검사불가 | 정답 취약점 | KEV | 취약 패키지 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    sections = []
    for case in cases:
        gold, parsed = load_gold(case["id"]), parse_case(case)
        url = f"https://github.com/{case['repo']}/blob/{case['commit']}/{case['main']}"
        kev = [v["id"] for v in gold["vulns"] if v["kev"]]
        lines.append(
            f"| {case['id']} | {', '.join(case['tags'])} | [{case['repo']}]({url}) | {len(parsed.dependencies)} | "
            f"{len(parsed.unchecked)} | {len(gold['vulns'])} | {len(kev)} | {len(gold['packages'])} |"
        )
        body = [f"## {case['id']}", "", f"출처: [{case['repo']}@{case['commit'][:12]} {case['main']}]({url})"]
        if case.get("companion"):
            body.append(f"함께 쓴 부모 POM: `{case['companion']}`")
        body += ["", "**정답 요약**", ""]
        if gold["packages"]:
            for p in gold["packages"]:
                n = sum(1 for v in gold["vulns"] if v["package"] == p["package"])
                body.append(f"- `{p['package']}`: 취약점 {n}건, 안전한 최소 업그레이드 `{p['min_safe_upgrade'] or '없음 (모두 고치는 버전 없음)'}`")
        else:
            body.append("- 취약점 없음 (보고서에 패키지가 하나도 없어야 정답)")
        if kev:
            body.append(f"- KEV 등재: {', '.join(kev)} (이것들이 순위 맨 위여야 함)")
        if gold["unchecked"]:
            body.append(f"- 검사 불가로 보고해야 할 항목 {len(gold['unchecked'])}개")
        body += ["", "**에이전트가 받는 입력 전문**", "", FENCE, build_user_message(parsed, Path(case["main"]).name), FENCE, ""]
        sections += body
    out = Path(__file__).parent / "inputs.md"
    out.write_text("\n".join(lines + [""] + sections), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
