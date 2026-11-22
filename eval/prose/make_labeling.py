"""사람 라벨링 파일 생성: v4 보고서에서 케이스마다 반복 하나를 무작위(고정 시드)로 골라 요약문과 사실표를 나란히 둔다.

채점기 판정은 넣지 않는다 (라벨을 채점기에 맞추지 않도록). 고르는 기준도 채점 결과와 무관하다.
  python eval/prose/make_labeling.py
"""

import glob
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))

from prose_grade import facts, load_trace  # noqa: E402

TRACES = ROOT / ".claude" / "hillclimb" / "triage" / "v4" / "traces"
HEADER = """# 요약문 개수 검증 (사람 라벨)

각 요약문의 **숫자(…개, …건)** 가 아래 사실표와 맞는지만 봐 주세요. 다른 내용(설명, 조치)은 보지 않아도 됩니다.

- 숫자 하나라도 사실과 다르면 **X**, 모두 맞으면 **O**
- 숫자가 가리키는 대상까지 봐 주세요. 예: 취약 패키지가 7개인데 "취약점 7건"이라고 썼다면 X
- "약 / 여 / 이상 / 가량"이 붙은 근사 표현은 실제 값과 10% 이내(작은 수는 ±2)면 O. "이상"은 실제 값이 그 이상이어야 O
- 0개, 1개처럼 1 이하의 숫자는 보지 않아도 됩니다. 패키지 하나에 대한 개수("log4j-core에 3건")는 패키지별 개수와 비교

답은 채팅에 **X인 번호만** 적어 주세요. 예: `X: 3, 7, 12` (이유를 덧붙이면 더 좋습니다)
"""


def main() -> None:
    cases = sorted({Path(p).name.rsplit("_rep", 1)[0] for p in glob.glob(str(TRACES / "*.json"))})
    rng = random.Random(7)
    items = [(c, rng.choice([0, 1, 2])) for c in cases]
    rng.shuffle(items)  # 케이스 이름 순서로 내용이 짐작되지 않게
    lines, meta = [HEADER], []
    for i, (case, rep) in enumerate(items, 1):
        payload, check, report = load_trace(TRACES / f"{case}_rep{rep}.json")
        f = facts(payload, check, report)
        meta.append({"no": i, "case": case, "rep": rep})
        short = lambda k: k.split("/", 1)[1].rsplit("@", 1)[0].split(":")[-1]  # noqa: E731
        per = ", ".join(f"{short(k)} {v}건" for k, v in f["per_package"].items()) or "없음"
        lines += [f"## {i}", "", "> " + report["summary"].replace("\n", " "), "", "| 사실 | 값 |", "|---|---|",
                  f"| 버전이 확인된 직접 의존성 (검사 대상) | {f['dependencies']} |",
                  f"| 검사하지 못한 항목 (버전 범위 등) | {f['unchecked']} |",
                  f"| 위 둘의 합 | {f['dependencies_plus_unchecked']} |",
                  f"| 취약점이 있는 패키지 | {f['vulnerable_packages']} |",
                  f"| 알려진 취약점이 없는 패키지 | {f['no_known_vuln_packages']} |",
                  f"| 취약점 총수 | {f['vulnerabilities']} |",
                  f"| 그중 KEV 등재 | {f['kev_vulnerabilities']} |",
                  f"| 패키지별 취약점 수 | {per} |",
                  f"| 파서 메모의 전체 패키지 수 | {', '.join(map(str, f['parser_note_numbers'])) or '없음'} |", ""]
    (HERE / "labeling.md").write_text("\n".join(lines), encoding="utf-8")
    (HERE / "labeling_items.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print(f"{len(meta)} items -> {HERE / 'labeling.md'}")


if __name__ == "__main__":
    main()
