"""평가 케이스 로딩 공통 코드 (gold 생성기와 러너가 같이 쓴다)."""

import json
from datetime import date
from pathlib import Path

from vulnagent.depfiles import ParseResult, parse_file

EVAL = Path(__file__).parent
AS_OF = date(2026, 11, 20)  # 평가에 고정할 KEV/EPSS 스냅샷 날짜


def load_cases() -> list[dict]:
    return json.loads((EVAL / "cases.json").read_text())


def case_files(case: dict) -> tuple[Path, Path | None]:
    folder = EVAL / "cases" / case["id"]
    main = folder / Path(case["main"]).name
    companion = folder / f"companion-{Path(case['companion']).name}" if case.get("companion") else None
    return main, companion


def parse_case(case: dict) -> ParseResult:
    main, companion = case_files(case)
    return parse_file(main, companion)


def load_gold(case_id: str) -> dict:
    return json.loads((EVAL / "gold" / f"{case_id}.json").read_text())
