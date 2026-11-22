"""cases.json의 공개 저장소 파일을 커밋 고정 URL로 내려받는다 (재현 가능).

  python eval/fetch_cases.py            # eval/cases/<id>/ 에 저장, 이미 있으면 건너뜀
"""

import json
import sys
import urllib.request
from pathlib import Path

EVAL = Path(__file__).parent
RAW = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-triage-agent/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def main() -> int:
    cases = json.loads((EVAL / "cases.json").read_text())
    for case in cases:
        out = EVAL / "cases" / case["id"]
        out.mkdir(parents=True, exist_ok=True)
        for role in ("main", "companion"):
            path = case.get(role)
            if not path:
                continue
            # companion(부모 pom 등)은 이름이 겹치지 않게 접두어를 붙인다
            target = out / (Path(path).name if role == "main" else f"companion-{Path(path).name}")
            if target.exists():
                continue
            target.write_bytes(fetch(RAW.format(repo=case["repo"], commit=case["commit"], path=path)))
            print(f"fetched {case['id']}/{target.name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
