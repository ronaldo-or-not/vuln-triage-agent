"""CI 회귀 검사 (API 비용 0). 하나라도 실패하면 종료 코드 1.

1. 채점기 자체 점검: 정답 보고서 20/20, 빈 보고서 2개 이하 통과 (채점기가 너무 관대해지거나 깨지지 않았는지)
2. 문서 추출(결정적) 기준선: 전체 재현율 >= 0.79, 정밀도 1.0, 무관 CVE 오추출 0 (4주차 기준)
3. 인젝션 방어 D2의 전제: 결정적 추출기는 공격 문서(스캔 제외)에서 표적을 절대 빼지 않는다
4. 데이터 레이어 재현성 (CI_DATABASE_URL이 있을 때): 평가 스냅샷을 빈 DB에 넣고 정답을 오프라인으로
   다시 계산하면 커밋된 eval/gold와 완전히 같아야 한다. OSV/KEV/EPSS 처리, 버전 계산, 정답 생성 중 어디가
   바뀌어도 여기서 잡힌다.
5. 서술 채점기 변이 테스트 (7주차): 일부러 틀리게 만든 요약문을 잡아내는 비율. 사실표에 없는 값 100%,
   맞는 근사 표현은 100% 통과(오탐 0), 대상을 엉뚱하게 쓴 값 >= 50%, 범위 밖 근사 >= 70%

  python eval/ci_checks.py
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

EVAL = Path(__file__).parent
ROOT = EVAL.parent
PY = sys.executable
failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    if not ok:
        failures.append(name)


def run(args: list[str], env: dict | None = None) -> None:
    proc = subprocess.run([PY, *args], cwd=ROOT, env={**os.environ, **(env or {})}, capture_output=True, text=True)
    if proc.returncode != 0:  # CI 로그에서 바로 원인을 볼 수 있게 출력 끝부분을 보여 준다
        print(f"command failed ({proc.returncode}): {' '.join(args)}\n{proc.stdout[-2000:]}{proc.stderr[-4000:]}")
        raise SystemExit(1)


def grader_selfcheck() -> None:
    for kind, test in (("oracle", lambda p, n: p == n), ("null", lambda p, n: p <= 2)):
        run(["eval/run_eval.py", "--fake", kind])
        rows = [json.loads(l) for l in (EVAL / "selfcheck" / kind / "results.jsonl").read_text().splitlines()]
        passes = sum(r["grade"]["pass"] for r in rows)
        check(f"grader {kind}", test(passes, len(rows)), f"{passes}/{len(rows)} pass")


def docs_baseline() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        run(["eval/docs_eval.py", "--results-dir", tmp])
        rows = [json.loads(l) for l in (Path(tmp) / "deterministic.jsonl").read_text().splitlines()]
    tp, fp, fn = (sum(r[k] for r in rows) for k in ("tp", "fp", "fn"))
    recall, precision = tp / (tp + fn), tp / max(tp + fp, 1)
    distractors = sum(r["distractor_fp"] for r in rows)
    check("docs deterministic", recall >= 0.79 and precision == 1.0 and distractors == 0,
          f"recall {recall:.3f}, precision {precision:.3f}, distractor FP {distractors} (n={len(rows)})")


def injection_premise() -> None:
    sys.path.insert(0, str(EVAL))
    import injection_eval as ie

    from vulnagent.docs.extract import extract_deterministic

    worked = total = 0
    for g in sorted((EVAL / "injection" / "gold").glob("*.json")):
        truth = json.loads(g.read_text())
        if truth["layout"] == "pdf_scan":
            continue
        total += 1
        worked += ie.score(extract_deterministic(EVAL / "injection" / "files" / truth["doc"]), truth)["success"]
    check("injection: deterministic ignores injected text", worked == 0, f"attack success {worked}/{total}")


def prose_grader_mutations() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "mutation.json"
        run(["eval/prose/mutation_test.py", "--json", str(out)])
        types = json.loads(out.read_text())["types"]
    rate = {k: v["rate"] for k, v in types.items()}
    ok = rate["unseen"] == 1.0 and rate["approx_in"] == 1.0 and rate["collides"] >= 0.5 and rate["approx_out"] >= 0.7
    check("prose grader mutations", ok, ", ".join(f"{k} {v:.3f}" for k, v in rate.items()))


def data_reproducibility() -> None:
    url = os.environ.get("CI_DATABASE_URL")
    if not url:
        print("[SKIP] data reproducibility: set CI_DATABASE_URL to an empty database")
        return
    with tempfile.TemporaryDirectory() as tmp:
        run(["eval/snapshot.py", "load"], {"DATABASE_URL": url})
        run(["eval/build_gold.py", "--out", tmp], {"DATABASE_URL": url, "VULNAGENT_OFFLINE": "1"})
        diffs = [g.name for g in sorted((EVAL / "gold").glob("*.json"))
                 if json.loads(g.read_text()) != json.loads((Path(tmp) / g.name).read_text())]
    check("data reproducibility", not diffs, f"{len(list((EVAL / 'gold').glob('*.json')))} gold files, differences: {diffs or 0}")


if __name__ == "__main__":
    grader_selfcheck()
    docs_baseline()
    injection_premise()
    prose_grader_mutations()
    data_reproducibility()
    print(f"\n{'ALL CHECKS PASSED' if not failures else 'FAILED: ' + ', '.join(failures)}")
    sys.exit(1 if failures else 0)
