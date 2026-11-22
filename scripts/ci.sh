#!/bin/bash
# CI와 같은 검사를 로컬·서버에서도 그대로 돌린다 (API 비용 0).
#   TEST_DATABASE_URL : 테스트용 빈 DB (이름이 _test로 끝나야 함)
#   CI_DATABASE_URL   : 재현성 검사용 빈 DB (없으면 그 검사만 건너뜀)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-.venv/bin/python}
echo "== unit / integration tests"
$PY -m pytest -q -p no:cacheprovider
echo "== evaluation regression checks"
$PY eval/ci_checks.py
