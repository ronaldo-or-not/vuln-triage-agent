#!/bin/bash
# 평가 데이터 스냅샷 왕복 검사: 내보내기 -> 빈 DB에 적재 -> 정답 오프라인 재계산 -> 커밋된 정답과 비교
set -euo pipefail
cd "$(dirname "$0")/.."
PG=.tools/pg/bin
SOCK="$PWD/.pgsock"
python=.venv/bin/python
DATABASE_URL="postgresql:///vulnagent?host=$SOCK" $python eval/snapshot.py export
$PG/dropdb -h "$SOCK" --if-exists vulnagent_snap
$PG/createdb -h "$SOCK" vulnagent_snap
DATABASE_URL="postgresql:///vulnagent_snap?host=$SOCK" $python eval/snapshot.py load
OUT=$(mktemp -d)
DATABASE_URL="postgresql:///vulnagent_snap?host=$SOCK" VULNAGENT_OFFLINE=1 $python eval/build_gold.py --out "$OUT" 2>/dev/null
$python - "$OUT" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1]); diffs = 0
for g in sorted(Path("eval/gold").glob("*.json")):
    a, b = json.loads(g.read_text()), json.loads((out / g.name).read_text())
    if a != b:
        diffs += 1
        keys = [k for k in a if a.get(k) != b.get(k)]
        print("DIFF", g.name, keys)
print(f"gold files compared: {len(list(Path('eval/gold').glob('*.json')))}, differences: {diffs}")
PY
du -sh eval/snapshot
