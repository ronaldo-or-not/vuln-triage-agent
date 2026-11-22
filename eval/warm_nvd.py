"""정답에 나온 CVE의 NVD 상세를 미리 캐시한다 (평가는 오프라인으로 돌기 때문).

NVD 한도(키 없이 30초 5회) 때문에 수백 건이면 수십 분 걸린다. 이미 캐시된 것은 건너뛴다.
  nohup python eval/warm_nvd.py > eval/warm_nvd.log 2>&1 &
"""

import json
import sys
from pathlib import Path

from vulnagent.config import load_settings
from vulnagent.db import connect
from vulnagent.http import make_client
from vulnagent.ids import normalize_cve
from vulnagent.sources import nvd


def main() -> int:
    settings = load_settings()
    conn = connect(settings.database_url)
    cves = sorted({
        cve for path in (Path(__file__).parent / "gold").glob("*.json")
        for v in json.loads(path.read_text())["vulns"] for cve in [v["id"], *v["aliases"]] if normalize_cve(cve)
    })
    cached = {r["cve_id"] for r in conn.execute("SELECT cve_id FROM nvd_cve WHERE cve_id = ANY(%s)", (cves,))}
    todo = [c for c in cves if c not in cached]
    print(f"{len(cves)} CVEs, {len(cached)} cached, fetching {len(todo)}", flush=True)
    limiter = nvd.make_limiter(settings.nvd_api_key)
    with make_client(settings.user_agent) as client:
        for i, cve in enumerate(todo, 1):
            try:
                nvd.store(conn, cve, nvd.fetch_cve(client, limiter, settings.nvd_api_key, cve))
            except Exception as exc:  # 하나 실패해도 계속 (나중에 다시 돌리면 남은 것만 받음)
                print(f"{cve}: {exc}", flush=True)
            if i % 25 == 0:
                print(f"{i}/{len(todo)}", flush=True)
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
