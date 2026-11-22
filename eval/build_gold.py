"""케이스별 정답(gold)을 코드로 계산한다. LLM은 쓰지 않는다.

정답의 정의: "도구(check_packages)가 돌려주는 사실을 빠짐없이, 지어내지 않고, 정책대로 정리하면
나오는 보고서". 즉 이 평가는 에이전트가 도구 결과를 얼마나 충실하고 정확하게 다루는지를 잰다.

  python eval/build_gold.py              # 온라인: OSV 캐시를 채우며 계산, KEV/EPSS 스냅샷 고정(pinned)
  VULNAGENT_OFFLINE=1 python eval/build_gold.py   # 재계산 (캐시만 사용)

출력: eval/gold/<case_id>.json
"""

import json
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from casefiles import AS_OF, load_cases, parse_case  # noqa: E402

from vulnagent.config import load_settings  # noqa: E402
from vulnagent.db import apply_schema, connect  # noqa: E402
from vulnagent.ids import normalize_package_name  # noqa: E402
from vulnagent.service import VulnService  # noqa: E402
from vulnagent.versions import fix_for_package, min_safe_upgrade, sort_versions  # noqa: E402

GOLD_DIR = Path(__file__).parent / "gold"


def pin_snapshots(conn, as_of: date) -> dict:
    snaps = VulnService(conn, replace(load_settings(), offline=True)).snapshots(as_of)
    conn.execute("UPDATE kev_snapshot SET pinned = true WHERE catalog_version = %s", (snaps["kev_catalog"],))
    conn.execute("UPDATE epss_snapshot SET pinned = true WHERE score_date = %s", (snaps["epss_date"],))
    return snaps


def package_records(conn, osv_ids: list[str]) -> list[dict]:
    rows = conn.execute("SELECT raw FROM osv_vuln WHERE id = ANY(%s) ORDER BY id", (osv_ids,))
    return [r["raw"] for r in rows]


def trim_affected(record: dict, ecosystem: str, matches) -> dict:
    """채점에 필요한 부분(조회한 패키지의 affected 범위)만 남긴다."""
    keep = [
        {"package": a["package"], "ranges": a.get("ranges", []), "versions": a.get("versions", [])}
        for a in record.get("affected", [])
        if a.get("package", {}).get("ecosystem", "").split(":")[0] == ecosystem and matches(a["package"].get("name", ""))
    ]
    return {"id": record["id"], "affected": keep}


def build_case(service: VulnService, case: dict) -> dict:
    parsed = parse_case(case)
    deps = [{"ecosystem": d.ecosystem, "name": d.name, "version": d.version} for d in parsed.dependencies]
    report = service.check_packages(deps) if deps else {"results": [], "as_of": service.snapshots(), "warnings": []}
    vulns, packages = [], []
    for result in report["results"]:
        if result["status"] != "vulnerable":
            continue
        ecosystem, rest = result["package"].split("/", 1)
        name, installed = rest.rsplit("@", 1)
        matches = lambda n, e=ecosystem, want=name: normalize_package_name(e, n) == want
        package_recs = []
        for v in result["vulnerabilities"]:
            records = [trim_affected(r, ecosystem, matches) for r in package_records(service.conn, v["osv_ids"])]
            package_recs += records
            verdicts = [fix_for_package(installed, r, ecosystem, matches) for r in records]
            fixes = [f for s, f in verdicts if s == "fixed"]
            status = "fixed" if fixes else ("no_fix" if any(s == "no_fix" for s, _ in verdicts) else "unknown")
            vulns.append({
                "id": v["id"],
                "aliases": sorted(set(v["cve_ids"]) | set(v["osv_ids"])),
                "package": result["package"],
                "kev": bool(v["kev"]) if v["kev"] is not None else None,
                "epss": v["epss"]["epss"] if v["epss"] else None,
                "fix_status": status,
                "fixed_version": sort_versions(fixes, ecosystem)[-1] if fixes else None,
            })
        packages.append({
            "package": result["package"],
            "ecosystem": ecosystem,
            "name": name,
            "installed": installed,
            "min_safe_upgrade": min_safe_upgrade(installed, ecosystem, package_recs, matches),
            "records": package_recs,
        })
    order = sorted(vulns, key=lambda v: (not v["kev"], -(v["epss"] or -1), v["id"]))
    return {
        "id": case["id"],
        "ecosystem": parsed.ecosystem,
        "as_of": report["as_of"],
        "dependencies_checked": len(deps),
        "unchecked": [u.spec for u in parsed.unchecked],
        "vulns": vulns,
        "packages": packages,
        "expected_order": [v["id"] for v in order],
        "source": {"repo": case["repo"], "commit": case["commit"], "path": case["main"], "companion": case.get("companion")},
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=GOLD_DIR, help="output directory (CI writes to a temp dir and diffs)")
    args = parser.parse_args()
    settings = load_settings()
    conn = connect(settings.database_url)
    apply_schema(conn)
    snaps = pin_snapshots(conn, AS_OF)
    service = VulnService(conn, replace(settings, as_of=AS_OF))
    args.out.mkdir(parents=True, exist_ok=True)
    for case in load_cases():
        gold = build_case(service, case)
        (args.out / f"{case['id']}.json").write_text(json.dumps(gold, indent=1, ensure_ascii=False, default=str))
        kev = sum(1 for v in gold["vulns"] if v["kev"])
        print(f"{case['id']:28s} vulns={len(gold['vulns']):3d} kev={kev} pkgs={len(gold['packages']):2d} "
              f"unchecked={len(gold['unchecked']):3d}", file=sys.stderr)
    print(f"pinned snapshots: {snaps}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
