"""사람용 CLI. MCP 서버와 같은 VulnService를 쓴다.

  python -m vulnagent init-db
  python -m vulnagent sync [--force]           # KEV/EPSS 스냅샷 받기 (cron으로 하루 1회 돌리면 됨)
  python -m vulnagent check PyPI/jinja2@2.10 npm/lodash@4.17.15
  python -m vulnagent show CVE-2021-44228
  python -m vulnagent status
  python -m vulnagent triage requirements.txt  # 에이전트 실행 (Claude API 호출). CWE·완화책 포함, --no-cwe로 끔
  python -m vulnagent extract report.pdf --llm --triage
  python -m vulnagent runs                     # 실행 기록 요약 (비용·지연·교정·경고)
"""

import argparse
import json
import logging
import sys
import time
from datetime import date
from pathlib import Path

from .config import PRODUCT_SETTINGS, load_settings
from .db import apply_schema, connect
from .errors import InvalidInput, SourceError
from .runlog import log_extract, log_triage, summarize
from .service import VulnService


def parse_package(spec: str) -> dict:
    """'PyPI/jinja2@2.10' -> {ecosystem, name, version}. Maven 이름의 ':'와 npm scope의 '@'를 고려해
    생태계는 첫 '/' 앞, 버전은 마지막 '@' 뒤로 자른다."""
    ecosystem, sep, rest = spec.partition("/")
    name, at, version = rest.rpartition("@")
    if not sep or not at or not name:
        raise InvalidInput(f"Expected ECOSYSTEM/NAME@VERSION, got {spec!r}")
    return {"ecosystem": ecosystem, "name": name, "version": version}


DEFAULT_CWE = PRODUCT_SETTINGS["cwe"]


def _warn_if_no_cwe_catalog() -> None:
    """CWE 라벨은 OSV/NVD 데이터만으로 붙지만, 이름과 완화책 조회(get_weakness)에는 CWE 카탈로그가 DB에 있어야 한다."""
    try:
        with connect(load_settings().database_url) as conn:
            loaded = conn.execute("SELECT to_regclass('cwe_entry') IS NOT NULL AS t").fetchone()["t"] and \
                conn.execute("SELECT EXISTS (SELECT 1 FROM cwe_entry) AS ok").fetchone()["ok"]
    except Exception:  # DB에 못 붙으면 MCP 서버가 더 분명한 오류를 낸다
        return
    if not loaded:
        print("WARNING: CWE catalog is not loaded (python -m vulnagent.kb.cwe, needs pgvector). CWE ids still come "
              "from GHSA/NVD, but names and knowledge-base mitigations are unavailable. Use --no-cwe to skip CWE.",
              file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnagent")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    p_sync = sub.add_parser("sync")
    p_sync.add_argument("--force", action="store_true")
    p_check = sub.add_parser("check")
    p_check.add_argument("packages", nargs="+")
    p_check.add_argument("--as-of", type=date.fromisoformat)
    p_show = sub.add_parser("show")
    p_show.add_argument("vuln_id")
    p_show.add_argument("--as-of", type=date.fromisoformat)
    sub.add_parser("status")
    p_triage = sub.add_parser("triage", help="run the triage agent on a dependency file (calls the Claude API)")
    p_triage.add_argument("file")
    p_triage.add_argument("--companion", help="package.json for lockfile v1, or the parent pom.xml")
    p_triage.add_argument("--model", default="claude-opus-5-5")
    p_triage.add_argument("--effort", default="medium")
    p_triage.add_argument("--context", help="deployment context, e.g. 'internet-facing API'")
    # 3주차 결과(v4)를 기본값으로: 보고서 검증 루프 + 도구의 결정적 계산. 비교 실험용으로 끌 수 있다.
    p_triage.add_argument("--no-validate", action="store_true", help="disable the report validation loop (v3)")
    p_triage.add_argument("--no-tool-hints", action="store_true", help="disable safe_upgrade/policy_rank hints (v4)")
    # 8주차 결과: CWE는 GHSA/NVD가 이미 붙인 라벨을 넘겨주는 방식(정답률 100%)을 기본으로. 검색 후보에서 고르기(44%)나
    # 기억(64%)보다 정확하고, 완화책은 security-kb의 get_weakness로 MITRE 완화책을 조회해 근거를 댄다.
    p_triage.add_argument("--no-cwe", action="store_true", help="leave out CWE ids and workarounds (week 8)")
    p_extract = sub.add_parser("extract", help="extract findings from a vulnerability report (PDF/DOCX/XLSX)")
    p_extract.add_argument("file")
    p_extract.add_argument("--llm", action="store_true", help="use Claude to read the document (needed for scans)")
    p_extract.add_argument("--model", default="claude-haiku-5-5")
    p_extract.add_argument("--triage", action="store_true", help="then run the triage agent on the extracted packages")
    # 5주차 결과: 문서 속 인젝션 방어 두 가지를 기본으로 켠다 (프롬프트 강화 + 결정적 교차 검증)
    p_extract.add_argument("--no-defense", action="store_true", help="disable injection defenses (for experiments)")
    sub.add_parser("runs", help="summarize the run log (cost, latency, corrections, injection warnings)")
    args = parser.parse_args(argv)

    if args.cmd == "runs":
        print(json.dumps(summarize(), indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "extract":
        import asyncio

        from .agent import run_triage
        from .docs.extract import cross_check, extract_deterministic, extract_llm, to_parse_result

        logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
        started = time.monotonic()
        deterministic = extract_deterministic(args.file)
        if args.llm:
            extraction = extract_llm(args.file, model=args.model, hardened=not args.no_defense)
            if not args.no_defense:
                extraction = cross_check(extraction, deterministic)
            for warning in extraction.suspected_injections + extraction.alerts:
                print(f"WARNING: {warning}", file=sys.stderr)
        else:
            extraction = deterministic
        log_extract(extraction, Path(args.file).name, time.monotonic() - started, defended=not args.no_defense)
        if not args.triage:
            print(json.dumps(extraction.to_dict(), indent=2, ensure_ascii=False))
            return 0
        parsed = to_parse_result(extraction, Path(args.file).name)
        started = time.monotonic()
        _warn_if_no_cwe_catalog()
        run = asyncio.run(run_triage(parsed, Path(args.file).name, validate=True, tool_hints=True, cwe=DEFAULT_CWE))
        log_triage(run, Path(args.file).name, time.monotonic() - started, source="extract")
        print(json.dumps(run.report, indent=2, ensure_ascii=False) if run.report else f"agent stopped: {run.status}")
        return 0 if run.status == "ok" else 1

    if args.cmd == "triage":
        import asyncio

        from .agent import triage_file

        logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
        if not args.no_cwe:
            _warn_if_no_cwe_catalog()
        started = time.monotonic()
        _parsed, run = asyncio.run(triage_file(args.file, args.companion, model=args.model, effort=args.effort,
                                               context=args.context, validate=not args.no_validate,
                                               tool_hints=not args.no_tool_hints, cwe=None if args.no_cwe else DEFAULT_CWE))
        log_triage(run, Path(args.file).name, time.monotonic() - started)
        print(json.dumps(run.report, indent=2, ensure_ascii=False) if run.report else f"agent stopped: {run.status}")
        print(f"status={run.status} turns={len(run.calls)} tools={len(run.tool_calls)} corrections={run.corrections} "
              f"models={sorted(set(run.models_served))} usage={run.usage_total()}", file=sys.stderr)
        return 0 if run.status == "ok" else 1

    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")
    settings = load_settings()
    conn = connect(settings.database_url)
    apply_schema(conn)
    service = VulnService(conn, settings)

    try:
        if args.cmd == "init-db":
            result = {"ok": True}
        elif args.cmd == "sync":
            result = service.sync_bulk(force=args.force)
        elif args.cmd == "check":
            result = service.check_packages([parse_package(s) for s in args.packages], args.as_of)
        elif args.cmd == "show":
            result = service.get_vulnerability(args.vuln_id, args.as_of)
        else:
            result = service.status()
    except (InvalidInput, SourceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
