"""PR 코멘트: 의존성 파일이 바뀐 PR에 트리아지 보고서를 댓글 하나로 단다 (GitHub Actions, .github/workflows/pr-triage.yml).

  python -m vulnagent.pr_comment                                   # Actions 안에서 (이벤트 파일에서 PR·커밋을 읽음)
  python -m vulnagent.pr_comment --file requirements.txt --base-file old.txt --dry-run out.md   # 로컬 확인

흐름 (파일마다)
  1. 바뀐 의존성 파일 고르기: 이름을 정확히 맞춘다(requirements*.txt, package-lock.json, package.json, pom.xml,
     build.gradle). eval/·tests/는 뺀다 (평가 케이스 20개가 들어 있다). 최대 MAX_FILES개
  2. 기준(base) 버전의 의존성을 데이터 레이어로만 검사 (LLM 없음, 비용 0) -> "이 PR에서 새로 생긴 취약점" 표시
  3. 바뀐(head) 파일로 에이전트 실행. CLI와 같은 제품 설정(검증 루프 + 결정적 계산 + CWE 라벨), 모델은 Haiku 5.5
  4. 마크다운으로 그리고, 숨은 표식이 있는 기존 댓글을 고치거나 새로 단다

신뢰 경계: 의존성 파일과 모델이 쓴 문장은 둘 다 믿지 않는다. 패키지 이름은 코드 스팬에 넣고(@babel/core 같은 npm
scope가 실제 GitHub 사용자를 호출하지 않게), 문장 속 '@'와 표의 '|'·줄바꿈을 무력화한다. 취약점이 있어도 검사를
실패시키지 않는다 (정보 제공용). 포크 PR에는 비밀값이 없어서 API 키 없이 조용히 끝난다.
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable

from .config import PRODUCT_SETTINGS, load_settings
from .depfiles import ParseResult, parse_file
from .ids import ECOSYSTEMS, normalize_package_name, normalize_vuln_id

MARKER = "<!-- vuln-triage-agent -->"
SUPPORTED = re.compile(r"(?:^|/)(requirements[^/]*\.txt|package-lock\.json|package\.json|pom\.xml|build\.gradle)$")
EXCLUDED = ("eval/", "tests/")
MAX_FILES = 3
MAX_BODY = 60000  # GitHub 댓글 한도(65,536자)보다 여유 있게
MAX_ROWS = 15
DEFAULT_MODEL = os.environ.get("VULNAGENT_PR_MODEL", "claude-haiku-5-5")
AGENT_TIMEOUT_S = 600
PRIORITY_KO = {"critical": "긴급", "high": "높음", "medium": "보통", "low": "낮음"}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{2,40}$")
CWE_ID = re.compile(r"^CWE-(\d{1,5})$")


# ------------------------------------------------------------------ 1. 파일 고르기
def select_files(changed: list[str]) -> tuple[list[tuple[str, str | None]], list[str]]:
    """(검사할 (파일, 함께 읽을 파일), 건너뛴 파일). lockfile과 package.json이 같은 폴더에서 함께 바뀌면 lockfile만
    검사하고 package.json을 함께 읽을 파일로 쓴다 (lockfile v1은 직접 의존성을 package.json에서 알아낸다)."""
    wanted = sorted({p for p in changed if SUPPORTED.search(p) and not p.startswith(EXCLUDED)})
    locks = {str(Path(p).parent) for p in wanted if p.endswith("package-lock.json")}
    picked: list[tuple[str, str | None]] = []
    for path in wanted:
        folder = str(Path(path).parent)
        if path.endswith("/package.json") or path == "package.json":
            if folder in locks:
                continue  # lockfile 쪽에서 함께 읽는다
        companion = None
        if path.endswith("package-lock.json"):
            companion = str(Path(folder) / "package.json")
        elif path.endswith("pom.xml") and folder not in (".", ""):
            companion = str(Path(folder).parent / "pom.xml")  # Maven 모듈의 부모 pom (있으면)
        picked.append((path, companion))
    return picked[:MAX_FILES], [p for p, _ in picked[MAX_FILES:]]


# ------------------------------------------------------------------ git
def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def git_show(rev: str, path: str) -> str | None:
    try:
        return git("show", f"{rev}:{path}")
    except subprocess.CalledProcessError:
        return None  # 이 커밋에는 없는 파일 (새로 추가됨 등)


def changed_files(base: str, head: str) -> list[str]:
    return [p for p in git("diff", "--name-only", "--diff-filter=AMR", base, head).splitlines() if p]


def parse_text(path: str, text: str, companion_text: str | None = None) -> ParseResult:
    """parse_file은 파일 이름으로 형식을 고르므로 같은 이름의 임시 파일로 쓴다."""
    with tempfile.TemporaryDirectory() as tmp:
        main = Path(tmp) / Path(path).name
        main.write_text(text, encoding="utf-8")
        comp = None
        if companion_text is not None:
            comp = Path(tmp) / "companion" / Path(path).name.replace("package-lock.json", "package.json")
            comp.parent.mkdir()
            comp.write_text(companion_text, encoding="utf-8")
        return parse_file(main, comp)


# ------------------------------------------------------------------ 2. 기준 버전 (LLM 없음)
def _canon(vuln_id: str) -> str:
    return (normalize_vuln_id(vuln_id) or vuln_id.strip()).upper()


def _pkg_key(label: str) -> str:
    """'PyPI/PyYAML@5.3.1' -> 'pypi/pyyaml' (버전 없이, 이름 정규화)."""
    ecosystem, sep, rest = label.strip().partition("/")
    eco = ECOSYSTEMS.get(ecosystem.lower()) if sep else None
    if eco is None:
        eco, rest = "", label.strip()
    name, at, _version = rest.rpartition("@")
    name = name if at and name else rest
    return f"{eco.lower()}/{normalize_package_name(eco, name).lower() if eco else name.lower()}"


def known_vulns(parsed: ParseResult, check: Callable[[list[dict]], dict]) -> set[tuple[str, str]]:
    """기준 버전에 이미 있던 (패키지, 취약점 id·별칭)."""
    if not parsed.dependencies:
        return set()
    packages = [{"ecosystem": d.ecosystem, "name": d.name, "version": d.version} for d in parsed.dependencies]
    keys = set()
    for start in range(0, len(packages), 200):  # check_packages 한 번에 200개까지
        for res in check(packages[start:start + 200]).get("results", []):
            for v in res.get("vulnerabilities", []):
                for alias in {v["id"], *v.get("cve_ids", []), *v.get("osv_ids", [])}:
                    keys.add((_pkg_key(res["package"]), _canon(alias)))
    return keys


# ------------------------------------------------------------------ 4. 그리기
def _text(s: object) -> str:
    """모델·파일에서 온 문장: '@' 호출과 HTML/표 깨짐을 막는다."""
    s = str(s or "")
    s = s.replace("@", "@\u200b").replace("<", "&lt;").replace(">", "&gt;").replace("![", "!\\[")  # 호출·이미지 삽입 금지
    return re.sub(r"\s+", " ", s).strip()


def _cell(s: object) -> str:
    return _text(s).replace("|", "\\|")


def _code(s: object) -> str:
    s = re.sub(r"\s+", " ", str(s or "")).replace("`", "'").replace("|", "\\|")
    return f"`{s}`" if s else ""


def _vuln_link(vid: str) -> str:
    return f"[{vid}](https://osv.dev/vulnerability/{vid})" if SAFE_ID.match(vid) else _code(vid)


def _cwe_link(cwe: object) -> str:
    m = CWE_ID.match(str(cwe or ""))
    return f"[{m.group(0)}](https://cwe.mitre.org/data/definitions/{m.group(1)}.html)" if m else ""


@dataclass
class FileResult:
    path: str
    report: dict | None = None
    status: str = "ok"
    new_keys: set[tuple[str, str]] | None = None  # None: 기준 버전과 비교하지 못함
    is_new_file: bool = False
    unchecked: list = field(default_factory=list)
    model: str | None = None
    cost_usd: float = 0.0
    latency_s: float = 0.0
    error: str | None = None

    def is_new(self, package: str, vuln_id: str) -> bool | None:
        if self.is_new_file:
            return True
        if self.new_keys is None:
            return None
        return (_pkg_key(package), _canon(vuln_id)) not in self.new_keys


def _vuln_rows(result: FileResult) -> list[dict]:
    rows = []
    for pkg in (result.report or {}).get("packages", []):
        for v in pkg.get("vulnerabilities", []):
            rows.append({"package": pkg.get("package", ""), "id": str(v.get("id", "")), "rank": v.get("rank") or 10**6,
                         "priority": v.get("priority"), "kev": v.get("kev"), "cwe": v.get("cwe"),
                         "new": result.is_new(pkg.get("package", ""), str(v.get("id", "")))})
    return sorted(rows, key=lambda r: r["rank"])


def _table(rows: list[dict], show_new: bool) -> list[str]:
    head = "| 순위 | 패키지 | 취약점 | 우선순위 | KEV | CWE |" + (" 새로 |" if show_new else "")
    out = [head, "|" + "---|" * (7 if show_new else 6)]
    for r in rows:
        out.append(f"| {r['rank'] if r['rank'] < 10**6 else ''} | {_code(r['package'])} | {_vuln_link(r['id'])} | "
                   f"{PRIORITY_KO.get(r['priority'], _cell(r['priority']))} | {'예' if r['kev'] else ''} | {_cwe_link(r['cwe'])} |"
                   + (f" {'🆕' if r['new'] else ''} |" if show_new else ""))
    return out


def render_file(result: FileResult, compact: bool = False) -> str:
    lines = [f"### {_code(result.path)}", ""]
    if result.error:
        lines += [f"검사하지 못했습니다: {_text(result.error)}", ""]
        return "\n".join(lines)
    report = result.report or {}
    if result.status != "ok":
        lines += [f"> 에이전트가 끝내지 못했습니다 (`{result.status}`). 아래는 데이터 레이어 결과만 정리한 것입니다.", ""]
    if report.get("summary"):
        lines += ["> " + _text(report["summary"]), ""]
    rows = _vuln_rows(result)
    packages = report.get("packages", [])
    new_rows = [r for r in rows if r["new"]]
    kev = sum(1 for r in rows if r["kev"])
    stats = [f"취약 패키지 {len(packages)}개", f"취약점 {len(rows)}건"]
    if result.new_keys is not None or result.is_new_file:
        stats.append(f"이 PR에서 새로 생김 **{len(new_rows)}건**")
    stats.append(f"CISA KEV {kev}건")
    lines += ["**" + " · ".join(stats[:2]) + "** · " + " · ".join(stats[2:]), ""]
    if not rows:
        lines += ["알려진 취약점이 없습니다. (OSV에 없다는 뜻이지 안전하다는 보장은 아닙니다)", ""]

    if new_rows and not result.is_new_file:
        lines += ["#### 이 PR에서 새로 생긴 취약점", ""] + _table(new_rows[:MAX_ROWS], show_new=False)
        if len(new_rows) > MAX_ROWS:
            lines.append(f"\n외 {len(new_rows) - MAX_ROWS}건은 아래 전체 목록에 있습니다.")
        lines.append("")

    if packages:
        lines += ["#### 패키지별 조치", "", "| 패키지 | 권장 업그레이드 | 취약점 | 새로 생김 | 이유 |", "|---|---|---|---|---|"]
        for pkg in sorted(packages, key=lambda p: min((v.get("rank") or 10**6 for v in p.get("vulnerabilities", [])), default=10**6)):
            vulns = pkg.get("vulnerabilities", [])
            new = sum(1 for v in vulns if result.is_new(pkg.get("package", ""), str(v.get("id", ""))))
            upgrade = _code(pkg["upgrade_to"]) if pkg.get("upgrade_to") else "없음 (아래 완화책)"
            reason = "" if compact else _cell(pkg.get("reason"))
            reason = reason if len(reason) <= 300 else reason[:299].rstrip("\\") + "…"
            lines.append(f"| {_code(pkg.get('package'))} | {upgrade} | {len(vulns)} | {new or ''} | {reason} |")
        lines.append("")
        workarounds = [p for p in packages if p.get("workaround")]
        if workarounds:
            lines += ["#### 업그레이드 전까지 완화책", ""]
            lines += [f"- {_code(p.get('package'))}: {_text(p['workaround'])}" for p in workarounds]
            lines.append("")

    if rows and not compact:
        lines += [f"<details><summary>전체 취약점 {len(rows)}건 (순위순)</summary>", ""]
        lines += _table(rows, show_new=result.new_keys is not None and not result.is_new_file)
        lines += ["", "</details>", ""]
    unchecked = report.get("unchecked") or result.unchecked
    if unchecked:
        lines += [f"<details><summary>검사하지 못한 항목 {len(unchecked)}개</summary>", ""]
        shown = unchecked if not compact else unchecked[:30]
        lines += [f"- {_code(u.get('spec'))}: {_text(u.get('reason'))}" for u in shown]
        if len(shown) < len(unchecked):
            lines.append(f"- 외 {len(unchecked) - len(shown)}개")
        lines += ["", "</details>", ""]
    if report.get("notes") and not compact:
        lines += ["<details><summary>참고</summary>", ""] + [f"- {_text(n)}" for n in report["notes"]] + ["", "</details>", ""]
    return "\n".join(lines)


def render(results: list[FileResult], skipped: list[str], head_sha: str = "") -> str:
    def build(compact: bool) -> str:
        parts = [MARKER, "## 의존성 취약점 트리아지", ""]
        parts.append(f"바뀐 의존성 파일 {len(results)}개를 검사했습니다."
                     + (f" 건너뜀 (파일 수 제한 {MAX_FILES}개): {', '.join(_code(s) for s in skipped)}" if skipped else ""))
        parts.append("")
        parts += [render_file(r, compact) for r in results]
        cost = sum(r.cost_usd for r in results)
        latency = sum(r.latency_s for r in results)
        models = sorted({r.model for r in results if r.model})
        parts += ["---", f"<sub>vuln-triage-agent · {', '.join(models) or '-'} · ${cost:.4f} · {latency:.0f}초"
                  + (f" · 커밋 {head_sha[:7]}" if head_sha else "")
                  + " · 정보 제공용이며 PR 검사를 실패시키지 않습니다</sub>"]
        return "\n".join(parts)

    body = build(compact=False)
    if len(body) > MAX_BODY:
        body = build(compact=True)  # 전체 목록·이유·참고를 빼고 다시
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY - 200].rsplit("\n", 1)[0] + "\n\n</details>\n\n…(댓글 길이 제한으로 잘렸습니다)"
    return body


# ------------------------------------------------------------------ 3. 에이전트 실행
def triage_one(path: str, head_text: str, base_text: str | None, companion_head: str | None,
               companion_base: str | None, check: Callable[[list[dict]], dict], model: str = DEFAULT_MODEL) -> FileResult:
    from .agent import run_triage
    from .runlog import cost_usd

    result = FileResult(path=path, is_new_file=base_text is None)
    try:
        parsed = parse_text(path, head_text, companion_head)
    except Exception as exc:  # 형식이 깨진 파일: 댓글에 이유를 적고 다음 파일로
        result.error = f"파일을 읽지 못했습니다 ({exc.__class__.__name__}: {exc})"[:300]
        return result
    result.unchecked = [{"spec": u.spec, "reason": u.reason} for u in parsed.unchecked]
    if base_text is not None:
        try:
            result.new_keys = known_vulns(parse_text(path, base_text, companion_base), check)
        except Exception:
            result.new_keys = None  # 비교만 빠지고 보고서는 그대로 낸다
    started = time.monotonic()
    try:
        run = asyncio.run(asyncio.wait_for(run_triage(parsed, Path(path).name, model=model, **PRODUCT_SETTINGS),
                                           timeout=AGENT_TIMEOUT_S))
    except Exception as exc:  # 시간 초과, API 오류: 데이터 레이어 표로 대신한다
        result.status = "timeout" if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) else f"error: {exc.__class__.__name__}"
        result.latency_s = time.monotonic() - started
        result.report = fallback_report(parsed, check)
        return result
    result.latency_s = time.monotonic() - started
    result.status, result.report = run.status, run.report
    result.model = ",".join(sorted(set(run.models_served))) or model
    result.cost_usd = sum(cost_usd(c["usage"], c.get("model")) or 0.0 for c in run.calls)
    if run.status != "ok" or not run.report:
        result.report = fallback_report(parsed, check)
    return result


def fallback_report(parsed: ParseResult, check: Callable[[list[dict]], dict]) -> dict:
    """에이전트가 실패했을 때: 데이터 레이어 결과만으로 표를 만든다 (요약·이유·순위 없음)."""
    packages = []
    if parsed.dependencies:
        deps = [{"ecosystem": d.ecosystem, "name": d.name, "version": d.version} for d in parsed.dependencies]
        for start in range(0, len(deps), 200):
            for res in check(deps[start:start + 200]).get("results", []):
                if res.get("status") == "vulnerable":
                    packages.append({"package": res["package"], "upgrade_to": res.get("safe_upgrade"), "reason": "",
                                     "workaround": None,
                                     "vulnerabilities": [{"id": v["id"], "rank": v.get("policy_rank"), "priority": None,
                                                          "kev": bool(v.get("kev")), "cwe": None}
                                                         for v in res["vulnerabilities"]]})
    return {"summary": "", "packages": packages, "unchecked": [{"spec": u.spec, "reason": u.reason} for u in parsed.unchecked],
            "notes": []}


# ------------------------------------------------------------------ 댓글 올리기
def github_request(method: str, url: str, token: str, body: dict | None = None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "vuln-triage-agent"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read() or b"null")


def upsert_comment(repo: str, pr: int, body: str, token: str, request=github_request) -> str:
    """숨은 표식이 있는 봇 댓글을 찾아 고치고, 없으면 새로 단다. PR 하나에 댓글 하나만 남는다."""
    api = f"https://api.github.com/repos/{repo}"
    page = 1
    while True:
        comments = request("GET", f"{api}/issues/{pr}/comments?per_page=100&page={page}", token)
        for c in comments:
            if MARKER in (c.get("body") or "") and (c.get("user") or {}).get("type") == "Bot":
                request("PATCH", f"{api}/issues/comments/{c['id']}", token, {"body": body})
                return "updated"
        if len(comments) < 100:
            break
        page += 1
    request("POST", f"{api}/issues/{pr}/comments", token, {"body": body})
    return "created"


# ------------------------------------------------------------------ main
def _service_check():
    from .db import apply_schema, connect
    from .service import VulnService

    settings = load_settings()
    conn = connect(settings.database_url)
    apply_schema(conn)
    # 기준 버전 비교와 대체 표도 safe_upgrade·policy_rank가 있는 출력으로
    return VulnService(conn, replace(settings, tool_hints=True)).check_packages


def _write_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m vulnagent.pr_comment")
    ap.add_argument("--base", help="base commit (default: from the pull_request event)")
    ap.add_argument("--head", help="head commit (default: from the pull_request event)")
    ap.add_argument("--file", help="local mode: triage this file instead of reading a PR")
    ap.add_argument("--base-file", help="local mode: the previous version of --file, to mark new vulnerabilities")
    ap.add_argument("--dry-run", metavar="OUT", help="write the comment to OUT instead of posting it")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    args = ap.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        msg = "ANTHROPIC_API_KEY is not set (fork PRs get no secrets, or the repository secret is missing); skipping."
        print(f"::notice::{msg}")
        _write_summary(f"vuln-triage-agent: {msg}")
        return 0

    event = {}
    if os.environ.get("GITHUB_EVENT_PATH") and Path(os.environ["GITHUB_EVENT_PATH"]).exists():
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()).get("pull_request") or {}
    check = _service_check()

    if args.file:
        head_text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        base_text = Path(args.base_file).read_text(encoding="utf-8", errors="replace") if args.base_file else None
        results, skipped, head = [triage_one(args.file, head_text, base_text, None, None, check, args.model)], [], ""
    else:
        base = args.base or (event.get("base") or {}).get("sha")
        head = args.head or (event.get("head") or {}).get("sha")
        if not base or not head:
            print("error: --base/--head or a pull_request event is required", file=sys.stderr)
            return 2
        # PR이 갈라져 나온 지점과 비교한다. base 브랜치에 그 뒤로 들어온 변경은 이 PR의 것이 아니다
        base = git("merge-base", base, head).strip()
        picked, skipped = select_files(changed_files(base, head))
        if not picked:
            print("no supported dependency file changed; nothing to do")
            return 0
        results = []
        for path, companion in picked:
            head_text = git_show(head, path) or ""
            results.append(triage_one(path, head_text, git_show(base, path),
                                      git_show(head, companion) if companion else None,
                                      git_show(base, companion) if companion else None, check, args.model))

    body = render(results, skipped, head or "")
    _write_summary(body.replace(MARKER, ""))
    if args.dry_run:
        Path(args.dry_run).write_text(body, encoding="utf-8")
        print(f"wrote {args.dry_run} ({len(body)} chars)")
        return 0
    repo, number, token = os.environ.get("GITHUB_REPOSITORY"), event.get("number"), os.environ.get("GITHUB_TOKEN")
    if not (repo and number and token):
        print("error: not in a pull_request workflow (GITHUB_REPOSITORY, event number, GITHUB_TOKEN); use --dry-run",
              file=sys.stderr)
        return 2
    print(f"comment {upsert_comment(repo, int(number), body, token)} ({len(body)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
