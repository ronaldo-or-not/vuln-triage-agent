"""보고서 서술(summary / reason / notes)의 사실 정확성 채점 (7주차). 코드만 쓰고 비용은 0이다.

기존 채점기(grade.py)는 보고서의 구조화된 필드(ID, 업그레이드 버전, 순위)만 본다. 그런데 사람이 실제로 읽는
요약문은 아무도 검사하지 않았고, v4 보고서 60개 중 20개에서 요약의 개수가 틀려 있었다
("의존성 44개" → 실제 43개, "12개 패키지 20건" → 실제 8개 19건).

입력: 최종 보고서, 그 실행에서 받은 check_packages 결과, 에이전트에 준 입력(payload). 정답 파일은 쓰지 않는다.
개수는 언제나 results에서 직접 센다. v5부터 도구가 주는 `counts` 필드는 읽지 않는다 (채점기가 도구를 믿으면
도구의 개수 버그를 못 잡는다).
지표 (모두 0/1, 첫 번째가 대표 지표):
  prose_ok        아래 다섯이 모두 1
  counts_ok       요약의 개수 표현(N개 / N건)이 이번 실행의 사실 중 하나와 맞다.
                  "약 / 여 / 이상 / 가량"이 붙은 근사 표현은 ±10%(최소 ±2) 안이면 맞다고 본다
  ids_grounded    서술에 나온 취약점 ID(CVE / GHSA / PYSEC)가 모두 이번 실행의 도구 결과에 있다
  kev_consistent  "KEV 항목은 없다"류 주장이 도구 결과와 모순되지 않는다 (요약·메모는 전체 기준, reason은 그 패키지 기준)
  top1_named      취약점이 있으면 요약이 정책 1순위 취약점의 ID나 패키지 이름을 언급한다
  korean_only     서술에 가나·한자가 섞이지 않았다

알려진 한계: counts_ok는 숫자가 사실 집합의 "어느 하나"와 맞으면 통과시킨다. 숫자를 엉뚱한 대상에 붙인 경우
(취약 패키지가 7개인데 "취약점 7건")는 놓친다. 사람 라벨과 대조해 재현율을 따로 잰다.
"""

import json
import re
from pathlib import Path

# \b를 쓰면 "CVE-2021-44228은"처럼 한글 조사가 붙은 ID를 놓친다 (한글도 단어 문자라서). ASCII 기준으로 경계를 잡는다
ID_RE = re.compile(r"(?<![0-9A-Za-z-])(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+)(?![0-9A-Za-z])", re.I)
# "44개", "20건", "60여 개", "6개 이상", "약 90개", "~100건"
# 천 단위 쉼표("1,479개")도 한 숫자로 읽는다. 쉼표 뒤만 잘라 479로 읽은 오탐이 실제로 있었다
COUNT_RE = re.compile(r"(?P<pre>(?:약|대략|~)\s*)?(?<![\d.,])(?P<n>\d{1,3}(?:,\d{3})+|\d{1,5})\s*(?P<yeo>여\s*)?(?:개|건)(?P<post>\s*(?:이상|가량|정도))?")
KEV_NONE_RE = re.compile(r"KEV[^.。]{0,25}(항목은|취약점은|등재된 (취약점|항목)은|등록 항목은|등재 항목은)[^.。]{0,10}없")
FOREIGN_RE = re.compile(r"[぀-ヿ一-鿿]")
METRICS = ["prose_ok", "counts_ok", "ids_grounded", "kev_consistent", "top1_named", "korean_only"]


def load_trace(path: Path) -> tuple[dict, dict, dict]:
    """대화 기록에서 (입력 payload, check_packages 결과, 최종 보고서)를 꺼낸다."""
    trace = json.loads(Path(path).read_text())
    user = next(t for t in trace if t["role"] == "user")["content"]
    payload = json.loads(user.split("```json\n", 1)[1].split("\n```", 1)[0])
    results = [json.loads(t["content"]) for t in trace if t["role"] == "tool_result"]
    check = next((r for r in results if isinstance(r, dict) and "results" in r), {"results": []})
    report = json.loads([t for t in trace if t["role"] == "assistant"][-1]["content"])
    return payload, check, report


def facts(payload: dict, check: dict, report: dict) -> dict:
    """서술이 말할 수 있는 개수들. 라벨링 파일의 사실표도 이것으로 만든다."""
    vulnerable = [r for r in check["results"] if r.get("status") == "vulnerable"]
    vulns = [(r["package"], v) for r in vulnerable for v in r["vulnerabilities"]]
    top = min(vulns, key=lambda pv: pv[1].get("policy_rank") or 1e9) if vulns else None
    return {
        "dependencies": len(payload["dependencies"]),
        "unchecked": len(payload["unchecked"]),
        "dependencies_plus_unchecked": len(payload["dependencies"]) + len(payload["unchecked"]),
        "vulnerable_packages": len(vulnerable),
        "no_known_vuln_packages": len(check["results"]) - len(vulnerable),
        "vulnerabilities": len(vulns),
        "kev_vulnerabilities": sum(1 for _, v in vulns if v.get("kev")),
        # 같은 취약점이 두 패키지에 걸리면 고유 개수가 합계보다 작다 (benchmark-java: 28건, 고유 27건)
        "unique_vulnerabilities": len({v["id"] for _, v in vulns}),
        "unique_kev_vulnerabilities": len({v["id"] for _, v in vulns if v.get("kev")}),
        "per_package": {r["package"]: len(r["vulnerabilities"]) for r in vulnerable},
        # "log4j-core: 9개 취약점, KEV 2건"처럼 패키지별 KEV 개수도 쓴다 (v5에서 오탐으로 발견)
        "per_package_kev": {r["package"]: sum(1 for v in r["vulnerabilities"] if v.get("kev")) for r in vulnerable},
        "report_packages": len(report["packages"]),
        "report_vulnerabilities": sum(len(p["vulnerabilities"]) for p in report["packages"]),
        # "1479 packages in total" 같은 패키지 수만. 버전 문자열(2.6.3)의 숫자까지 넣으면 작은 수가 모두 통과한다
        "parser_note_numbers": sorted({int(n) for n in re.findall(r"(\d+)\s*packages", " ".join(payload.get("parser_notes", [])))}),
        "top1": {"package": top[0], "id": top[1]["id"]} if top else None,
    }


def _allowed_numbers(f: dict) -> set[int]:
    nums = {v for k, v in f.items() if isinstance(v, int)}
    return nums | set(f["per_package"].values()) | set(f["per_package_kev"].values()) | set(f["parser_note_numbers"])


def _allowed_by_category(f: dict) -> dict[str, set[int]]:
    """숫자가 가리키는 대상별 허용 값. 대상을 알 수 없으면 전체(any)와 비교한다."""
    vuln = {f["vulnerabilities"], f["report_vulnerabilities"], f["kev_vulnerabilities"], f["unique_vulnerabilities"],
            f["unique_kev_vulnerabilities"], *f["per_package"].values(), *f["per_package_kev"].values()}
    pkg = {f[k] for k in ("dependencies", "unchecked", "dependencies_plus_unchecked", "vulnerable_packages",
                          "no_known_vuln_packages", "report_packages")} | set(f["parser_note_numbers"])
    vulnerable = {f["vulnerable_packages"], f["report_packages"]}
    return {"vuln": vuln, "vulnerable_pkg": vulnerable, "pkg": pkg, "any": _allowed_numbers(f)}


# "4개에서 취약점이", "4개 패키지에서" -> 취약점이 나온 패키지 수
VULNERABLE_PKG_AFTER = re.compile(r"\s*(의\s*)?(패키지\s*)?에서")
# "13개 중", "4개 패키지", "9개 의존성" -> 패키지/의존성 수
PKG_AFTER = re.compile(r"\s*(중|의\s*(직접\s*)?(패키지|의존성|항목)|(직접\s*)?(패키지|의존성|항목|라이브러리|dependenc|direct))")
VULN_AFTER = re.compile(r"\s*(의\s*)?(고유\s*)?취약점")
VULN_BEFORE = re.compile(r"취약점\s*(총\s*)?(약\s*)?$")
UNCHECKED_BEFORE = re.compile(r"(검사\s*불가|검사하지\s*못한|확인하지\s*못한|확인\s*불가|미확인)[^.。]{0,10}$")
PKG_BEFORE = re.compile(r"(의존성|패키지|dependency|dependencies|항목)\s*(총\s*)?(약\s*)?$")


def claim_category(summary: str, start: int, end: int) -> str:
    """요약문 속 개수 표현이 무엇을 센 것인지 주변 낱말로 추정한다: vuln / vulnerable_pkg / pkg / any(모름).

    순서가 중요하다: "건"은 거의 언제나 취약점을 센다 ("취약점 총 37건 중"의 "중"보다 우선).
    """
    tail = summary[end:end + 16]
    unit = re.match(r"\s*(여\s*)?(개|건)", tail)
    rest = re.sub(r"^\s*(이상|가량|정도)", "", tail[unit.end():]) if unit else tail
    before = summary[max(0, start - 12):start]
    if UNCHECKED_BEFORE.search(before):  # "검사하지 못한 항목은 95건" -> 검사 못 한 항목 수 (v5에서 오탐으로 발견)
        return "pkg"
    if (unit and unit.group(2) == "건") or VULN_BEFORE.search(before):
        return "vuln"
    if re.search(r"나머지\s*(약\s*)?$", before):  # "나머지 9개 패키지에서는 (취약점이 없었다)" -> 취약 패키지가 아님
        return "pkg"
    if VULNERABLE_PKG_AFTER.match(rest):
        return "vulnerable_pkg"
    if PKG_AFTER.match(rest):
        return "pkg"
    if VULN_AFTER.match(rest):
        return "vuln"
    if PKG_BEFORE.search(before):
        return "pkg"
    return "any"


def count_claims(summary: str) -> list[dict]:
    out = []
    for m in COUNT_RE.finditer(summary):
        post = (m.group("post") or "").strip()
        out.append({"n": int(m.group("n").replace(",", "")), "approx": bool(m.group("pre") or m.group("yeo") or post),
                    "at_least": post == "이상", "text": summary[max(0, m.start() - 12): m.end() + 8],
                    "span": (m.start("n"), m.end("n")), "category": claim_category(summary, m.start("n"), m.end("n"))})
    return out


def _claim_ok(c: dict, allowed: set[int]) -> bool:
    n = c["n"]
    if n <= 1 or n in allowed:
        return True
    if c["approx"]:  # ±10%(최소 ±2), "이상"이면 실제 값이 그 이상이어야 한다
        return any(abs(n - a) <= max(2, 0.1 * a) and (not c["at_least"] or a >= n) for a in allowed)
    return False


def grade_prose(payload: dict, check: dict, report: dict) -> tuple[dict, dict]:
    f = facts(payload, check, report)
    summary, notes = report["summary"], " ".join(report["notes"])
    reasons = {p["package"]: p["reason"] for p in report["packages"]}
    everything = " ".join([summary, notes, *reasons.values()])
    why: dict[str, str] = {}

    allowed = _allowed_by_category(f)
    wrong = [f"{c['text']} [{c['category']}]" for c in count_claims(summary) if not _claim_ok(c, allowed[c["category"]])]
    if wrong:
        why["counts_ok"] = "facts: " + json.dumps({k: f[k] for k in ("dependencies", "unchecked", "vulnerable_packages",
                                                                   "vulnerabilities")}) + " | claims: " + " / ".join(wrong)

    known = set()
    for r in check["results"]:
        for v in r.get("vulnerabilities", []):
            known |= {v["id"].upper(), *(i.upper() for i in v.get("cve_ids", [])), *(i.upper() for i in v.get("osv_ids", []))}
    unknown = sorted({m.upper() for m in ID_RE.findall(everything)} - known)
    if unknown:
        why["ids_grounded"] = "not in tool output: " + ", ".join(unknown[:5])

    kev_pkgs = {r["package"] for r in check["results"] for v in r.get("vulnerabilities", []) if v.get("kev")}
    contradictions = []
    if kev_pkgs and KEV_NONE_RE.search(summary + " " + notes):
        contradictions.append("summary/notes say no KEV")
    contradictions += [f"{pkg} reason says no KEV" for pkg, text in reasons.items() if pkg in kev_pkgs and KEV_NONE_RE.search(text)]
    if contradictions:
        why["kev_consistent"] = "; ".join(contradictions)

    if f["top1"]:
        top = f["top1"]
        short = top["package"].split("/", 1)[1].rsplit("@", 1)[0].split(":")[-1]
        names = {top["id"]} | {v for r in check["results"] for x in r.get("vulnerabilities", []) if x["id"] == top["id"]
                                for v in [*x.get("cve_ids", []), *x.get("osv_ids", [])]}
        # "Apache Struts2 2.3.20"도 struts2-core를 가리킨다: -core / -api 같은 접미사를 뗀 이름도 인정 (v5에서 오탐으로 발견)
        stem = re.sub(r"-(core|api|common|starter|lib|java)$", "", short.lower())
        if not any(n in summary for n in names) and short.lower() not in summary.lower() and stem not in summary.lower():
            why["top1_named"] = f"summary does not mention rank-1 {top['id']} ({short})"

    foreign = FOREIGN_RE.findall(everything)
    if foreign:
        why["korean_only"] = "foreign script: " + "".join(foreign[:10])

    scores = {m: int(m not in why) for m in METRICS[1:]}
    scores = {"prose_ok": int(all(scores.values())), **scores}
    return scores, why
