"""8주차 CWE·완화책 채점기 (전부 결정적 코드, LLM 판정 없음, 비용 0).

정답: eval/cwe/labels.json (GHSA ∪ NVD 라벨, 카탈로그에 있는 것만). 근거: 그 실행의 대화 기록(trace).

취약점 단위 (정답 취약점마다 하나씩 센다. 보고서에서 빠진 취약점은 오답)
- cwe_hit       : 보고한 cwe가 정답 라벨 중 하나 (라벨이 카탈로그에 없는 취약점은 세지 않음)
- cwe_answered  : cwe를 null이 아니게 채움
- cwe_valid     : 채운 cwe가 CWE-<숫자> 형식이고 카탈로그에 있음 (없는 번호를 지어내지 않음)
- cwe_grounded  : 채운 cwe가 이번 실행의 도구 결과 어딘가에 나왔음 (기억에서 꺼낸 것인지 구분)

패키지 단위 (업그레이드로 다 못 고치는 패키지만: 모든 취약점을 벗어나는 단일 업그레이드가 없음)
- wa_present    : workaround를 썼음
- wa_relevant   : workaround가 인용한 CWE 중 하나가 그 패키지 취약점들의 정답 라벨에 있음
- wa_grounded   : workaround가 인용한 CWE 중 하나를 이번 실행에서 get_weakness로 조회했음 (지식베이스 근거)
그 밖의 패키지에 쓴 workaround 수(wa_extra)는 지시 준수 참고용으로만 센다.
"""

import json
import re
from collections import deque
from pathlib import Path

from grade import _canon, _pkg_name

HERE = Path(__file__).resolve().parent
CWE_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)
CWE_FORM = re.compile(r"^CWE-\d+$")


def load_reference() -> tuple[dict[str, set[str]], dict[str, str]]:
    """(취약점 id -> 카탈로그에 있는 정답 라벨, 카탈로그 id -> 이름)."""
    catalog = json.loads((HERE / "cwe" / "catalog.json").read_text())["names"]
    raw = json.loads((HERE / "cwe" / "labels.json").read_text())["labels"]
    labels = {vid: {c for c in v["ghsa"] + v["nvd"] if c in catalog} for vid, v in raw.items()}
    return labels, catalog


def tool_evidence(trace: list[dict]) -> tuple[set[str], set[str]]:
    """(도구 결과 어디든 나온 CWE id, get_weakness가 돌려준 CWE id).

    병렬 호출이면 trace에 tool_call들이 먼저 쌓이고 tool_result가 같은 순서로 이어진다.
    """
    anywhere, detailed = set(), set()
    pending: deque[str] = deque()
    for t in trace:
        if t["role"] == "tool_call":
            pending.append(t["name"])
        elif t["role"] == "tool_result":
            name = pending.popleft() if pending else ""
            found = {f"CWE-{n}" for n in CWE_RE.findall(t["content"])}
            anywhere |= found
            if name == "get_weakness":
                try:
                    detailed.add(json.loads(t["content"])["cwe_id"])
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass  # 오류 결과 (없는 id 등)
    return anywhere, detailed


def needs_workaround(gold: dict) -> set[str]:
    """업그레이드 하나로 모든 취약점을 벗어날 수 없는 패키지 (정답의 min_safe_upgrade가 없음).

    처음에는 '수정 버전 없는 취약점이 있는 패키지'도 넣었는데(14개), 파일럿에서 틀린 정의로 드러났다.
    spring-context 3.2.6의 CVE-2024-38820은 5.3.x 줄에 수정이 없을 뿐이고(last_affected 5.3.40),
    6.1.20으로 올리면 벗어난다. 에이전트가 workaround를 쓰지 않은 것이 맞았다. 지금 정의로는 7개.
    """
    eco = gold["ecosystem"]
    return {_pkg_name(p["package"], eco) for p in gold["packages"] if p["min_safe_upgrade"] is None}


def grade_cwe(report: dict, trace: list[dict], gold: dict, labels: dict[str, set[str]], catalog: dict) -> dict:
    """반환: 개수 dict (실험군끼리 합산해 비율을 내기 위해 비율이 아니라 분자·분모를 돌려준다)와 오답 예시."""
    eco = gold["ecosystem"]
    alias_to_id = {_canon(a): v["id"] for v in gold["vulns"] for a in [v["id"], *v["aliases"]]}
    anywhere, detailed = tool_evidence(trace)

    reported: dict[tuple[str, str], str | None] = {}
    workaround: dict[str, str | None] = {}
    for pkg in report.get("packages", []):
        name = _pkg_name(pkg.get("package", ""), eco)
        workaround[name] = pkg.get("workaround")
        for v in pkg.get("vulnerabilities", []):
            vid = alias_to_id.get(_canon(v.get("id", "")))
            if vid and (name, vid) not in reported:
                cwe = v.get("cwe")
                reported[(name, vid)] = cwe.strip().upper() if isinstance(cwe, str) and cwe.strip() else None

    c = {k: 0 for k in ("vulns", "labeled", "hit", "answered", "valid", "grounded",
                        "wa_needed", "wa_present", "wa_relevant", "wa_grounded", "wa_extra")}
    misses = []
    per_vuln: dict[str, bool] = {}  # 실험군끼리 같은 취약점을 짝지어 비교하는 데 쓴다
    for v in gold["vulns"]:
        key = (_pkg_name(v["package"], eco), v["id"])
        cwe = reported.get(key)
        gold_cwes = labels.get(v["id"], set())
        c["vulns"] += 1
        if cwe:
            c["answered"] += 1
            c["valid"] += bool(CWE_FORM.match(cwe)) and cwe in catalog
            c["grounded"] += cwe in anywhere
        if gold_cwes:
            c["labeled"] += 1
            per_vuln[f"{key[0]}|{key[1]}"] = cwe in gold_cwes
            if cwe in gold_cwes:
                c["hit"] += 1
            elif len(misses) < 8:
                misses.append(f"{v['id']}: {cwe} not in {sorted(gold_cwes)}")

    needed = needs_workaround(gold)
    pkg_labels: dict[str, set[str]] = {}
    for v in gold["vulns"]:
        pkg_labels.setdefault(_pkg_name(v["package"], eco), set()).update(labels.get(v["id"], set()))
    wa_misses = []
    for name in needed:
        c["wa_needed"] += 1
        text = workaround.get(name)
        if not (isinstance(text, str) and text.strip()):
            wa_misses.append(f"{name}: no workaround")
            continue
        c["wa_present"] += 1
        cited = {f"CWE-{n}" for n in CWE_RE.findall(text)}
        c["wa_relevant"] += bool(cited & pkg_labels.get(name, set()))
        c["wa_grounded"] += bool(cited & detailed)
        if not cited & pkg_labels.get(name, set()):
            wa_misses.append(f"{name}: cites {sorted(cited)}, labels {sorted(pkg_labels.get(name, set()))}")
    c["wa_extra"] = sum(1 for name, text in workaround.items()
                        if name not in needed and isinstance(text, str) and text.strip())
    return {"counts": c, "misses": misses, "wa_misses": wa_misses, "per_vuln": per_vuln}


def oracle_cwe_report(gold: dict, labels: dict[str, set[str]]) -> tuple[dict, list[dict]]:
    """CI 자체 점검용: 정답 라벨을 그대로 쓰고 완화책도 get_weakness로 조회한 것처럼 만든 보고서와 trace."""
    eco = gold["ecosystem"]
    needed = needs_workaround(gold)
    packages: dict[str, dict] = {}
    fetched = set()
    for v in gold["vulns"]:
        cwe = min(labels.get(v["id"], set()), default=None)
        pkg = packages.setdefault(v["package"], {"package": v["package"], "vulnerabilities": [], "workaround": None})
        pkg["vulnerabilities"].append({"id": v["id"], "cwe": cwe})
        if _pkg_name(v["package"], eco) in needed and cwe:
            pkg["workaround"] = (pkg["workaround"] or "임시 완화책") + f" ({cwe})"
            fetched.add(cwe)
    trace = []
    for cwe in sorted(fetched):
        trace += [{"role": "tool_call", "name": "get_weakness", "content": json.dumps({"cwe_id": cwe})},
                  {"role": "tool_result", "content": json.dumps({"cwe_id": cwe})}]
    return {"packages": list(packages.values())}, trace


def search_diagnostics(report: dict, trace: list[dict], gold: dict, labels: dict[str, set[str]]) -> dict:
    """검색 실험군 분해: 틀린 이유가 검색(후보에 정답 없음)인지 선택(후보에 있는데 다른 것을 고름)인지.

    search_weaknesses_many 호출의 key(에이전트가 넣은 취약점 id)로 취약점마다 후보 목록을 찾는다.
    """
    alias_to_id = {_canon(a): v["id"] for v in gold["vulns"] for a in [v["id"], *v["aliases"]]}
    candidates: dict[str, list[str]] = {}
    pending: deque[str] = deque()
    for t in trace:
        if t["role"] == "tool_call":
            pending.append(t["name"])
        elif t["role"] == "tool_result":
            if (pending.popleft() if pending else "") != "search_weaknesses_many":
                continue
            try:
                for r in json.loads(t["content"])["results"]:
                    vid = alias_to_id.get(_canon(str(r["key"])))
                    if vid:
                        candidates[vid] = [c["cwe_id"] for c in r["candidates"]]
            except (json.JSONDecodeError, KeyError, TypeError):
                pass
    chosen = {}
    for pkg in report.get("packages", []):
        for v in pkg.get("vulnerabilities", []):
            vid = alias_to_id.get(_canon(v.get("id", "")))
            if vid and vid not in chosen:
                cwe = v.get("cwe")
                chosen[vid] = cwe.strip().upper() if isinstance(cwe, str) and cwe.strip() else None
    d = {k: 0 for k in ("labeled", "searched", "label_in_candidates", "label_top1", "chosen_top1", "chosen_in_candidates",
                        "hit_from_candidates", "hit_outside_candidates", "miss_label_in_candidates",
                        "miss_label_not_in_candidates", "null")}
    for vid in {v["id"] for v in gold["vulns"]}:
        gold_cwes = labels.get(vid, set())
        if not gold_cwes:
            continue
        d["labeled"] += 1
        cands, cwe = candidates.get(vid), chosen.get(vid)
        if cands is None:
            continue
        d["searched"] += 1
        in_cands = bool(gold_cwes & set(cands))
        d["label_in_candidates"] += in_cands
        d["label_top1"] += bool(cands) and cands[0] in gold_cwes  # 검색기 1위만 그대로 썼을 때의 정답 (재순위 효과 비교용)
        d["null"] += cwe is None
        d["chosen_top1"] += bool(cands) and cwe == cands[0]
        d["chosen_in_candidates"] += cwe in cands
        if cwe in gold_cwes:
            d["hit_from_candidates" if cwe in cands else "hit_outside_candidates"] += 1
        else:
            d["miss_label_in_candidates" if in_cands else "miss_label_not_in_candidates"] += 1
    return d
