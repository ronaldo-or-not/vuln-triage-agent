"""보고서 채점기 (전부 결정적 코드, LLM 판정 없음).

지표 (케이스마다 전부 채운다. 해당 사항이 없으면 1 = 문제없음)
- pass         : 아래 필수 조건을 모두 만족 (헤드라인)
- recall       : 정답 취약점 중 보고서에 나온 비율
- no_halluc    : 도구 결과에 없는 ID를 하나도 쓰지 않음
- kev_order    : KEV 등재 취약점이 전부 비등재보다 순위가 높음
- kev_facts    : 보고서의 kev 표기가 실제와 일치
- upgrade_ok   : 취약 패키지 중 업그레이드 추천이 안전한 비율
                 (추천 버전을 각 취약점의 OSV 범위에 다시 넣어 하나라도 걸리면 오답. 최소 버전인지는 보지 않음)
- unchecked_ok : 파서가 검사 불가로 넘긴 항목을 빠짐없이 보고
- order_tau    : 정책 순서(KEV, EPSS)와 보고 순위의 켄달 타우 (-1~1, 참고용, pass에 포함 안 함)
"""

import re

from vulnagent.ids import ECOSYSTEMS, normalize_package_name, normalize_vuln_id
from vulnagent.versions import compare, is_affected

METRICS = [
    {"id": "pass", "label": "pass", "kind": "binary"},
    {"id": "recall", "label": "recall", "kind": "float", "scale": 1},
    {"id": "no_halluc", "label": "no halluc", "kind": "binary"},
    {"id": "kev_order", "label": "KEV first", "kind": "binary"},
    {"id": "kev_facts", "label": "KEV facts", "kind": "binary"},
    {"id": "upgrade_ok", "label": "upgrade ok", "kind": "float", "scale": 1},
    {"id": "unchecked_ok", "label": "unchecked ok", "kind": "binary"},
    {"id": "order_tau", "label": "order tau", "kind": "float", "scale": 1},
]
REQUIRED_FOR_PASS = ("no_halluc", "kev_order", "kev_facts", "unchecked_ok")


def _canon(vuln_id: str) -> str:
    return (normalize_vuln_id(vuln_id) or vuln_id.strip()).upper()


def _split_package(label: str) -> tuple[str | None, str, str | None]:
    """'PyPI/jinja2@2.10' -> ('PyPI', 'jinja2', '2.10'). 생태계 접두어가 없어도 받아준다.
    npm scope('@babel/core@7.0.0')의 '/'는 생태계 구분자가 아니다."""
    ecosystem, sep, rest = label.strip().partition("/")
    if not sep or ecosystem.lower() not in ECOSYSTEMS:
        ecosystem, rest = None, label.strip()
    name, at, version = rest.rpartition("@")
    if not at or not name:
        return ecosystem, rest, None
    return ecosystem, name, version


def _unchecked_key(spec: str) -> str:
    spec = spec.strip()
    if spec.startswith("-") or "://" in spec:
        return spec
    if "@" in spec[1:]:  # npm: name@range (scope의 앞 @는 제외)
        return spec[: spec.index("@", 1)]
    if ":" in spec:  # Maven: group:artifact[:version]
        return ":".join(spec.split(":")[:2])
    return re.match(r"[A-Za-z0-9._-]+", spec).group(0) if re.match(r"[A-Za-z0-9._-]+", spec) else spec


def _kendall_tau(pairs: list[tuple[int, int]]) -> float:
    n = len(pairs)
    if n < 2:
        return 1.0
    concordant = discordant = 0
    for i in range(n):
        for j in range(i + 1, n):
            a = (pairs[i][0] - pairs[j][0]) * (pairs[i][1] - pairs[j][1])
            concordant += a > 0
            discordant += a < 0
    total = concordant + discordant
    return (concordant - discordant) / total if total else 1.0


def _pkg_name(label: str, ecosystem: str) -> str:
    return normalize_package_name(ecosystem, _split_package(label)[1]).lower()


def _expected_order(gold: dict) -> list[tuple[str, str]]:
    """정책 순서: KEV 먼저, 그다음 EPSS 높은 순. 키는 (패키지, ID) - 같은 CVE가 두 패키지에 걸칠 수 있다."""
    eco = gold["ecosystem"]
    vulns = sorted(gold["vulns"], key=lambda v: (not v["kev"], -(v["epss"] or -1), v["id"], v["package"]))
    return [(_pkg_name(v["package"], eco), v["id"]) for v in vulns]


def grade(report: dict, gold: dict) -> tuple[dict, dict]:
    """반환: (지표 dict, 설명 dict). 설명은 리포트에서 왜 틀렸는지 보여주는 용도."""
    eco = gold["ecosystem"]
    alias_to_id = {_canon(a): v["id"] for v in gold["vulns"] for a in [v["id"], *v["aliases"]]}
    gold_keys = {(_pkg_name(v["package"], eco), v["id"]): v for v in gold["vulns"]}
    gold_kev = {k: bool(v["kev"]) for k, v in gold_keys.items()}
    expected_pos = {k: i for i, k in enumerate(_expected_order(gold))}

    reported: dict[tuple[str, str], dict] = {}
    unknown: list[str] = []
    for pkg in report.get("packages", []):
        name = _pkg_name(pkg.get("package", ""), eco)
        for vuln in pkg.get("vulnerabilities", []):
            canon = alias_to_id.get(_canon(vuln.get("id", "")))
            key = (name, canon)
            if canon is None:
                unknown.append(vuln.get("id", ""))
            elif key not in gold_keys:  # 실제 있는 취약점이지만 다른 패키지에 붙임
                unknown.append(f"{vuln.get('id')} under {pkg.get('package')}")
            elif key not in reported:
                reported[key] = vuln

    scores, why = {}, {}
    total = len(gold["vulns"])
    missing = [f"{v['id']}" for k, v in gold_keys.items() if k not in reported]
    scores["recall"] = round((total - len(missing)) / total, 4) if total else 1.0
    if missing:
        why["recall"] = f"missing {len(missing)}/{total}: {', '.join(missing[:8])}{' ...' if len(missing) > 8 else ''}"

    scores["no_halluc"] = 0 if unknown else 1
    if unknown:
        why["no_halluc"] = f"ids not returned by the tools: {', '.join(unknown[:8])}"

    kev_ranks = [v.get("rank", 10**9) for vid, v in reported.items() if gold_kev[vid]]
    other_ranks = [v.get("rank", 10**9) for vid, v in reported.items() if not gold_kev[vid]]
    scores["kev_order"] = 1 if not kev_ranks or not other_ranks or max(kev_ranks) < min(other_ranks) else 0
    if not scores["kev_order"]:
        why["kev_order"] = f"lowest KEV rank {max(kev_ranks)} is below highest non-KEV rank {min(other_ranks)}"

    wrong_kev = [vid for (_n, vid), v in reported.items() if bool(v.get("kev")) != gold_kev[(_n, vid)]]
    scores["kev_facts"] = 0 if wrong_kev else 1
    if wrong_kev:
        why["kev_facts"] = f"wrong kev flag: {', '.join(wrong_kev[:8])}"

    by_name = {}
    for pkg in report.get("packages", []):
        _, name, _ = _split_package(pkg.get("package", ""))
        by_name[name.lower()] = pkg
    upgrade_hits, upgrade_notes = 0, []
    for gp in gold["packages"]:
        eco = gp["ecosystem"]
        candidates = [p for n, p in by_name.items() if normalize_package_name(eco, n) == gp["name"].lower()
                      or normalize_package_name(eco, n) == normalize_package_name(eco, gp["name"])]
        target = candidates[0].get("upgrade_to") if candidates else None
        matches = lambda n, e=eco, want=gp["name"]: normalize_package_name(e, n) == normalize_package_name(e, want)
        if not candidates:
            upgrade_notes.append(f"{gp['package']}: package missing from report")
            continue
        if gp["min_safe_upgrade"] is None:
            ok = target is None
            if not ok:
                upgrade_notes.append(f"{gp['package']}: no version fixes all, but report says {target}")
        elif target is None:
            ok = False
            upgrade_notes.append(f"{gp['package']}: report gives no upgrade (safe: {gp['min_safe_upgrade']})")
        else:
            # 추천 버전은 도구가 알려준 수정 버전 중 하나여야 한다 (999.0.0 같은 존재하지 않는 버전 방지).
            # 프롬프트가 요구하는 '모두 고치는 가장 낮은 버전'은 항상 어떤 수정 버전과 같다.
            known_fixes = {e["fixed"] for r in gp["records"] for a in r["affected"]
                           for rng in a["ranges"] for e in rng.get("events", []) if "fixed" in e}
            still = [r["id"] for r in gp["records"] if is_affected(target, r, eco, matches)]
            downgrade = compare(target, gp["installed"], eco) < 0
            unknown_version = target not in known_fixes
            ok = not still and not downgrade and not unknown_version
            if unknown_version:
                upgrade_notes.append(f"{gp['package']} -> {target} is not a fixed version returned by the tools")
            elif still:
                upgrade_notes.append(f"{gp['package']} -> {target} still affected by {', '.join(still[:4])} (safe: {gp['min_safe_upgrade']})")
            elif downgrade:
                upgrade_notes.append(f"{gp['package']} -> {target} is a downgrade")
        upgrade_hits += ok
    scores["upgrade_ok"] = round(upgrade_hits / len(gold["packages"]), 4) if gold["packages"] else 1.0
    if upgrade_notes:
        why["upgrade_ok"] = "; ".join(upgrade_notes[:6])

    report_specs = " | ".join(u.get("spec", "") for u in report.get("unchecked", [])).lower()
    lost = [
        spec for spec in gold["unchecked"]
        if not re.search(rf"(?<![\w.-]){re.escape(_unchecked_key(spec).lower())}(?![\w-])", report_specs)
    ]
    scores["unchecked_ok"] = 0 if lost else 1
    if lost:
        why["unchecked_ok"] = f"unchecked entries not reported ({len(lost)}/{len(gold['unchecked'])}): {', '.join(lost[:6])}"

    pairs = [(expected_pos[key], v.get("rank", 10**9)) for key, v in reported.items()]
    scores["order_tau"] = round(_kendall_tau(pairs), 4)

    scores["pass"] = int(scores["recall"] == 1.0 and scores["upgrade_ok"] == 1.0
                         and all(scores[k] == 1 for k in REQUIRED_FOR_PASS))
    return {m["id"]: scores[m["id"]] for m in METRICS}, why


def oracle_report(gold: dict) -> dict:
    """정답으로 만든 '완벽한' 보고서. 채점기 자체를 검증하는 데 쓴다 (~100%가 나와야 정상)."""
    rank = {key: i + 1 for i, key in enumerate(_expected_order(gold))}
    packages = []
    for gp in gold["packages"]:
        vulns = [v for v in gold["vulns"] if v["package"] == gp["package"]]
        name = _pkg_name(gp["package"], gold["ecosystem"])
        packages.append({
            "package": gp["package"],
            "upgrade_to": gp["min_safe_upgrade"],
            "reason": "oracle",
            "vulnerabilities": [{"id": v["id"], "rank": rank[(name, v["id"])], "priority": "high", "kev": bool(v["kev"])}
                                for v in vulns],
        })
    return {"summary": "oracle", "packages": packages,
            "unchecked": [{"spec": s, "reason": "oracle"} for s in gold["unchecked"]], "notes": []}


def null_report(_gold: dict) -> dict:
    """아무것도 없다고 말하는 보고서. 대부분 실패해야 정상 (채점기가 너무 관대하지 않은지 확인)."""
    return {"summary": "", "packages": [], "unchecked": [], "notes": []}
