"""생태계별 버전 비교와 OSV 영향 범위(range) 계산.

1주차 한계였던 "수정 버전을 문자열로 정렬"(2.12.2, 2.15.0, 2.3.1)을 해결한다.
업그레이드 대상을 정하려면 '설치된 버전이 속한 범위의 수정 버전'을 알아야 한다.
예: log4j-core 2.14.1 + CVE-2021-44228 -> 범위 [2.13.0, 2.15.0) -> 2.15.0 (2.3.1은 다운그레이드라 오답)

- PyPI/npm: PEP 440(packaging)으로 비교. 안 되는 형식은 일반 규칙으로 대체.
- Maven 등: 숫자/한정자 토큰 비교 (alpha < beta < milestone < rc < snapshot < 릴리스 < sp).
"""

import functools
import re

from packaging.version import InvalidVersion, Version

_QUALIFIERS = {
    "alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3,
    "rc": -2, "cr": -2, "preview": -2, "snapshot": -1,
    "ga": 0, "final": 0, "release": 0, "sp": 1,
}
_PAD = (1, 0)  # 토큰이 모자랄 때 채우는 값 = "릴리스"


def _generic_key(v: str) -> list[tuple[int, int]]:
    key: list[tuple[int, int]] = []
    for token in re.findall(r"\d+|[a-zA-Z]+", v.lower()):
        if token.isdigit():
            key.append((2, int(token)))
        else:
            # 한정자 앞 숫자 묶음의 끝 0은 지운다: 2.0-beta9 == 2-beta9 (Maven 규칙)
            while key and key[-1] == (2, 0):
                key.pop()
            rank = _QUALIFIERS.get(token, -1.5)  # 모르는 한정자는 rc와 snapshot 사이로
            key.append((0, rank) if rank < 0 else (1, rank))
    while key and key[-1] == (2, 0):  # 2.0 == 2.0.0
        key.pop()
    return key


def compare(a: str, b: str, ecosystem: str = "") -> int:
    if a == b:
        return 0
    if ecosystem in ("PyPI", "npm"):
        try:
            va, vb = Version(a), Version(b)
            return (va > vb) - (va < vb)
        except InvalidVersion:
            pass
    ka, kb = _generic_key(a), _generic_key(b)
    n = max(len(ka), len(kb))
    ka += [_PAD] * (n - len(ka))
    kb += [_PAD] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def sort_versions(versions, ecosystem: str = "") -> list[str]:
    return sorted(versions, key=functools.cmp_to_key(lambda x, y: compare(x, y, ecosystem)))


def at_least(candidate: str, required: str, ecosystem: str = "") -> bool:
    return compare(candidate, required, ecosystem) >= 0


def _event_version(event: dict) -> str:
    return next(iter(event.values()))


def fix_for_range(installed: str, events: list[dict], ecosystem: str) -> tuple[str, str | None]:
    """한 range의 events로 설치 버전을 판정한다.

    반환: ("fixed", 수정버전) | ("no_fix", None) | ("not_affected", None)
    OSV 규칙: introduced <= v < fixed 이면 영향, introduced <= v <= last_affected 이면 영향(수정 없음).
    introduced "0"은 "처음부터"라는 뜻.
    """
    def ge(v, bound):
        return bound == "0" or compare(v, bound, ecosystem) >= 0

    order = {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 2}
    events = sorted(
        events,
        key=functools.cmp_to_key(
            lambda x, y: (
                -1 if _event_version(x) == "0" and _event_version(y) != "0"
                else 1 if _event_version(y) == "0" and _event_version(x) != "0"
                else compare(_event_version(x), _event_version(y), ecosystem)
                or order[next(iter(x))] - order[next(iter(y))]
            )
        ),
    )
    introduced = None
    for event in events:
        kind, value = next(iter(event.items()))
        if kind == "introduced":
            introduced = value
        elif kind == "fixed":
            if introduced is not None and ge(installed, introduced) and compare(installed, value, ecosystem) < 0:
                return "fixed", value
            introduced = None
        elif kind == "last_affected":
            if introduced is not None and ge(installed, introduced) and compare(installed, value, ecosystem) <= 0:
                return "no_fix", None
            introduced = None
    if introduced is not None and ge(installed, introduced):
        return "no_fix", None
    return "not_affected", None


def is_affected(version: str, record: dict, ecosystem: str, name_matches) -> bool | None:
    """이 버전이 레코드의 영향 범위에 들어가는가. 범위로 판정할 수 없으면 None.

    업그레이드 추천을 채점할 때 쓴다: 추천 버전을 각 취약점 범위에 다시 넣어 보면
    '2.15.0으로 올리면 CVE-2021-44228은 고쳐지지만 CVE-2021-45046은 남는다' 같은 오답이 잡힌다.
    """
    listed = False
    verdicts = []
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] != ecosystem or not name_matches(pkg.get("name", "")):
            continue
        if version in affected.get("versions", []):
            listed = True
        for rng in affected.get("ranges", []):
            if rng.get("type") in ("ECOSYSTEM", "SEMVER"):
                verdicts.append(fix_for_range(version, rng.get("events", []), ecosystem)[0])
    if listed or any(v in ("fixed", "no_fix") for v in verdicts):
        return True
    return False if verdicts else None


def min_safe_upgrade(installed: str, ecosystem: str, records: list[dict], name_matches) -> str | None:
    """설치 버전보다 높으면서 이 패키지의 모든 취약점 범위를 벗어나는 가장 낮은 '수정 버전'. 없으면 None.

    후보는 레코드에 나온 수정 버전들뿐이다 (레지스트리의 전체 버전 목록은 모르므로).
    평가의 정답(build_gold.py)과 v4 도구 힌트가 같은 함수를 쓴다.
    """
    candidates = {
        event["fixed"]
        for rec in records for a in rec.get("affected", [])
        if a.get("package", {}).get("ecosystem", "").split(":")[0] == ecosystem and name_matches(a["package"].get("name", ""))
        for rng in a.get("ranges", []) if rng.get("type") in ("ECOSYSTEM", "SEMVER")
        for event in rng.get("events", []) if "fixed" in event
    }
    for candidate in sort_versions((c for c in candidates if compare(c, installed, ecosystem) > 0), ecosystem):
        if not any(is_affected(candidate, rec, ecosystem, name_matches) for rec in records):
            return candidate
    return None


def fix_for_package(installed: str, record: dict, ecosystem: str, name_matches) -> tuple[str, str | None]:
    """OSV 레코드 하나에서 '조회한 패키지'의 영향 범위를 보고 수정 버전을 정한다.

    name_matches(affected_package_name) -> bool 로 같은 패키지인지 판단한다 (PEP 503 등).
    반환 상태: fixed / no_fix / unknown (범위로 판정이 안 됨: versions 목록만 있거나 GIT 범위뿐)
    """
    verdicts = []
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] != ecosystem or not name_matches(pkg.get("name", "")):
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") in ("ECOSYSTEM", "SEMVER"):
                verdicts.append(fix_for_range(installed, rng.get("events", []), ecosystem))
    fixes = [v for status, v in verdicts if status == "fixed"]
    if fixes:
        return "fixed", sort_versions(fixes, ecosystem)[-1]
    if any(status == "no_fix" for status, _ in verdicts):
        return "no_fix", None
    return "unknown", None
