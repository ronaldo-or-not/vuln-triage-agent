"""설정. 모든 값은 환경변수로 덮어쓸 수 있다 (.env.example 참고)."""

import os
from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class Settings:
    database_url: str
    nvd_api_key: str | None
    offline: bool  # True면 네트워크를 절대 쓰지 않고 DB 캐시만 본다 (평가 재현용)
    as_of: date | None  # 기본 스냅샷 날짜. 평가 때 고정해서 KEV/EPSS 값이 날마다 바뀌지 않게 한다
    tool_hints: bool  # v4: check_packages가 safe_upgrade / policy_rank를 결정적으로 계산해 함께 준다
    cwe_mode: str  # 8주차 실험: "" 그대로 / "labels" check_packages가 CWE 라벨을 붙임 / "hidden" 모든 도구에서 CWE 라벨을 숨김
    user_agent: str
    osv_query_ttl_hours: int
    nvd_ttl_hours: int
    nvd_pending_ttl_hours: int  # 아직 분석 대기 중인 CVE는 곧 바뀌므로 더 자주 갱신
    nvd_notfound_ttl_hours: int
    bulk_refresh_hours: int  # KEV/EPSS 스냅샷을 새로 받을 주기
    keep_snapshots: int  # pinned가 아닌 스냅샷을 최근 몇 개까지 남길지


CWE_MODES = ("", "labels", "hidden")
# 평가로 고른 제품 설정 (CLI와 PR 코멘트가 같이 쓴다): 검증 루프(3주차) + 결정적 계산 도구(4·5주차) + CWE 라벨 전달(8주차).
# agent.run_triage의 인자 기본값은 실험 재현을 위해 v0 그대로 둔다.
PRODUCT_SETTINGS = {"validate": True, "tool_hints": True, "cwe": "labels"}


def load_settings() -> Settings:
    env = os.environ
    if env.get("VULNAGENT_CWE_MODE", "") not in CWE_MODES:
        raise ValueError(f"VULNAGENT_CWE_MODE must be one of {CWE_MODES}, got {env['VULNAGENT_CWE_MODE']!r}")
    return Settings(
        database_url=env.get("DATABASE_URL", "postgresql:///vulnagent"),
        nvd_api_key=env.get("NVD_API_KEY") or None,
        offline=env.get("VULNAGENT_OFFLINE", "0") == "1",
        as_of=date.fromisoformat(env["VULNAGENT_AS_OF"]) if env.get("VULNAGENT_AS_OF") else None,
        tool_hints=env.get("VULNAGENT_TOOL_HINTS", "0") == "1",
        cwe_mode=env.get("VULNAGENT_CWE_MODE", ""),
        # 외부 API에는 개인정보 없는 일반 클라이언트 이름만 보낸다.
        user_agent="vuln-triage-agent/0.1",
        osv_query_ttl_hours=int(env.get("OSV_QUERY_TTL_HOURS", "24")),
        nvd_ttl_hours=int(env.get("NVD_TTL_HOURS", "168")),
        nvd_pending_ttl_hours=int(env.get("NVD_PENDING_TTL_HOURS", "24")),
        nvd_notfound_ttl_hours=int(env.get("NVD_NOTFOUND_TTL_HOURS", "24")),
        bulk_refresh_hours=int(env.get("BULK_REFRESH_HOURS", "24")),
        keep_snapshots=int(env.get("KEEP_SNAPSHOTS", "7")),
    )
