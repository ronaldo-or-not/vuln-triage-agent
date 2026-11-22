"""두 종류의 실패를 구분한다. MCP 계층에서 둘 다 모델이 읽고 회복할 수 있는 메시지로 바뀐다."""


class InvalidInput(ValueError):
    """호출자가 고칠 수 있는 입력 오류 (잘못된 생태계, ID 형식 등)."""


class SourceError(RuntimeError):
    """외부 데이터 소스 장애 (타임아웃, 5xx, 속도 제한 초과 후 재시도 실패)."""
