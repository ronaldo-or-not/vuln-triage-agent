"""HTTP 공통: 재시도, 백오프, 속도 제한."""

import collections
import logging
import threading
import time

import httpx

from .errors import SourceError

log = logging.getLogger(__name__)

RETRYABLE = frozenset({429, 500, 502, 503, 504})


def make_client(user_agent: str) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(30.0, connect=10.0),
        headers={"User-Agent": user_agent},
        follow_redirects=True,  # EPSS 최신 파일 URL은 날짜별 파일로 302 리다이렉트된다
    )


class RateLimiter:
    """슬라이딩 윈도우 속도 제한: window초 안에 최대 max_calls번.

    NVD 공개 한도는 API 키 없이 30초에 5회, 키가 있으면 30초에 50회다.
    초과하면 429를 받으므로, 받고 나서 기다리기보다 미리 간격을 맞춘다.
    """

    def __init__(self, max_calls: int, window_seconds: float):
        self.max_calls = max_calls
        self.window = window_seconds
        self._calls: collections.deque[float] = collections.deque()
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            while True:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self.window:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                time.sleep(self.window - (now - self._calls[0]) + 0.05)


def _retry_after(response: httpx.Response, fallback: float) -> float:
    # retry-after가 0이나 아주 작은 값으로 와도 기본 백오프보다 짧게 기다리지 않는다 (NVD가 0을 준 적 있음)
    try:
        return min(max(float(response.headers.get("retry-after", fallback)), fallback), 60.0)
    except ValueError:  # 날짜 형식 retry-after는 무시하고 기본 백오프
        return fallback


def request(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    tries: int = 4,
    retryable: frozenset[int] = RETRYABLE,
    limiter: RateLimiter | None = None,
    **kwargs,
) -> httpx.Response:
    """재시도 가능한 실패(네트워크 오류, 429, 5xx)는 지수 백오프로 다시 시도한다.

    4xx 같은 재시도해도 소용없는 응답은 그대로 돌려주고, 판단은 호출한 쪽이 한다.
    """
    for attempt in range(tries):
        if limiter:
            limiter.wait()
        backoff = 2.0 * (2**attempt)
        try:
            response = client.request(method, url, **kwargs)
        except httpx.TransportError as exc:
            if attempt == tries - 1:
                raise SourceError(f"{method} {url} failed: {exc}") from exc
            log.warning("network error on %s, retrying in %.0fs: %s", url, backoff, exc)
            time.sleep(backoff)
            continue
        if response.status_code in retryable and attempt < tries - 1:
            delay = _retry_after(response, backoff)
            log.warning("HTTP %s on %s, retrying in %.0fs", response.status_code, url, delay)
            time.sleep(delay)
            continue
        if response.status_code in retryable:
            raise SourceError(f"{method} {url} kept failing with HTTP {response.status_code}")
        return response
    raise AssertionError("unreachable")
