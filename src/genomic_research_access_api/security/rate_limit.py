"""Small deterministic in-memory rate limiter for local dynamic validation."""

from __future__ import annotations

import base64
import json
import re
import time
from collections import OrderedDict, deque
from collections.abc import Callable

from fastapi import Request


class InMemoryRateLimiter:
    def __init__(
        self,
        *,
        max_requests: int,
        window_seconds: int,
        max_subjects: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._max_subjects = max_subjects
        self._clock = clock
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()

    def check(self, key: str) -> int | None:
        now = self._clock()
        bucket = self._buckets.setdefault(key, deque())
        self._buckets.move_to_end(key)
        while bucket and now - bucket[0] >= self._window_seconds:
            bucket.popleft()
        if len(bucket) >= self._max_requests:
            retry_after = max(1, int(self._window_seconds - (now - bucket[0])))
            return retry_after
        bucket.append(now)
        while len(self._buckets) > self._max_subjects:
            self._buckets.popitem(last=False)
        return None

    def reset(self) -> None:
        self._buckets.clear()


def rate_limit_key_from_request(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        subject = _subject_from_unverified_jwt(authorization.removeprefix("Bearer ").strip())
        if subject:
            return f"sub:{subject}"
    client_host = request.client.host if request.client else "unknown"
    sanitized = re.sub(r"[^A-Za-z0-9_.:-]", "_", client_host)[:120] or "unknown"
    return f"client:{sanitized}"


def _subject_from_unverified_jwt(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        return None
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", subject)[:120]
