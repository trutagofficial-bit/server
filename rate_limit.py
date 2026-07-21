"""
server/rate_limit.py
=====================
Per-uid AND per-IP rate limiting for the anonymous /public/* endpoints
(migration spec §3, "web clint/index.html" change notes: "max 5
requests/minute per QR").

Ships as a plain in-memory sliding-window counter — fine for a single
uvicorn worker on Render/Railway free tier, which is the deploy target
in the spec. It is NOT correct across multiple worker processes/
instances (each process has its own counters, so real-world limits
become max_requests * worker_count). If you scale past one instance,
swap Store for a Redis-backed one (see RedisStore stub below) without
changing any call sites — that's the whole reason this is behind a
small interface instead of a global dict sprinkled through api.py.

Usage:
    from .rate_limit import limiter

    limiter.check(f"uid:{uid}", max_requests=5, window_seconds=60)
    limiter.check(f"ip:{request.client.host}", max_requests=20, window_seconds=60)
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException


class InMemoryStore:
    def __init__(self):
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def hit(self, key: str, window_seconds: int) -> int:
        """Record one hit for `key`, evict anything older than the
        window, and return the count remaining in the window
        (including this hit)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[key]
            bucket.append(now)
            cutoff = now - window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            return len(bucket)


class RedisStore:
    """Drop-in replacement for InMemoryStore once you need rate limits
    that hold across multiple server instances. Not wired up by
    default so this backend has zero extra dependencies until you
    actually need Redis.

        pip install redis
        export REDIS_URL=redis://...

    Then swap the `store` instance at the bottom of this file.
    """

    def __init__(self, redis_url: str):
        import redis  # local import: only required if you opt into this

        self._r = redis.from_url(redis_url)

    def hit(self, key: str, window_seconds: int) -> int:
        now = time.time()
        pipe = self._r.pipeline()
        pipe.zadd(key, {str(now): now})
        pipe.zremrangebyscore(key, 0, now - window_seconds)
        pipe.zcard(key)
        pipe.expire(key, window_seconds)
        _, _, count, _ = pipe.execute()
        return count


class RateLimiter:
    def __init__(self, store):
        self._store = store

    def check(self, key: str, max_requests: int, window_seconds: int = 60) -> None:
        """Raises HTTP 429 if `key` has exceeded max_requests within
        window_seconds. Call once per identity you want to bound
        (typically once for the anonymous uid, once for the IP)."""
        count = self._store.hit(key, window_seconds)
        if count > max_requests:
            raise HTTPException(
                status_code=429,
                detail="Too many requests — please slow down and try again shortly.",
            )


# Single shared instance used across api.py. Swap InMemoryStore() for
# RedisStore(os.environ["REDIS_URL"]) when you outgrow one instance.
limiter = RateLimiter(InMemoryStore())
