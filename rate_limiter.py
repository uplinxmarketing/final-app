"""
rate_limiter.py — API rate limiting and request throttling for Uplinx Meta Manager.

Provides:
- ApiCallTracker  : Per-account Meta API call counting and adaptive throttling
- RateLimiter     : Per-IP sliding-window rate limiter for incoming requests
- BatchHandler    : Meta Graph API batch-request helper

Singletons ``api_tracker`` and ``rate_limiter`` are exported at module level.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from typing import Any, Optional

import httpx

logger = logging.getLogger("uplinx")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Meta API hourly call thresholds (200 calls/hour soft limit assumed).
_HOURLY_LIMIT: int = 200
_THROTTLE_THRESHOLD_75: int = int(_HOURLY_LIMIT * 0.75)  # 150
_THROTTLE_THRESHOLD_90: int = int(_HOURLY_LIMIT * 0.90)  # 180

# Normal delay between consecutive calls (seconds).
_NORMAL_DELAY: float = 0.5

# Elevated delay at 75 % usage (seconds).
_ELEVATED_DELAY: float = 1.0

# Pause duration triggered at 90 % usage (seconds).
_PAUSE_DURATION: float = 300.0  # 5 minutes

# Per-IP sliding window: max requests per window.
_IP_WINDOW_SECONDS: int = 60
_IP_MAX_REQUESTS: int = 60

# Meta batch API endpoint.
_META_BATCH_URL: str = "https://graph.facebook.com/"

# Maximum number of requests per Meta batch call.
_MAX_BATCH_SIZE: int = 50


# ---------------------------------------------------------------------------
# 1. ApiCallTracker
# ---------------------------------------------------------------------------


class ApiCallTracker:
    """Track outbound Meta Graph API calls per account and apply adaptive throttling.

    Call history is kept in memory as a sliding deque of UNIX timestamps.
    Entries older than one hour are purged on each :meth:`record_call` so
    memory usage stays bounded regardless of uptime.

    This class is safe for concurrent use within a single asyncio event loop
    because all mutations are performed inside ``async`` methods which cannot
    be pre-empted between individual statements.
    """

    def __init__(self) -> None:
        # account_id -> deque of UNIX timestamps (float)
        self._calls: defaultdict[str, deque[float]] = defaultdict(deque)
        # account_id -> resume timestamp (float, UNIX epoch)
        self.is_paused: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _trim_old_calls(self, account_id: str) -> None:
        """Remove call timestamps older than one hour for *account_id*."""
        cutoff = time.monotonic() - 3600.0
        calls = self._calls[account_id]
        while calls and calls[0] < cutoff:
            calls.popleft()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def record_call(self, account_id: str) -> None:
        """Record a single outbound API call for *account_id*.

        Appends the current monotonic timestamp and purges entries older than
        one hour.

        Args:
            account_id: The Meta ad account ID (or any unique account string)
                making the call.
        """
        self._calls[account_id].append(time.monotonic())
        self._trim_old_calls(account_id)
        logger.debug(
            "API call recorded for account %r — %d calls in last hour.",
            account_id,
            len(self._calls[account_id]),
        )

    def get_call_count(self, account_id: str, window_hours: int = 1) -> int:
        """Return the number of calls made by *account_id* in the last *window_hours*.

        Args:
            account_id: The account to query.
            window_hours: Look-back window in hours.  Defaults to ``1``.

        Returns:
            Integer call count within the requested window.
        """
        cutoff = time.monotonic() - (window_hours * 3600.0)
        return sum(1 for ts in self._calls[account_id] if ts >= cutoff)

    def get_throttle_delay(self, account_id: str) -> float:
        """Compute the recommended inter-call delay for *account_id*.

        Thresholds (based on a 200-call/hour soft limit):

        * ``< 150 calls`` → :data:`_NORMAL_DELAY` (0.5 s)
        * ``150 – 179 calls`` → :data:`_ELEVATED_DELAY` (1.0 s)
        * ``≥ 180 calls`` → sets a 5-minute pause flag and returns
          :data:`_PAUSE_DURATION` (300 s)

        Args:
            account_id: The account to evaluate.

        Returns:
            Recommended sleep duration in seconds.
        """
        count = self.get_call_count(account_id)

        if count >= _THROTTLE_THRESHOLD_90:
            resume_time = time.monotonic() + _PAUSE_DURATION
            self.is_paused[account_id] = resume_time
            logger.warning(
                "Account %r has reached 90%% of the hourly API limit (%d calls). "
                "Pausing for %.0f seconds.",
                account_id,
                count,
                _PAUSE_DURATION,
            )
            return _PAUSE_DURATION

        if count >= _THROTTLE_THRESHOLD_75:
            logger.info(
                "Account %r is at 75%% of the hourly API limit (%d calls). "
                "Applying elevated throttle delay.",
                account_id,
                count,
            )
            return _ELEVATED_DELAY

        return _NORMAL_DELAY

    async def wait_if_needed(self, account_id: str) -> None:
        """Sleep for the throttle delay appropriate to *account_id*'s usage.

        If the account is currently paused, this method waits until the pause
        period has elapsed before returning.

        Args:
            account_id: The account to throttle.
        """
        # Check if account is in a pause period.
        if self.is_account_paused(account_id):
            remaining = self.is_paused[account_id] - time.monotonic()
            if remaining > 0:
                logger.info(
                    "Account %r is paused — waiting %.1f s.", account_id, remaining
                )
                await asyncio.sleep(remaining)
            else:
                del self.is_paused[account_id]

        delay = self.get_throttle_delay(account_id)
        if delay > 0:
            await asyncio.sleep(delay)

    def is_account_paused(self, account_id: str) -> bool:
        """Return ``True`` if *account_id* is currently in a throttle pause.

        Automatically clears the pause entry if the resume time has passed.

        Args:
            account_id: The account to check.

        Returns:
            ``True`` while the pause period is still active.
        """
        resume_time = self.is_paused.get(account_id)
        if resume_time is None:
            return False
        if time.monotonic() >= resume_time:
            del self.is_paused[account_id]
            return False
        return True


# ---------------------------------------------------------------------------
# 2. RateLimiter (per-IP sliding window)
# ---------------------------------------------------------------------------


class RateLimiter:
    """Per-IP rate limiter using a sliding-window algorithm.

    Tracks request timestamps for each IP address in memory.  Requests older
    than :data:`_IP_WINDOW_SECONDS` (60 s) are evicted on every check, keeping
    the data structure bounded.

    Limits:
        60 requests per 60-second window (1 req/s average).
    """

    def __init__(self) -> None:
        # ip_address -> deque of UNIX timestamps (float, using time.monotonic)
        self._requests: defaultdict[str, deque[float]] = defaultdict(deque)

    def _evict_old(self, ip: str) -> None:
        """Remove entries older than the sliding window for *ip*."""
        cutoff = time.monotonic() - _IP_WINDOW_SECONDS
        q = self._requests[ip]
        while q and q[0] < cutoff:
            q.popleft()

    def check_rate_limit(self, ip: str) -> bool:
        """Check whether *ip* is within the allowed request rate.

        Records the current request timestamp if the limit has not been
        exceeded.

        Args:
            ip: The client IP address string.

        Returns:
            ``True`` if the request is permitted; ``False`` if the rate limit
            has been exceeded.
        """
        self._evict_old(ip)
        count = len(self._requests[ip])
        if count >= _IP_MAX_REQUESTS:
            logger.warning(
                "Rate limit exceeded for IP %r — %d requests in last %ds.",
                ip,
                count,
                _IP_WINDOW_SECONDS,
            )
            return False
        self._requests[ip].append(time.monotonic())
        return True

    def get_remaining(self, ip: str) -> int:
        """Return the number of requests *ip* may still make in the current window.

        Args:
            ip: The client IP address string.

        Returns:
            Remaining request allowance (never negative).
        """
        self._evict_old(ip)
        used = len(self._requests[ip])
        return max(0, _IP_MAX_REQUESTS - used)


# ---------------------------------------------------------------------------
# 3. BatchHandler
# ---------------------------------------------------------------------------


class BatchHandler:
    """Helper for bundling multiple Graph API requests into a single batch call.

    Meta's Batch API allows up to 50 requests per HTTP call, dramatically
    reducing network overhead when many operations need to be performed
    sequentially.

    Reference:
        https://developers.facebook.com/docs/graph-api/batch-requests/
    """

    async def batch_requests(
        self,
        requests: list[dict[str, Any]],
        token: str,
        max_batch: int = _MAX_BATCH_SIZE,
    ) -> list[Any]:
        """Execute *requests* as one or more Meta batch API calls.

        Each item in *requests* should be a dict with at minimum a ``method``
        key (``"GET"``, ``"POST"``, etc.) and a ``relative_url`` key.  Optional
        keys mirror the Meta Batch API spec (``body``, ``name``, ``depends_on``,
        etc.).

        The list is automatically split into chunks of *max_batch* items
        (≤ 50), and each chunk is sent as a single HTTP POST.  Results from all
        chunks are concatenated and returned in order.

        Args:
            requests: A list of request descriptor dicts following the Meta
                Batch API format.
            token: A valid Meta access token used to authenticate the batch
                call.
            max_batch: Maximum number of sub-requests per batch HTTP call.
                Defaults to ``50`` (Meta's hard limit).

        Returns:
            A flat list of response objects (as parsed JSON) in the same order
            as *requests*.  Entries may be dicts (from Meta) or ``None`` if a
            particular batch slot returned no parseable response.

        Raises:
            httpx.HTTPStatusError: If the batch HTTP request itself returns a
                non-2xx status code.
            httpx.RequestError: If a network-level error occurs.
        """
        if not requests:
            return []

        results: list[Any] = []

        # Split into chunks respecting the Meta 50-request limit.
        chunks = [
            requests[i : i + max_batch] for i in range(0, len(requests), max_batch)
        ]

        async with httpx.AsyncClient(timeout=60.0) as client:
            for chunk_index, chunk in enumerate(chunks):
                import json as _json

                batch_payload = _json.dumps(chunk)
                logger.debug(
                    "Sending batch chunk %d/%d with %d sub-requests.",
                    chunk_index + 1,
                    len(chunks),
                    len(chunk),
                )

                response = await client.post(
                    _META_BATCH_URL,
                    data={
                        "access_token": token,
                        "batch": batch_payload,
                        "include_headers": "false",
                    },
                )
                response.raise_for_status()

                chunk_results: list[Any] = response.json()

                # Parse each sub-response body from its JSON string.
                for item in chunk_results:
                    if item is None:
                        results.append(None)
                        continue

                    body = item.get("body")
                    if body:
                        try:
                            results.append(_json.loads(body))
                        except (_json.JSONDecodeError, TypeError):
                            results.append(item)
                    else:
                        results.append(item)

        logger.debug(
            "Batch API completed: %d total sub-requests, %d chunks.",
            len(requests),
            len(chunks),
        )
        return results


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

api_tracker: ApiCallTracker = ApiCallTracker()
"""Singleton :class:`ApiCallTracker` — import and use throughout the app."""

rate_limiter: RateLimiter = RateLimiter()
"""Singleton :class:`RateLimiter` — import and use throughout the app."""
