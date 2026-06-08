"""
media_bridge.py — Zero-disk Google Drive → Meta media pipeline.

The app must never accumulate posted files on its (ephemeral) disk. This module
streams media straight from Google Drive into Meta:

* For Facebook Page photos and Meta Ads images/videos, Meta accepts the raw
  bytes (multipart upload). We pull the bytes from Drive into memory, push them
  to Meta, and discard them immediately — nothing is written to disk.

* For Instagram, Meta's publishing API only accepts a *public URL it fetches
  itself*. We expose a short-lived, tokenised proxy endpoint (``/media/{token}``)
  that streams the Drive file through on demand. Meta fetches it once, then the
  token expires. Still nothing on disk.

The ephemeral token store is in-memory (single-worker deployment). Tokens are
short-lived because Meta fetches IG media within seconds of container creation.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import httpx

logger = logging.getLogger("uplinx")

# How long a media proxy token stays valid (seconds). Meta fetches IG media
# within seconds, but we allow a generous window for retries / slow fetches.
TOKEN_TTL_SECONDS = 1800  # 30 minutes

GOOGLE_DRIVE_BASE = "https://www.googleapis.com/drive/v3"


@dataclass
class _MediaToken:
    drive_file_id: str
    google_token: str
    mime_type: str
    filename: str
    expires_at: float


# token -> _MediaToken
_TOKEN_STORE: dict[str, _MediaToken] = {}


def _purge_expired() -> None:
    """Drop expired tokens so the in-memory store never grows unbounded."""
    now = time.time()
    expired = [t for t, m in _TOKEN_STORE.items() if m.expires_at < now]
    for t in expired:
        _TOKEN_STORE.pop(t, None)


def mint_media_token(
    drive_file_id: str,
    google_token: str,
    mime_type: str = "application/octet-stream",
    filename: str = "media",
    ttl_seconds: int = TOKEN_TTL_SECONDS,
) -> str:
    """Register a Drive file for public proxy access and return an opaque token."""
    _purge_expired()
    token = secrets.token_urlsafe(24)
    _TOKEN_STORE[token] = _MediaToken(
        drive_file_id=drive_file_id,
        google_token=google_token,
        mime_type=mime_type or "application/octet-stream",
        filename=filename or "media",
        expires_at=time.time() + ttl_seconds,
    )
    return token


def resolve_media_token(token: str) -> Optional[_MediaToken]:
    """Return the mapping for a token, or None if missing/expired."""
    _purge_expired()
    m = _TOKEN_STORE.get(token)
    if m is None:
        return None
    if m.expires_at < time.time():
        _TOKEN_STORE.pop(token, None)
        return None
    return m


def revoke_media_token(token: str) -> None:
    """Explicitly drop a token (e.g. once publishing is confirmed)."""
    _TOKEN_STORE.pop(token, None)


async def stream_drive_file(
    drive_file_id: str, google_token: str, chunk_size: int = 256 * 1024
) -> AsyncIterator[bytes]:
    """Yield a Drive file's bytes in chunks without buffering the whole file.

    Used by the public ``/media/{token}`` proxy so large videos never have to
    sit in memory (let alone on disk) in their entirety.
    """
    url = f"{GOOGLE_DRIVE_BASE}/files/{drive_file_id}"
    headers = {"Authorization": f"Bearer {google_token}"}
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream(
            "GET", url, headers=headers, params={"alt": "media"}
        ) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes(chunk_size):
                yield chunk

