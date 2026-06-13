"""
media_bridge.py — Zero-disk Google Drive → Meta media pipeline.

The app must never accumulate posted files on its (ephemeral) disk. This module
streams media straight from Google Drive into Meta:

* For Facebook Page photos and Meta Ads images/videos, Meta accepts the raw
  bytes (multipart upload). We pull the bytes from Drive into memory, push them
  to Meta, and discard them immediately — nothing is written to disk.

* For Instagram, Meta's publishing API only accepts a *public URL it fetches
  itself*. We mint a short-lived token (stored in the DB so it works across
  multiple server workers) that points at a Drive file id + the Google account
  that can read it — never the access token itself. The ``/media/{token}``
  endpoint resolves a fresh Google token at fetch time and streams the bytes
  through on demand. Meta fetches it once; the token expires on its own. Still
  nothing on disk, and no secret stored.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Optional

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import MediaProxyToken
# Read-only-guarded httpx client: Drive access here is download-only, and this
# enforces (alongside the read-only OAuth scopes) that nothing can ever delete
# or modify the user's Drive even through the streaming download path.
from google_api import _ro_client

logger = logging.getLogger("uplinx")

# How long a media proxy token stays valid. Meta fetches IG media within
# seconds, but we allow a generous window for retries / slow fetches / video
# processing.
TOKEN_TTL_SECONDS = 1800  # 30 minutes

GOOGLE_DRIVE_BASE = "https://www.googleapis.com/drive/v3"


async def mint_media_token(
    db: AsyncSession,
    drive_file_id: str,
    google_user_id: str,
    mime_type: str = "application/octet-stream",
    filename: str = "media",
    ttl_seconds: int = TOKEN_TTL_SECONDS,
) -> str:
    """Register a Drive file for public proxy access and return an opaque token."""
    token = secrets.token_urlsafe(24)
    row = MediaProxyToken(
        token=token,
        drive_file_id=drive_file_id,
        google_user_id=google_user_id or "",
        mime_type=mime_type or "application/octet-stream",
        filename=filename or "media",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
    )
    db.add(row)
    await db.flush()
    return token


async def resolve_media_token(db: AsyncSession, token: str) -> Optional[MediaProxyToken]:
    """Return the mapping for a token, or None if missing/expired."""
    row = await db.get(MediaProxyToken, token)
    if row is None:
        return None
    expires_at = row.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at is not None and expires_at < datetime.now(timezone.utc):
        return None
    return row


async def revoke_media_token(db: AsyncSession, token: str) -> None:
    """Explicitly drop a token (e.g. once publishing is confirmed)."""
    await db.execute(delete(MediaProxyToken).where(MediaProxyToken.token == token))


async def purge_expired_tokens(db: AsyncSession) -> int:
    """Delete expired tokens so the table never grows unbounded. Returns count."""
    result = await db.execute(
        delete(MediaProxyToken).where(
            MediaProxyToken.expires_at < datetime.now(timezone.utc)
        )
    )
    return result.rowcount or 0


async def open_drive_stream(
    drive_file_id: str, google_token: str, chunk_size: int = 256 * 1024
) -> tuple[int, Optional[AsyncIterator[bytes]], Optional[int]]:
    """Open a Drive download and verify the status BEFORE any bytes flow.

    ``stream_drive_file`` raises inside the generator — by then Starlette has
    already sent ``200 OK`` headers, so a Drive 401/404 reached Meta as a 200
    with a broken body and an opaque "media fetch" error. This variant lets
    the ``/media/{token}`` endpoint return a real 502 instead.

    Returns ``(status_code, body_iterator, content_length)``; the iterator is
    ``None`` when Drive answered with an error (connection already closed in
    that case). ``content_length`` is taken from Drive's response headers so
    the proxy can forward it — Meta's media fetcher rejects chunked responses
    without a Content-Length.
    """
    url = f"{GOOGLE_DRIVE_BASE}/files/{drive_file_id}"
    headers = {"Authorization": f"Bearer {google_token}"}
    client = _ro_client(timeout=None)
    try:
        req = client.build_request("GET", url, headers=headers, params={"alt": "media"})
        response = await client.send(req, stream=True)
    except Exception:
        await client.aclose()
        raise
    if response.status_code != 200:
        await response.aclose()
        await client.aclose()
        return response.status_code, None, None

    content_length: Optional[int] = None
    try:
        cl = response.headers.get("content-length")
        if cl:
            content_length = int(cl)
    except Exception:
        pass

    async def _body() -> AsyncIterator[bytes]:
        try:
            async for chunk in response.aiter_bytes(chunk_size):
                yield chunk
        finally:
            await response.aclose()
            await client.aclose()

    return response.status_code, _body(), content_length


async def stream_drive_file(
    drive_file_id: str, google_token: str, chunk_size: int = 256 * 1024
) -> AsyncIterator[bytes]:
    """Yield a Drive file's bytes in chunks without buffering the whole file.

    Used by the public ``/media/{token}`` proxy so large videos never have to
    sit in memory (let alone on disk) in their entirety.
    """
    url = f"{GOOGLE_DRIVE_BASE}/files/{drive_file_id}"
    headers = {"Authorization": f"Bearer {google_token}"}
    async with _ro_client(timeout=None) as client:
        async with client.stream(
            "GET", url, headers=headers, params={"alt": "media"}
        ) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes(chunk_size):
                yield chunk
