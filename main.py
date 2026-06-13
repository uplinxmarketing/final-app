"""
Uplinx Meta Manager — FastAPI application.
All routes, OAuth flows, session management, and API endpoints.
"""
import aiofiles
import asyncio
import os
import json
import logging
import hashlib
import re
import secrets
import time
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

from fastapi import FastAPI, Request, Response, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse, FileResponse
from pydantic import BaseModel
from sqlalchemy import select, delete, update, func, or_, and_
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
import base64 as _b64

from database import (
    async_engine,
    init_db, get_db,
    ConnectedMetaAccount, ConnectedGoogleAccount, ConnectedPostingAccount,
    MetaApp,
    Client, ClientAdAccount, ClientInstagramAccount, ClientPostingProfile,
    Conversation, Message, ActiveContext,
    Skill, QuickCommand, ScheduledPost, ImageCache,
    User, UserPageAssignment, UserClientAssignment,
    PublishJob, BusinessPortfolio,
    UserApiUsage, bump_user_usage,
    PostingEventLog, log_posting_event,
)
from security import (
    FernetEncryption, setup_logging,
    generate_oauth_state, verify_oauth_state,
    create_session_token, verify_session_token,
    sanitize_text, validate_file_extension,
    validate_mime_type, sanitize_filename
)
import meta_api
import google_api
import media_bridge
from file_processor import process_uploaded_file, cleanup_old_uploads
from skills_manager import (
    initialize_default_skills, initialize_default_quick_commands,
    get_all_skills, create_skill, update_skill,
    toggle_skill, delete_skill, get_quick_commands, create_quick_command
)
from claude_agent import ClaudeAgent, invalidate_account_cache, invalidate_system_prompt, _system_prompt_cache
from rate_limiter import api_tracker
from admin_router import router as admin_router, init_admin_db

logger = setup_logging()
encryption = FernetEncryption()
agent = ClaudeAgent()

# Unique id for this worker process — used to atomically claim queued work so
# that with multiple server workers the same post/job is never processed twice.
WORKER_ID = secrets.token_hex(4)

# Configurable upload directory — override via UPLOADS_DIR env var.
_UPLOAD_DIR = Path(settings.UPLOADS_DIR)

# ── Password helpers ───────────────────────────────────────────────────────────

def _hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:260000${salt}${_b64.b64encode(dk).decode()}"


def _verify_password(pw: str, hashed: str) -> bool:
    try:
        _, rest = hashed.split("pbkdf2:sha256:", 1)
        iters_s, salt, dk_b64 = rest.split("$")
        dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), int(iters_s))
        return secrets.compare_digest(_b64.b64decode(dk_b64), dk)
    except Exception:
        return False

# ── Lifespan ──────────────────────────────────────────────────────────────────

_bg_tasks: list[asyncio.Task] = []

async def _load_settings_from_db() -> None:
    """Reload persisted API keys / config from the DB into the live settings.

    On Render (ephemeral filesystem) the .env file is wiped on every redeploy,
    so the DB is the durable source of truth. Values already present in the
    environment / .env take precedence (env vars set in the Render dashboard
    should win), so we only fill in keys that are currently empty.
    """
    try:
        from database import load_app_settings
        async for db in get_db():
            stored = await load_app_settings(db)
            break
    except Exception as exc:
        logger.error(f"Could not load settings from DB: {exc}")
        return
    if not stored:
        return
    applied = []
    for key, value in stored.items():
        if not value:
            continue
        # Don't override a value already provided via the environment / .env.
        current = getattr(settings, key, "")
        if current:
            continue
        if hasattr(settings, key):
            setattr(settings, key, value)
            applied.append(key)
    if applied:
        logger.info("Loaded %d setting(s) from DB: %s", len(applied), ", ".join(applied))
        try:
            agent._init_client()
        except Exception as exc:
            logger.warning("Could not re-init agent after DB settings load: %s", exc)


async def _deferred_startup() -> None:
    """All seeding and CRM init — runs in background 3s after server starts."""
    await asyncio.sleep(3)
    try:
        async for db in get_db():
            try:
                await initialize_default_skills(db)
                await initialize_default_quick_commands(db)
            except Exception as _e:
                logger.error(f"Skills seed error: {_e}")
            if settings.META_APP_ID:
                _r = await db.execute(select(MetaApp).where(MetaApp.app_id == settings.META_APP_ID, MetaApp.app_type == "ads").limit(1))
                if not _r.scalar_one_or_none():
                    db.add(MetaApp(name="Default Ads App", app_type="ads", app_id=settings.META_APP_ID,
                                   encrypted_app_secret=encryption.encrypt(settings.META_APP_SECRET or "placeholder"), sort_order=0))
            if settings.META_POSTING_APP_ID:
                _r = await db.execute(select(MetaApp).where(MetaApp.app_id == settings.META_POSTING_APP_ID, MetaApp.app_type == "posting").limit(1))
                if not _r.scalar_one_or_none():
                    db.add(MetaApp(name="Default Posting App", app_type="posting", app_id=settings.META_POSTING_APP_ID,
                                   encrypted_app_secret=encryption.encrypt(settings.META_POSTING_APP_SECRET or "placeholder"), sort_order=0))
            await db.commit()
            break
    except Exception as _e:
        logger.error(f"MetaApp seed error: {_e}")
    try:
        async for db in get_db():
            res = await db.execute(select(User).where(User.username == "admin").limit(1))
            admin_user = res.scalar_one_or_none()
            if settings.ADMIN_PASSWORD:
                if admin_user:
                    admin_user.hashed_password = _hash_password(settings.ADMIN_PASSWORD)
                    admin_user.is_active = True
                    admin_user.role = "admin"
                    if settings.ADMIN_EMAIL:
                        admin_user.email = settings.ADMIN_EMAIL
                    await db.commit()
                else:
                    db.add(User(username="admin", email=settings.ADMIN_EMAIL or None,
                                hashed_password=_hash_password(settings.ADMIN_PASSWORD),
                                role="admin", interface_access="both", is_active=True))
                    await db.commit()
            elif not admin_user:
                pw = settings.LOGIN_PASSWORD or secrets.token_urlsafe(16)
                db.add(User(username="admin", hashed_password=_hash_password(pw),
                            role="admin", interface_access="both", is_active=True))
                await db.commit()
            break
    except Exception as _e:
        logger.error(f"User seed error: {_e}")
    try:
        await init_admin_db(async_engine)
    except Exception as _e:
        logger.error(f"CRM admin DB init error: {_e}")
    logger.info("Deferred startup complete.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure upload directory exists (supports custom UPLOADS_DIR path)
    try:
        _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as _exc:
        logger.warning(f"Could not create uploads dir {_UPLOAD_DIR}: {_exc}")
    try:
        await init_db()
    except Exception as _exc:
        logger.error(f"init_db error (non-fatal): {type(_exc).__name__}: {_exc}")
    try:
        await _recover_stale_jobs()
    except Exception as _exc:
        logger.error(f"stale job recovery error (non-fatal): {_exc}")
    try:
        await _restore_scheduled_from_checkpoint()
    except Exception as _exc:
        logger.error(f"checkpoint restore error (non-fatal): {_exc}")
    # Restore persisted API keys from the DB before serving requests, so the AI
    # agent works immediately after a redeploy (Render wipes the .env file).
    try:
        await _load_settings_from_db()
    except Exception as _exc:
        logger.error(f"settings reload error (non-fatal): {type(_exc).__name__}: {_exc}")
    _bg_tasks.append(asyncio.create_task(_deferred_startup()))
    _bg_tasks.append(asyncio.create_task(_cleanup_uploads_loop()))
    _bg_tasks.append(asyncio.create_task(_token_refresh_loop()))
    _bg_tasks.append(asyncio.create_task(_scheduled_posts_loop()))
    _bg_tasks.append(asyncio.create_task(_publish_jobs_loop()))
    _bg_tasks.append(asyncio.create_task(_scheduled_posts_checkpoint_loop()))
    _bg_tasks.append(asyncio.create_task(_drive_precache_loop()))
    logger.info("Uplinx Meta Manager started")
    yield
    for task in _bg_tasks:
        task.cancel()
    logger.info("Uplinx Meta Manager stopped")

async def _protected_upload_ids() -> set | None:
    """Local upload file ids still referenced by posts that have NOT been
    confirmed published — these must survive the periodic purge.

    Protected statuses:
      - ScheduledPost: pending / processing (waiting or mid-publish), and
        failed (the user can re-queue from the UI — media must still exist).
      - PublishJob: queued / running, and recently failed (retryable).

    Returns ``None`` if the scan itself failed — callers must treat that as
    "unknown" and SKIP the purge entirely rather than delete blindly.
    """
    ids: set = set()
    try:
        async for db in get_db():
            result = await db.execute(
                select(ScheduledPost.job_data).where(
                    ScheduledPost.status.in_(("pending", "processing", "failed"))
                )
            )
            for jd in result.scalars().all():
                for m in (jd or {}).get("media", []):
                    if m.get("local_file_id"):
                        ids.add(m["local_file_id"])
                    if m.get("cache_file_id"):
                        ids.add(m["cache_file_id"])
            recent = datetime.now(timezone.utc) - timedelta(days=7)
            result = await db.execute(
                select(PublishJob.items).where(
                    or_(
                        PublishJob.status.in_(("queued", "running")),
                        and_(PublishJob.status == "failed", PublishJob.created_at >= recent),
                    )
                )
            )
            for items in result.scalars().all():
                for it in (items or []):
                    for m in (it or {}).get("media", []):
                        if m.get("local_file_id"):
                            ids.add(m["local_file_id"])
                        if m.get("cache_file_id"):
                            ids.add(m["cache_file_id"])
            break
    except Exception as exc:
        logger.warning("Protected uploads scan error — purge will be skipped: %s", exc)
        return None
    return ids


async def _cleanup_uploads_loop() -> None:
    while True:
        await asyncio.sleep(3600)
        try:
            keep = await _protected_upload_ids()
            if keep is None:
                # Could not determine which files are still needed — deleting
                # anything now could destroy media for unpublished posts.
                logger.warning("Skipping upload purge: protected-file scan failed")
                continue
            count = await cleanup_old_uploads(settings.AUTO_CLEAR_UPLOADS_HOURS, keep_ids=keep)
            if count:
                logger.info("Auto-cleaned %d upload(s), kept %d scheduled-post file(s)", count, len(keep))
        except Exception as exc:
            logger.warning("Upload cleanup error: %s", exc)

async def _token_refresh_loop() -> None:
    """Check for Meta tokens expiring within 7 days and attempt refresh."""
    while True:
        await asyncio.sleep(3600)
        try:
            async for db in get_db():
                threshold = datetime.utcnow() + timedelta(days=7)
                for model in (ConnectedMetaAccount, ConnectedPostingAccount):
                    # Posting-account tokens were issued by the Posting app —
                    # fb_exchange_token rejects a token from a different app,
                    # so refreshing them with the Ads app credentials silently
                    # failed every hour and the tokens eventually expired.
                    if model is ConnectedPostingAccount and settings.META_POSTING_APP_ID:
                        app_id, app_secret = settings.META_POSTING_APP_ID, settings.META_POSTING_APP_SECRET
                    else:
                        app_id, app_secret = settings.META_APP_ID, settings.META_APP_SECRET
                    result = await db.execute(
                        select(model).where(
                            model.is_active == True,
                            model.token_expiry <= threshold,
                        )
                    )
                    accounts = result.scalars().all()
                    for acc in accounts:
                        # Per-account isolation: one corrupted row (e.g. a
                        # re-keyed encryption value) must not abort the rest
                        # of the accounts or the Google block below.
                        try:
                            token = encryption.decrypt(acc.encrypted_long_token)
                            refresh = await meta_api.exchange_for_long_lived_token(
                                token, app_id, app_secret
                            )
                            if refresh.get("success") and refresh.get("data", {}).get("access_token"):
                                new_token = refresh["data"]["access_token"]
                                acc.encrypted_long_token = encryption.encrypt(new_token)
                                expiry_days = refresh["data"].get("expires_in", 5184000) // 86400
                                acc.token_expiry = datetime.utcnow() + timedelta(days=expiry_days)
                                await db.commit()
                                logger.info("Refreshed token for %s", acc.facebook_user_id)
                            else:
                                _ref_err = refresh.get("error", "unknown error")
                                logger.warning("Meta token refresh failed for %s: %s",
                                               acc.facebook_user_id, _ref_err)
                                await log_posting_event(db, "token_error",
                                    f"Meta posting token refresh failed for {acc.user_name or acc.facebook_user_id}",
                                    level="warning", platform="facebook",
                                    detail=str(_ref_err)[:500])
                        except Exception as acc_exc:
                            logger.warning("Meta token refresh error for %s: %s",
                                           getattr(acc, "facebook_user_id", "?"), acc_exc)
                            try:
                                await log_posting_event(db, "token_error",
                                    f"Meta posting token error for {getattr(acc, 'facebook_user_id', '?')}",
                                    level="error", platform="facebook", detail=str(acc_exc)[:500])
                            except Exception:
                                pass
                # Google: access tokens last 1h — refresh proactively when
                # expiring within 10 min so Drive media never 401s mid-publish,
                # and the refresh token stays in active use (Google revokes
                # refresh tokens left unused for ~6 months).
                try:
                    g_threshold = datetime.utcnow() + timedelta(minutes=10)
                    result = await db.execute(
                        select(ConnectedGoogleAccount).where(
                            ConnectedGoogleAccount.is_active == True,
                            ConnectedGoogleAccount.token_expiry <= g_threshold,
                        )
                    )
                    for gacc in result.scalars().all():
                        if not gacc.encrypted_refresh_token:
                            continue
                        try:
                            refresh = await google_api.refresh_access_token(
                                encryption.decrypt(gacc.encrypted_refresh_token),
                                settings.GOOGLE_CLIENT_ID,
                                settings.GOOGLE_CLIENT_SECRET,
                            )
                            if refresh.get("success"):
                                gacc.encrypted_access_token = encryption.encrypt(refresh["access_token"])
                                gacc.token_expiry = datetime.utcnow() + timedelta(seconds=refresh.get("expires_in", 3600))
                                await db.commit()
                                logger.info("Refreshed Google token for %s", gacc.user_email or gacc.google_user_id)
                            else:
                                _g_err = refresh.get("error", "unknown error")
                                logger.warning("Google token refresh failed for %s: %s",
                                               gacc.user_email or gacc.google_user_id, _g_err)
                                await log_posting_event(db, "token_error",
                                    f"Google token refresh failed for {gacc.user_email or gacc.google_user_id}",
                                    level="warning", platform="google", detail=str(_g_err)[:500])
                        except Exception as g_exc:
                            logger.warning("Google token refresh error for %s: %s",
                                           gacc.user_email or gacc.google_user_id, g_exc)
                            try:
                                await log_posting_event(db, "token_error",
                                    f"Google token error for {gacc.user_email or gacc.google_user_id}",
                                    level="error", platform="google", detail=str(g_exc)[:500])
                            except Exception:
                                pass
                except Exception as gblock_exc:
                    logger.warning("Google token refresh block error: %s", gblock_exc)
        except Exception as exc:
            logger.warning("Token refresh loop error: %s", exc)


async def _scheduled_posts_loop() -> None:
    """Publish self-scheduled Drive posts (e.g. Instagram) once they're due.

    Instagram has no native scheduling, so future-dated IG posts are queued in
    ``scheduled_posts`` with a ``job_data`` payload. This worker wakes every
    minute, picks up due rows, and publishes them by streaming the media from
    Drive — nothing is written to disk.
    """
    # One-time repair: posts that exhausted their retries because of the
    # pre-r194 null-posting_user_id bug get returned to the queue — the token
    # lookup now falls back to the active account, so they can publish.
    try:
        async for db in get_db():
            res = await db.execute(
                update(ScheduledPost)
                .where(
                    ScheduledPost.status == "failed",
                    ScheduledPost.error_message.like("%no posting account%"),
                )
                .values(status="pending", attempts=0, error_message=None,
                        claimed_by=None, claimed_at=None)
            )
            await db.commit()
            if res.rowcount:
                logger.info("Re-queued %d scheduled post(s) failed by the null posting account bug", res.rowcount)
            break
    except Exception as exc:
        logger.warning("Scheduled posts repair error: %s", exc)

    while True:
        await asyncio.sleep(60)
        try:
            async for db in get_db():
                now = datetime.now(timezone.utc)
                result = await db.execute(
                    select(ScheduledPost.id).where(
                        ScheduledPost.status == "pending",
                        ScheduledPost.job_data.isnot(None),
                        ScheduledPost.scheduled_time <= now,
                        or_(
                            ScheduledPost.next_retry_at.is_(None),
                            ScheduledPost.next_retry_at <= now,
                        ),
                    ).limit(10)
                )
                due_ids = list(result.scalars().all())
                for pid in due_ids:
                    # Atomically claim the row: only the worker whose UPDATE flips
                    # status pending→processing gets to publish it. This is safe
                    # across multiple workers (single-statement atomic update).
                    claim = await db.execute(
                        update(ScheduledPost)
                        .where(ScheduledPost.id == pid, ScheduledPost.status == "pending")
                        .values(status="processing", claimed_by=WORKER_ID, claimed_at=now)
                    )
                    await db.commit()
                    if claim.rowcount != 1:
                        continue  # another worker claimed it first
                    post = await db.get(ScheduledPost, pid)
                    if post is not None:
                        await _execute_scheduled_job(post, db)
                # Self-heal: requeue posts stuck in "processing" for >15 min
                # (their worker died mid-publish). Startup recovery alone isn't
                # enough — a long-lived server never re-runs it.
                try:
                    stale_cutoff = now - timedelta(minutes=15)
                    healed = await db.execute(
                        update(ScheduledPost)
                        .where(ScheduledPost.status == "processing",
                               or_(ScheduledPost.claimed_at.is_(None),
                                   ScheduledPost.claimed_at < stale_cutoff))
                        .values(status="pending", claimed_by=None, claimed_at=None)
                    )
                    await db.commit()
                    if healed.rowcount:
                        logger.warning("Requeued %d stuck scheduled post(s)", healed.rowcount)
                except Exception:
                    pass
                # Housekeeping: drop expired media-proxy tokens.
                try:
                    await media_bridge.purge_expired_tokens(db)
                    await db.commit()
                except Exception:
                    pass
                break
        except Exception as exc:
            logger.warning("Scheduled posts loop error: %s", exc)


_RETRY_BACKOFF_SECONDS = [300, 600, 1800, 3600]  # 5m, 10m, 30m, 1h

# Meta transient errors: code 1 = unknown, code 2 = "Please retry your request
# later". These resolve on retry in the vast majority of cases.
_META_TRANSIENT_CODES = {1, 2}


async def _meta_post_retry(
    client: httpx.AsyncClient, url: str, data: dict, retries: int = 4
) -> httpx.Response:
    """POST to the Meta Graph API, retrying transient code-1/2 errors.

    Returns the last response either way — callers keep their existing
    status-code / error-body handling.
    """
    resp: httpx.Response | None = None
    for attempt in range(retries):
        resp = await client.post(url, data=data)
        if resp.status_code in (200, 201):
            return resp
        try:
            code = (resp.json().get("error") or {}).get("code", 0)
        except Exception:
            code = 0
        if code not in _META_TRANSIENT_CODES:
            return resp
        if attempt < retries - 1:
            wait = 5 * (attempt + 1)  # 5s, 10s, 15s
            logger.warning(
                "Meta transient error (code %s) on %s — retry %d/%d in %ds",
                code, url.split("?")[0], attempt + 1, retries - 1, wait,
            )
            await asyncio.sleep(wait)
    return resp


def _classify_meta_error(err_body: dict) -> tuple[str, bool]:
    """Return (human_message, is_rate_limit) from a Meta API error response."""
    err = err_body.get("error", err_body)
    code = err.get("code", 0)
    msg = err.get("message", "Unknown error")
    subcode = err.get("error_subcode", 0)
    # Rate / quota limits
    if code in (4, 17, 32, 341) or subcode in (2446079, 2446085):
        return f"Meta API rate limit reached (code {code}) — the post will be retried automatically.", True
    # Token / auth
    if code == 190:
        return f"Meta access token expired or invalid — reconnect your Facebook account.", False
    # Missing permission
    if code in (10, 200, 230, 270):
        return f"Missing Meta permission (code {code}): {msg}", False
    # Scheduled time invalid (caught earlier but just in case)
    if code == 100:
        return f"Meta rejected the post: {msg}", False
    # Unrecognised error: keep the diagnostic identifiers — Meta's generic
    # "An unknown error has occurred" is useless without code/subcode/trace.
    extras = []
    if code:
        extras.append(f"code {code}" + (f"/{subcode}" if subcode else ""))
    if err.get("error_user_msg"):
        extras.append(err["error_user_msg"])
    if err.get("fbtrace_id"):
        extras.append(f"fbtrace {err['fbtrace_id']}")
    return (f"{msg} ({'; '.join(extras)})" if extras else msg), False


async def _execute_scheduled_job(post: ScheduledPost, db: AsyncSession) -> None:
    """Publish a single due scheduled post, updating its status in place."""
    job = post.job_data or {}
    post.attempts = (post.attempts or 0) + 1
    try:
        posting_token = await _posting_token_for_uid(job.get("posting_user_id"), db)
        google_uid = job.get("google_user_id")
        # Validate (and refresh) the Google token now so the media proxy can
        # resolve it when Meta fetches — but only when some media item must
        # stream live from Drive. Items with a local upload or a schedule-time
        # disk backup publish fine without any Google account.
        needs_drive = any(
            m.get("drive_file_id") and not m.get("local_file_id")
            and not (m.get("cache_file_id") and (_UPLOAD_DIR / m["cache_file_id"]).exists())
            for m in job.get("media", [])
        )
        if needs_drive:
            await _google_token_for_uid(google_uid, db)
        item = BulkPostItem(
            platform="instagram",
            instagram_id=job.get("instagram_id", ""),
            page_id=job.get("page_id", ""),
            caption=post.caption or "",   # caption already includes hashtags
            hashtags=[],
            media=[DriveMediaItem(**m) for m in job.get("media", [])],
            media_type=job.get("media_type", "IMAGE"),
        )
        # Always prefer the live BASE_URL setting over the URL recorded at
        # schedule time; the server may have redeployed with a different domain.
        base_url = _effective_base_url() or job.get("base_url", "")
        r = await _publish_instagram_drive(item, posting_token, google_uid, base_url, db)
        if r.get("success"):
            post.status = "published"
            post.meta_post_id = r.get("media_id")
            post.published_at = datetime.now(timezone.utc)
            post.error_message = None
            post.next_retry_at = None
            # Publish confirmed by Meta — the disk backups of this post's
            # Drive media are no longer needed.
            _purge_drive_cache(job)
            await log_posting_event(db, "publish_ok", f"Scheduled post #{post.id} published successfully",
                level="info", platform=post.platform or "instagram",
                page_id=job.get("page_id",""), post_id=post.id,
                detail=f"meta_post_id={r.get('media_id')} attempts={post.attempts}")
        else:
            raise RuntimeError(r.get("error", "publish failed"))
    except Exception as exc:
        err_str = str(exc)
        post.error_message = err_str[:500]
        max_attempts = 5
        if post.attempts >= max_attempts:
            post.status = "failed"
            post.claimed_by = None
            post.claimed_at = None
            post.next_retry_at = None
            await log_posting_event(db, "publish_fail", f"Scheduled post #{post.id} permanently failed after {post.attempts} attempts",
                level="error", platform=post.platform or "instagram",
                page_id=job.get("page_id",""), post_id=post.id, detail=err_str[:2000])
        else:
            delay = _RETRY_BACKOFF_SECONDS[min(post.attempts - 1, len(_RETRY_BACKOFF_SECONDS) - 1)]
            post.status = "pending"
            post.claimed_by = None
            post.claimed_at = None
            post.next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
            await log_posting_event(db, "publish_fail", f"Scheduled post #{post.id} failed (attempt {post.attempts}/{max_attempts}), retrying in {delay//60}m",
                level="warning", platform=post.platform or "instagram",
                page_id=job.get("page_id",""), post_id=post.id, detail=err_str[:2000])
        logger.warning("Scheduled post %s attempt %d failed: %s", post.id, post.attempts, exc)
    try:
        await db.commit()
    except Exception:
        # The publish failure may itself have been a DB error that left the
        # session pending-rollback; without this the status/attempts update
        # was lost and the row stayed "processing" with a free retry budget.
        await db.rollback()
        try:
            await db.execute(
                update(ScheduledPost)
                .where(ScheduledPost.id == post.id)
                .values(
                    status=post.status,
                    attempts=post.attempts,
                    error_message=post.error_message,
                    claimed_by=post.claimed_by,
                    claimed_at=post.claimed_at,
                    next_retry_at=post.next_retry_at,
                    meta_post_id=post.meta_post_id,
                    published_at=post.published_at,
                )
            )
            await db.commit()
        except Exception as exc2:
            logger.error("Could not persist scheduled post %s status: %s", post.id, exc2)


async def _posting_token_for_uid(uid: Optional[str], db: AsyncSession) -> str:
    """Fetch a posting account's token by facebook_user_id (no Request needed).

    If uid is provided and that account is logged out / disconnected, we raise
    immediately rather than falling back to a different account — that would
    silently publish a post from the wrong Facebook account.

    The any-active-account fallback is kept only for legacy jobs that have
    no uid recorded at all (pre-r194 null posting_user_id rows).
    """
    acc = None
    if uid:
        result = await db.execute(
            select(ConnectedPostingAccount).where(
                ConnectedPostingAccount.facebook_user_id == uid,
                ConnectedPostingAccount.is_active == True,
            )
        )
        acc = result.scalar_one_or_none()
        if not acc:
            raise RuntimeError(
                f"the Facebook account that placed this post ({uid}) is logged out — "
                "reconnect it to resume scheduled posts"
            )
    else:
        # Legacy job with no uid: fall back to most recent active account.
        result = await db.execute(
            select(ConnectedPostingAccount)
            .where(ConnectedPostingAccount.is_active == True)
            .order_by(ConnectedPostingAccount.id.desc())
        )
        acc = result.scalars().first()
    if not acc:
        raise RuntimeError("no posting account on scheduled job")
    exp = acc.token_expiry
    if exp is not None:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            raise RuntimeError("posting token expired — reconnect to resume scheduled posts")
    return encryption.decrypt(acc.encrypted_long_token)


async def _google_token_for_uid(uid: Optional[str], db: AsyncSession) -> str:
    """Fetch (refreshing if needed) a Google account's token by google_user_id.

    Falls back to any active Google account when the recorded uid is missing
    or its account was replaced — a scheduled post must not fail because
    someone reconnected Drive with a different Google login in the meantime.
    """
    acc = None
    if uid:
        result = await db.execute(
            select(ConnectedGoogleAccount).where(
                ConnectedGoogleAccount.google_user_id == uid,
                ConnectedGoogleAccount.is_active == True,
            )
        )
        acc = result.scalar_one_or_none()
    if not acc:
        result = await db.execute(
            select(ConnectedGoogleAccount)
            .where(ConnectedGoogleAccount.is_active == True)
            .order_by(ConnectedGoogleAccount.id.desc())
        )
        acc = result.scalars().first()
    if not acc:
        raise RuntimeError("No connected Google account — reconnect Drive to resume scheduled posts")
    exp = acc.token_expiry
    expired = False
    if exp is not None:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        expired = exp < datetime.now(timezone.utc)
    if expired:
        refresh = await google_api.refresh_access_token(
            encryption.decrypt(acc.encrypted_refresh_token),
            settings.GOOGLE_CLIENT_ID,
            settings.GOOGLE_CLIENT_SECRET,
        )
        if not refresh.get("success"):
            raise RuntimeError("Google token expired — reconnect to resume scheduled posts")
        acc.encrypted_access_token = encryption.encrypt(refresh["access_token"])
        acc.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=refresh.get("expires_in", 3600))
        await db.commit()
    return encryption.decrypt(acc.encrypted_access_token)


# ── Bulk publish job worker ────────────────────────────────────────────────────

async def _publish_jobs_loop() -> None:
    """Process queued bulk-publish jobs one at a time.

    Wakes frequently, atomically claims the oldest queued job (so with multiple
    workers each job is handled by exactly one), and works through its posts one
    by one — committing progress after every item so all watching frontends see
    live status. Heavy work (video processing, IG polling) is serialised per
    worker, which keeps Meta happy and makes "who has to wait" predictable.
    """
    while True:
        await asyncio.sleep(3)
        try:
            async for db in get_db():
                # Runtime self-heal: requeue jobs stuck "running" for >30 min
                # (their worker died mid-run, or item processing raised before
                # any progress commit). Startup-only recovery isn't enough on
                # a long-lived server — without this a wedged job stays
                # "running" forever and its remaining posts never publish.
                try:
                    stale = datetime.now(timezone.utc) - timedelta(minutes=30)
                    healed = await db.execute(
                        update(PublishJob)
                        .where(PublishJob.status == "running",
                               or_(PublishJob.started_at.is_(None),
                                   PublishJob.started_at < stale))
                        .values(status="queued", claimed_by=None)
                    )
                    await db.commit()
                    if healed.rowcount:
                        logger.warning("Requeued %d stuck publish job(s)", healed.rowcount)
                except Exception:
                    await db.rollback()
                result = await db.execute(
                    select(PublishJob.id)
                    .where(PublishJob.status == "queued")
                    .order_by(PublishJob.created_at)
                    .limit(1)
                )
                jid = result.scalar_one_or_none()
                if jid is None:
                    break
                claim = await db.execute(
                    update(PublishJob)
                    .where(PublishJob.id == jid, PublishJob.status == "queued")
                    .values(status="running", claimed_by=WORKER_ID,
                            started_at=datetime.now(timezone.utc))
                )
                await db.commit()
                if claim.rowcount != 1:
                    break  # another worker grabbed it
                job = await db.get(PublishJob, jid)
                if job is not None:
                    await _process_publish_job(job, db)
                break
        except Exception as exc:
            logger.warning("Publish jobs loop error: %s", exc)


async def _recover_stale_jobs() -> None:
    """On startup, requeue jobs left 'running' by a crashed/restarted worker.

    Safe because items already completed are skipped on resume (we track
    ``completed``). Only touches jobs idle for >15 min to avoid stealing work
    from a live sibling worker.
    """
    try:
        async for db in get_db():
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)
            await db.execute(
                update(PublishJob)
                .where(PublishJob.status == "running",
                       or_(PublishJob.started_at.is_(None), PublishJob.started_at < cutoff))
                .values(status="queued", claimed_by=None)
            )
            # Likewise return any half-claimed scheduled posts to the queue.
            await db.execute(
                update(ScheduledPost)
                .where(ScheduledPost.status == "processing",
                       or_(ScheduledPost.claimed_at.is_(None), ScheduledPost.claimed_at < cutoff))
                .values(status="pending", claimed_by=None, claimed_at=None)
            )
            await db.commit()
            break
    except Exception as exc:
        logger.warning("Stale job recovery error: %s", exc)


_CHECKPOINT_KEY = "scheduled_posts_checkpoint"


def _write_checkpoint_file(payload: str) -> None:
    """Write checkpoint JSON to CHECKPOINT_FILE if configured."""
    path = (settings.CHECKPOINT_FILE or "").strip()
    if not path:
        return
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(payload, encoding="utf-8")
    except Exception as exc:
        logger.debug("Checkpoint file write error (%s): %s", path, exc)


def _read_checkpoint_file() -> str | None:
    """Read checkpoint JSON from CHECKPOINT_FILE if it exists and configured."""
    path = (settings.CHECKPOINT_FILE or "").strip()
    if not path:
        return None
    try:
        p = Path(path)
        if p.exists():
            return p.read_text(encoding="utf-8")
    except Exception as exc:
        logger.debug("Checkpoint file read error (%s): %s", path, exc)
    return None


async def _build_checkpoint_snapshot(db: AsyncSession) -> tuple[list, str]:
    """Return (snapshot list, json payload) of all pending scheduled posts."""
    result = await db.execute(
        select(ScheduledPost).where(
            ScheduledPost.status == "pending",
            ScheduledPost.job_data.isnot(None),
        ).order_by(ScheduledPost.scheduled_time)
    )
    pending = result.scalars().all()
    snapshot = [
        {
            "id": p.id,
            "sched_uid": (p.job_data or {}).get("sched_uid"),
            "platform": p.platform,
            "page_id": p.page_id,
            "instagram_id": p.instagram_id,
            "caption": p.caption or "",
            "media_type": p.media_type,
            "timezone": p.timezone or "UTC",
            "scheduled_time": p.scheduled_time.isoformat(),
            "attempts": p.attempts,
            "job_data": p.job_data,
        }
        for p in pending
    ]
    payload = json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "count": len(snapshot),
        "posts": snapshot,
    })
    return snapshot, payload


async def _save_checkpoint(db: AsyncSession) -> None:
    """Snapshot pending posts to DB AppSetting and (if configured) to a file."""
    from database import AppSetting
    _, payload = await _build_checkpoint_snapshot(db)
    row = await db.get(AppSetting, _CHECKPOINT_KEY)
    if row is None:
        db.add(AppSetting(key=_CHECKPOINT_KEY, value=payload, is_secret=False))
    else:
        row.value = payload
    await db.commit()
    _write_checkpoint_file(payload)


async def _scheduled_posts_checkpoint_loop() -> None:
    """Snapshot pending scheduled posts to DB + optional file every 60s.

    60s interval (vs the old 5m) tightens the loss window when posts are
    pending. Also writes to CHECKPOINT_FILE so posts survive a SQLite wipe
    on server redeploy when that path is on a persistent disk.
    """
    while True:
        await asyncio.sleep(60)
        try:
            async for db in get_db():
                await _save_checkpoint(db)
                break
        except Exception as exc:
            logger.debug("Checkpoint loop error: %s", exc)


async def _restore_scheduled_from_checkpoint() -> None:
    """On startup, re-insert pending scheduled posts that vanished from the table.

    Reads the checkpoint from the DB AppSetting first; if that's empty (e.g.
    after a SQLite wipe), falls back to CHECKPOINT_FILE on disk. Any post in
    the snapshot whose sched_uid is no longer present is re-created as pending.
    Posts whose due time already passed are restored too (published late).
    """
    from database import AppSetting
    try:
        async for db in get_db():
            row = await db.get(AppSetting, _CHECKPOINT_KEY)
            raw_value = (row.value if row else None) or _read_checkpoint_file()
            if not raw_value:
                break
            try:
                data = json.loads(raw_value)
            except Exception:
                break
            posts = data.get("posts") or []
            if not posts:
                break
            result = await db.execute(select(ScheduledPost.job_data))
            existing_uids = {
                (jd or {}).get("sched_uid")
                for jd in result.scalars().all()
                if (jd or {}).get("sched_uid")
            }
            restored = 0
            for s in posts:
                jd = s.get("job_data")
                uid = (jd or {}).get("sched_uid") or s.get("sched_uid")
                # Legacy snapshots (no job_data / no uid) can't be restored safely.
                if not jd or not uid or uid in existing_uids:
                    continue
                try:
                    sched_dt = datetime.fromisoformat(s["scheduled_time"])
                except Exception:
                    continue
                db.add(ScheduledPost(
                    platform=s.get("platform") or "instagram",
                    page_id=s.get("page_id"),
                    instagram_id=s.get("instagram_id"),
                    caption=s.get("caption") or "",
                    media_type=s.get("media_type") or "IMAGE",
                    scheduled_time=sched_dt,
                    timezone=s.get("timezone") or "UTC",
                    status="pending",
                    job_data=jd,
                ))
                restored += 1
            if restored:
                await db.commit()
                logger.warning(
                    "Restored %d scheduled post(s) from checkpoint after table reset", restored
                )
            break
    except Exception as exc:
        logger.warning("Checkpoint restore error: %s", exc)


async def _process_publish_job(job: PublishJob, db: AsyncSession) -> None:
    """Publish every item in a job, one at a time, committing progress as it goes."""
    try:
        items = [BulkPostItem(**it) for it in (job.items or [])]
    except Exception as exc:
        # A malformed item definition must fail the job cleanly — raising here
        # left it claimed as "running" forever (recovery only ran at startup).
        job.status = "failed"
        job.error = f"Invalid job item: {exc}"[:500]
        job.finished_at = datetime.now(timezone.utc)
        await log_posting_event(db, "job_fail", f"Bulk job #{job.id} failed: invalid item definition",
            level="error", job_id=job.id, detail=str(exc)[:2000],
            username=job.created_by_name or job.created_by or "")
        await db.commit()
        return
    results = list(job.results or [])
    # Only require a Google account when some media must stream from Drive —
    # jobs made entirely of device uploads (or disk-cached media) publish fine
    # without one, and must not hard-fail just because Drive is disconnected.
    needs_drive = any(
        m.drive_file_id and not m.local_file_id
        and not (m.cache_file_id and (_UPLOAD_DIR / m.cache_file_id).exists())
        for it in items for m in it.media
    )
    try:
        posting_token = await _posting_token_for_uid(job.posting_user_id, db)
        google_token = await _google_token_for_uid(job.google_user_id, db) if needs_drive else ""
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)[:500]
        job.finished_at = datetime.now(timezone.utc)
        await log_posting_event(db, "token_error", f"Bulk job #{job.id} failed: could not get posting/google token",
            level="error", detail=str(exc)[:2000], job_id=job.id,
            username=job.created_by_name or job.created_by or "")
        await db.commit()
        return

    now = datetime.now(timezone.utc)
    for idx, item in enumerate(items):
        if idx < (job.completed or 0):
            continue  # resume: already done in a previous (interrupted) run
        try:
            scheduled_ts = _parse_scheduled_ts(item.scheduled_time)
            is_future = bool(scheduled_ts and scheduled_ts > int(now.timestamp()) + 60)
            if item.platform == "instagram" and is_future:
                sid = await _schedule_ig_job(
                    item, scheduled_ts, job.posting_user_id, job.google_user_id, job.base_url or "", db
                )
                r = {"success": True, "scheduled": True, "scheduled_id": sid}
            elif item.platform == "facebook":
                r = await _publish_facebook_drive(item, posting_token, google_token)
            elif item.platform == "instagram":
                r = await _publish_instagram_drive(item, posting_token, job.google_user_id, job.base_url or "", db)
            else:
                r = {"success": False, "error": f"Unknown platform: {item.platform}"}
        except Exception as exc:
            logger.exception("Job %s item %d failed", job.id, idx)
            r = {"success": False, "error": str(exc)}

        results.append({"index": idx, **r})
        job.results = list(results)   # new list object so the JSON column is marked dirty
        job.completed = idx + 1
        _page_id = getattr(item, "page_id", "") or getattr(item, "instagram_id", "") or ""
        if r.get("success"):
            job.succeeded = (job.succeeded or 0) + 1
            if r.get("scheduled"):
                job.scheduled_count = (job.scheduled_count or 0) + 1
                await log_posting_event(db, "schedule_ok",
                    f"Job #{job.id} item {idx+1}: {item.platform} post scheduled",
                    level="info", platform=item.platform, page_id=_page_id,
                    post_id=r.get("scheduled_id"), job_id=job.id,
                    username=job.created_by_name or job.created_by or "")
            else:
                await log_posting_event(db, "publish_ok",
                    f"Job #{job.id} item {idx+1}: {item.platform} post published",
                    level="info", platform=item.platform, page_id=_page_id,
                    job_id=job.id, username=job.created_by_name or job.created_by or "")
        else:
            job.failed = (job.failed or 0) + 1
            await log_posting_event(db, "publish_fail",
                f"Job #{job.id} item {idx+1}: {item.platform} post failed",
                level="error", platform=item.platform, page_id=_page_id,
                job_id=job.id, username=job.created_by_name or job.created_by or "",
                detail=r.get("error","")[:2000])
        await db.commit()  # progress is now visible to every poller

    job.status = "done"
    job.finished_at = datetime.now(timezone.utc)
    await log_posting_event(db, "job_ok" if not job.failed else "job_fail",
        f"Bulk job #{job.id} complete: {job.succeeded} ok, {job.failed} failed, {job.scheduled_count} scheduled",
        level="info" if not job.failed else "warning", job_id=job.id,
        username=job.created_by_name or job.created_by or "")
    await db.commit()

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Uplinx Meta Manager", version="1.0.0", lifespan=lifespan)
app.include_router(admin_router)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ── Session helpers ────────────────────────────────────────────────────────────

SESSION_COOKIE = "uplinx_session"
LOGIN_COOKIE = "uplinx_login"
PUBLIC_PATHS = {"/health", "/", "/ads", "/auth/meta", "/auth/meta/callback",
                "/auth/meta/posting", "/auth/meta/posting/callback",
                "/auth/google", "/auth/google/callback", "/auth/done", "/setup",
                "/api/accounts/meta/token", "/api/accounts/posting/token",
                "/login", "/api/login", "/api/logout",
                "/api/auth/login", "/api/auth/logout", "/api/auth/me",
                "/api/auth/emergency-reset", "/api/posting/debug", "/privacy"}


def _login_token() -> str:
    return hashlib.sha256(
        f"{settings.LOGIN_PASSWORD}:{settings.SECRET_KEY}".encode()
    ).hexdigest()


def _session_cookie_max_age(session_data: dict) -> int:
    """Cookie lifetime matching the session's remember-me flag.

    OAuth callbacks re-issue the session cookie; without this a remember-me
    user who connected an account had their 30-day cookie clobbered down to 8h.
    """
    return 86400 * 30 if session_data.get("_remember") else 28800

@app.middleware("http")
async def session_middleware(request: Request, call_next):
    if (request.url.path in PUBLIC_PATHS
            or request.url.path.startswith("/static")
            or request.url.path.startswith("/frontend")
            or request.url.path.startswith("/media/")    # public media proxy (Meta fetches IG media)
            or request.url.path.startswith("/admin")    # admin has its own auth
            or request.url.path.startswith("/api/setup")
            or request.url.path.startswith("/api/auth/")):   # all auth endpoints are public
        return await call_next(request)

    token = request.cookies.get(SESSION_COOKIE)
    session = verify_session_token(token) if token else None
    if session is None:
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "Not authenticated"}, status_code=401)
        return RedirectResponse("/")

    request.state.session = session
    return await call_next(request)


@app.middleware("http")
async def login_guard(request: Request, call_next):
    # The new per-user auth system uses /api/auth/* — always allow those through
    # so both normal users and admins can log in regardless of LOGIN_PASSWORD setting
    if not settings.LOGIN_PASSWORD:
        return await call_next(request)
    path = request.url.path
    if (path in {"/login", "/api/login", "/api/logout", "/health"}
            or path.startswith("/api/auth/")   # per-user auth endpoints
            or path.startswith("/admin")        # admin has its own auth system
            or path.startswith("/frontend/")
            or path.startswith("/media/")       # public media proxy (Meta fetches IG media)
            or path.startswith("/static/")):
        return await call_next(request)
    # Accept either the legacy login cookie (master password) OR a valid per-user
    # session cookie (set by admin SSO login). This means users who log in via the
    # admin panel don't also need to enter the master password.
    login_token = request.cookies.get(LOGIN_COOKIE)
    session_token = request.cookies.get(SESSION_COOKIE)
    has_login_cookie = login_token and secrets.compare_digest(login_token, _login_token())
    has_session = bool(verify_session_token(session_token) if session_token else None)
    if not has_login_cookie and not has_session:
        if path.startswith("/api/"):
            return JSONResponse({"error": "Login required"}, status_code=403)
        return RedirectResponse("/login")
    return await call_next(request)


def get_session(request: Request) -> dict:
    return getattr(request.state, "session", {})


def _token_expired(token_expiry) -> bool:
    """Timezone-safe expiry check.

    Stored token_expiry may be timezone-aware (e.g. ``+00:00``) while
    ``datetime.utcnow()`` is naive — comparing the two raises a TypeError.
    Normalize both to aware UTC before comparing.
    """
    if not token_expiry:
        return False
    if token_expiry.tzinfo is None:
        token_expiry = token_expiry.replace(tzinfo=timezone.utc)
    return token_expiry < datetime.now(timezone.utc)


async def get_meta_token(request: Request, db: AsyncSession) -> str:
    """Decrypt and return the active Meta access token, refreshing if near expiry."""
    session = get_session(request)
    uid = session.get("meta_user_id")
    if not uid:
        raise HTTPException(401, "Meta account not connected")
    result = await db.execute(
        select(ConnectedMetaAccount).where(
            ConnectedMetaAccount.facebook_user_id == uid,
            ConnectedMetaAccount.is_active == True,
        )
    )
    acc = result.scalar_one_or_none()
    if not acc:
        raise HTTPException(401, "Meta account not found")
    if _token_expired(acc.token_expiry):
        raise HTTPException(401, "Meta token expired — please reconnect")
    acc.last_used_at = datetime.utcnow()
    await db.commit()
    return encryption.decrypt(acc.encrypted_long_token)


async def get_google_token(request: Request, db: AsyncSession) -> str:
    """Decrypt and return Google access token, refreshing if expired.

    Prefers the account tied to the current session, but falls back to any
    active connected Google account — the Drive connection is app-wide, not
    per-login. Sessions expire after 8h / on network change; the stored
    refresh token does not, so Drive must keep working for every user without
    reconnecting.
    """
    session = get_session(request)
    uid = session.get("google_user_id")
    from database import ConnectedGoogleAccount
    acc = None
    if uid:
        result = await db.execute(
            select(ConnectedGoogleAccount).where(
                ConnectedGoogleAccount.google_user_id == uid,
                ConnectedGoogleAccount.is_active == True,
            )
        )
        acc = result.scalar_one_or_none()
    if not acc:
        # Session has no Google uid (expired cookie, different user logged in)
        # — use the most recently connected active account instead.
        result = await db.execute(
            select(ConnectedGoogleAccount)
            .where(ConnectedGoogleAccount.is_active == True)
            .order_by(ConnectedGoogleAccount.id.desc())
        )
        acc = result.scalars().first()
    if not acc:
        raise HTTPException(401, "Google account not connected")
    if _token_expired(acc.token_expiry):
        refresh = await google_api.refresh_access_token(
            encryption.decrypt(acc.encrypted_refresh_token),
            settings.GOOGLE_CLIENT_ID,
            settings.GOOGLE_CLIENT_SECRET,
        )
        if not refresh.get("success"):
            raise HTTPException(401, "Google token expired — please reconnect")
        acc.encrypted_access_token = encryption.encrypt(refresh["access_token"])
        acc.token_expiry = datetime.utcnow() + timedelta(seconds=refresh.get("expires_in", 3600))
        await db.commit()
    return encryption.decrypt(acc.encrypted_access_token)

async def get_posting_token(request: Request, db: AsyncSession) -> str:
    """Decrypt and return the active Posting Meta access token.

    Prefers the posting account tied to the current session. If the session
    doesn't carry a posting_user_id (e.g. connected in a popup/other tab, or a
    fresh login after the account was already stored), fall back to the most
    recently used active posting account — consistent with the app-wide,
    non-session-scoped posting account listing.
    """
    session = get_session(request)
    uid = session.get("posting_user_id")
    acc = None
    if uid:
        result = await db.execute(
            select(ConnectedPostingAccount).where(
                ConnectedPostingAccount.facebook_user_id == uid,
                ConnectedPostingAccount.is_active == True,
            )
        )
        acc = result.scalar_one_or_none()
    if acc is None:
        # Fallback: any active posting account (most recently created first).
        result = await db.execute(
            select(ConnectedPostingAccount)
            .where(ConnectedPostingAccount.is_active == True)
            .order_by(ConnectedPostingAccount.id.desc())
        )
        acc = result.scalars().first()
    if not acc:
        raise HTTPException(401, "Posting account not connected")
    if _token_expired(acc.token_expiry):
        raise HTTPException(401, "Posting token expired — please reconnect")
    acc.last_used_at = datetime.utcnow()
    await db.commit()
    return encryption.decrypt(acc.encrypted_long_token)

# ── Pydantic request models ────────────────────────────────────────────────────

class CreateClientRequest(BaseModel):
    name: str
    industry: Optional[str] = None
    website: Optional[str] = None
    notes: Optional[str] = None
    color_tag: str = "#6c63ff"

class UpdateClientRequest(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    website: Optional[str] = None
    notes: Optional[str] = None
    color_tag: Optional[str] = None
    is_archived: Optional[bool] = None
    sort_order: Optional[int] = None

class CreateAdAccountRequest(BaseModel):
    nickname: str
    meta_account_id: str
    default_page_id: Optional[str] = None
    default_page_name: Optional[str] = None
    default_pixel_id: Optional[str] = None
    default_pixel_name: Optional[str] = None
    default_instagram_id: Optional[str] = None
    default_instagram_username: Optional[str] = None
    default_daily_budget: Optional[float] = None
    default_countries: Optional[list[str]] = None
    default_age_min: int = 18
    default_age_max: int = 65
    default_timezone: str = "UTC"
    default_objective: str = "OUTCOME_SALES"
    is_default: bool = False

class CreateConversationRequest(BaseModel):
    client_id: Optional[int] = None
    client_ad_account_id: Optional[int] = None
    title: str = "New Conversation"

class UpdateConversationRequest(BaseModel):
    title: Optional[str] = None
    is_pinned: Optional[bool] = None
    is_archived: Optional[bool] = None

class ChatRequest(BaseModel):
    message: str
    attachments: list[str] = []

class LoginRequest(BaseModel):
    password: str

class UpdateContextRequest(BaseModel):
    selected_meta_account_id: Optional[str] = None
    selected_ad_account_id: Optional[str] = None
    selected_page_id: Optional[str] = None
    selected_pixel_id: Optional[str] = None
    selected_instagram_id: Optional[str] = None
    selected_timezone: Optional[str] = None
    overrides: Optional[dict] = None

class CreateSkillRequest(BaseModel):
    name: str
    description: Optional[str] = None
    content: str
    client_id: Optional[int] = None

class UpdateSkillRequest(BaseModel):
    content: str
    description: Optional[str] = None

class CreateQuickCommandRequest(BaseModel):
    trigger: str
    name: str
    description: Optional[str] = None
    prompt_template: str
    client_id: Optional[int] = None

class CreateCampaignRequest(BaseModel):
    ad_account_id: str
    name: str
    objective: str = "OUTCOME_SALES"
    daily_budget_euros: float = 10.0
    status: str = "ACTIVE"

# ── Setup wizard ──────────────────────────────────────────────────────────────

def _is_setup_complete() -> bool:
    """Return True when at least one AI key and the Meta app ID are configured."""
    has_meta = bool(settings.META_APP_ID and settings.META_APP_SECRET)
    has_ai = bool(
        settings.ANTHROPIC_API_KEY
        or settings.OPENAI_API_KEY
        or settings.GROQ_API_KEY
    )
    return has_meta and has_ai

class SetupSaveRequest(BaseModel):
    meta_app_id: str = ""
    meta_app_secret: str = ""
    meta_posting_app_id: str = ""
    meta_posting_app_secret: str = ""
    ai_provider: str = "claude"
    anthropic_api_key: str = ""
    claude_model: str = ""
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    google_client_id: str = ""
    google_client_secret: str = ""

@app.get("/setup", response_class=HTMLResponse)
async def setup_page():
    setup_path = Path("frontend/setup.html")
    if setup_path.exists():
        return HTMLResponse(setup_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Setup page not found</h1>", status_code=500)

def _require_admin_cookie(request: Request) -> dict:
    """Admin gate for /api/setup paths, which bypass the session middleware.

    Those endpoints write API secrets into .env/DB — without this check any
    visitor could overwrite META_APP_SECRET, ANTHROPIC_API_KEY, etc.
    """
    token = request.cookies.get(SESSION_COOKIE)
    session = verify_session_token(token) if token else None
    if not session or session.get("user_role") != "admin":
        raise HTTPException(403, "Admin access required")
    return session


@app.post("/api/setup/save")
async def setup_save(req: SetupSaveRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Write provided keys into the .env file, persist them to the DB, and reload settings.

    The DB copy is the durable source of truth: on platforms with an ephemeral
    filesystem (Render), the .env file is wiped on every redeploy, so keys are
    reloaded from the DB on startup.
    """
    _require_admin_cookie(request)
    env_path = Path(".env")
    if not env_path.exists():
        env_path.write_text("", encoding="utf-8")

    lines = env_path.read_text(encoding="utf-8").splitlines()

    def _set_key(lines: list[str], key: str, value: str) -> list[str]:
        for i, line in enumerate(lines):
            if line.startswith(f"{key}=") or line.startswith(f"{key} ="):
                lines[i] = f"{key}={value}"
                return lines
        lines.append(f"{key}={value}")
        return lines

    pairs = {
        "META_APP_ID": req.meta_app_id,
        "META_APP_SECRET": req.meta_app_secret,
        "META_POSTING_APP_ID": req.meta_posting_app_id,
        "META_POSTING_APP_SECRET": req.meta_posting_app_secret,
        "AI_PROVIDER": req.ai_provider,
        "ANTHROPIC_API_KEY": req.anthropic_api_key,
        "CLAUDE_MODEL": req.claude_model,
        "OPENAI_API_KEY": req.openai_api_key,
        "OPENAI_MODEL": req.openai_model,
        "GROQ_API_KEY": req.groq_api_key,
        "GROQ_MODEL": req.groq_model,
        "GOOGLE_CLIENT_ID": req.google_client_id,
        "GOOGLE_CLIENT_SECRET": req.google_client_secret,
    }
    for key, value in pairs.items():
        if value:  # never overwrite an existing key with an empty string
            lines = _set_key(lines, key, value)

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Persist to the DB (durable across redeploys on ephemeral filesystems).
    try:
        from database import save_app_setting
        for key, value in pairs.items():
            await save_app_setting(key, value, db)
        await db.commit()
    except Exception as exc:
        logger.warning("Could not persist settings to DB: %s", exc)

    # Update the live settings object in-place so _is_setup_complete()
    # returns True immediately without needing a server restart.
    try:
        if req.meta_app_id:
            settings.META_APP_ID = req.meta_app_id
        if req.meta_app_secret:
            settings.META_APP_SECRET = req.meta_app_secret
        if req.meta_posting_app_id:
            settings.META_POSTING_APP_ID = req.meta_posting_app_id
        if req.meta_posting_app_secret:
            settings.META_POSTING_APP_SECRET = req.meta_posting_app_secret
        if req.ai_provider:
            settings.AI_PROVIDER = req.ai_provider
        if req.anthropic_api_key:
            settings.ANTHROPIC_API_KEY = req.anthropic_api_key
        if req.openai_api_key:
            settings.OPENAI_API_KEY = req.openai_api_key
        if req.openai_model:
            settings.OPENAI_MODEL = req.openai_model
        if req.groq_api_key:
            settings.GROQ_API_KEY = req.groq_api_key
        if req.groq_model:
            settings.GROQ_MODEL = req.groq_model
        if req.google_client_id:
            settings.GOOGLE_CLIENT_ID = req.google_client_id
        if req.google_client_secret:
            settings.GOOGLE_CLIENT_SECRET = req.google_client_secret
        agent._init_client()
    except Exception as exc:
        logger.warning("Could not update live settings: %s", exc)

    return {"success": True, "message": "Settings saved."}


@app.delete("/api/setup/key/{provider}")
async def clear_api_key(provider: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Remove a single AI provider key from .env, the DB, and live settings."""
    _require_admin_cookie(request)
    env_key_map = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "groq": "GROQ_API_KEY"}
    env_key = env_key_map.get(provider)
    if not env_key:
        raise HTTPException(400, f"Unknown provider: {provider}")
    env_path = Path(".env")
    if env_path.exists():
        lines = [l for l in env_path.read_text(encoding="utf-8").splitlines()
                 if not (l.startswith(f"{env_key}=") or l.startswith(f"{env_key} ="))]
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Also remove the durable DB copy so it isn't restored on next redeploy.
    try:
        from database import delete_app_setting
        await delete_app_setting(env_key, db)
        await db.commit()
    except Exception as exc:
        logger.warning("Could not delete setting %s from DB: %s", env_key, exc)
    if provider == "anthropic":
        settings.ANTHROPIC_API_KEY = ""
    elif provider == "openai":
        settings.OPENAI_API_KEY = ""
    elif provider == "groq":
        settings.GROQ_API_KEY = ""
    agent._init_client()
    return {"success": True}


_USER_SETTINGS_FILE = Path("user_settings.json")


def _load_user_settings() -> dict:
    if _USER_SETTINGS_FILE.exists():
        try:
            import json as _json
            return _json.loads(_USER_SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_user_settings(data: dict) -> None:
    import json as _json
    existing = _load_user_settings()
    existing.update(data)
    _USER_SETTINGS_FILE.write_text(_json.dumps(existing, indent=2), encoding="utf-8")


@app.get("/api/setup/user-settings")
async def get_user_settings():
    return _load_user_settings()


@app.post("/api/setup/user-settings")
async def save_user_settings(request: Request):
    _require_admin_cookie(request)
    body = await request.json()
    _save_user_settings(body)
    # Custom instructions are part of the system prompt — bust cache
    _system_prompt_cache.clear()
    return {"success": True}


@app.get("/api/setup/status")
async def setup_status():
    from database import DATABASE_URL as _db_url
    db_type = "sqlite" if _db_url.startswith("sqlite") else "postgresql"
    return {
        "complete": _is_setup_complete(),
        "ai_provider": settings.AI_PROVIDER,
        "has_meta": bool(settings.META_APP_ID),
        "has_posting_app": bool(settings.META_POSTING_APP_ID),
        "has_anthropic": bool(settings.ANTHROPIC_API_KEY),
        "has_openai": bool(settings.OPENAI_API_KEY),
        "has_groq": bool(settings.GROQ_API_KEY),
        "has_google": bool(settings.GOOGLE_CLIENT_ID),
        "google_redirect_uri": settings.google_redirect_uri,
        "db_type": db_type,
    }

@app.get("/api/setup/redirect-uris")
async def setup_redirect_uris(request: Request):
    """Return the EXACT OAuth redirect URIs this app sends, computed from the
    live request host. Copy these verbatim into the Meta/Google dashboards."""
    fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    fwd_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    scheme = fwd_proto or request.url.scheme
    host = fwd_host or request.url.netloc
    base = f"{scheme}://{host}"
    return {
        "detected_scheme": scheme,
        "detected_host": host,
        "meta_ads_redirect_uri": f"{base}/auth/meta/callback",
        "meta_posting_redirect_uri": f"{base}/auth/meta/posting/callback",
        "google_redirect_uri": f"{base}/auth/google/callback",
        "app_domain": host,
    }


# ── Health & frontend ──────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    # Deployment markers so /health shows exactly what's live:
    # - commit: the git SHA Render deployed (RENDER_GIT_COMMIT env var)
    # - release: version.txt baked into that commit (lags one release because
    #   the bump lands after the code merge and is skipped by the buildFilter)
    try:
        release = Path("version.txt").read_text(encoding="utf-8").strip()
    except Exception:
        release = "unknown"
    return {
        "status": "ok",
        "version": "1.0.0",
        "release": release,
        "commit": os.environ.get("RENDER_GIT_COMMIT", "")[:7] or "unknown",
    }


@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page():
    p = Path("frontend/privacy.html")
    return HTMLResponse(p.read_text(encoding="utf-8") if p.exists() else "<h1>Privacy Policy</h1>")


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    p = Path("frontend/login.html")
    return HTMLResponse(p.read_text(encoding="utf-8") if p.exists() else "<h1>Login</h1>")


@app.post("/api/login")
async def do_login(req: LoginRequest, response: Response):
    if not settings.LOGIN_PASSWORD:
        return {"success": True}
    if not secrets.compare_digest(req.password, settings.LOGIN_PASSWORD):
        raise HTTPException(401, "Incorrect password")
    response.set_cookie(
        LOGIN_COOKIE, _login_token(),
        max_age=30 * 24 * 3600, httponly=True, samesite="lax"
    )
    return {"success": True}


@app.post("/api/logout")
async def do_logout(response: Response):
    response.delete_cookie(LOGIN_COOKIE)
    return {"success": True}


# ── Per-user auth endpoints ────────────────────────────────────────────────────

class UserLoginRequest(BaseModel):
    username: str
    password: str
    remember_me: bool = False  # True → 30-day cookie; False → session cookie

class UserCreateRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    role: str = "user"
    interface_access: str = "both"

class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    interface_access: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None
    email: Optional[str] = None

class PageAssignmentRequest(BaseModel):
    page_id: str
    page_name: Optional[str] = None
    platform: str  # 'facebook' or 'instagram'
    meta_app_db_id: Optional[int] = None


async def _provision_meta_user_from_staff(staff, db: AsyncSession) -> User:
    """Find or create the Meta Ads app `users` row linked to a CRM staff member.

    The CRM (crm_staff) is the single source of truth for identity. The Meta app
    still references its own `users` table for page/client assignments, so we keep
    a linked row in sync. This never deletes Meta data — it only links/back-fills
    and keeps the password hash in sync with the CRM.
    """
    # Match an existing Meta user by username or email.
    conds = []
    if staff.username:
        conds.append(User.username == staff.username)
    if staff.email:
        conds.append(func.lower(User.email) == staff.email.lower())
    user = None
    if conds:
        user = (await db.execute(select(User).where(or_(*conds)))).scalars().first()

    derived_username = staff.username or (staff.email.split("@")[0] if staff.email else f"user{staff.id}")
    role = "admin" if staff.is_admin else "user"

    if user:
        # Keep the linked Meta user in sync with the CRM record — but only
        # sync the password when the rows are linked by matching email, so a
        # Meta user who merely shares a username doesn't get their password
        # replaced. Never re-activate a deactivated user or change an
        # existing user's role: admin edits used to be reverted at the staff
        # member's next login.
        email_match = bool(
            staff.email and user.email and staff.email.lower() == user.email.lower()
        )
        if email_match:
            user.hashed_password = staff.hashed_password
        if not user.is_active:
            raise HTTPException(401, "This account has been deactivated")
        if staff.email and not user.email:
            user.email = staff.email
    else:
        user = User(
            username=derived_username,
            email=staff.email,
            hashed_password=staff.hashed_password,
            role=role,
            interface_access="both",
            is_active=True,
        )
        db.add(user)
    await db.flush()
    return user


@app.post("/api/auth/login")
async def api_auth_login(req: UserLoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    # ── Unified login ────────────────────────────────────────────────────────
    # The CRM (crm_staff) is the single source of truth. Validate the credential
    # (which may be an email OR a username) against crm_staff, then ensure a
    # linked Meta Ads `users` row exists so the rest of the app keeps working.
    from admin_models import StaffMember
    ident = (req.username or "").strip()
    staff = (await db.execute(
        select(StaffMember).where(
            or_(
                func.lower(StaffMember.email) == ident.lower(),
                StaffMember.username == ident,
            ),
            StaffMember.is_active == True,
        )
    )).scalars().first()

    if staff and _verify_password(req.password, staff.hashed_password):
        user = await _provision_meta_user_from_staff(staff, db)
        await db.commit()
    else:
        # Fallback: legacy Meta-only users that haven't been migrated yet.
        # Accept email OR username so nobody is locked out by which one they typed.
        result = await db.execute(
            select(User).where(
                or_(
                    User.username == ident,
                    func.lower(User.email) == ident.lower(),
                ),
                User.is_active == True,
            )
        )
        user = result.scalars().first()
        if not user or not _verify_password(req.password, user.hashed_password):
            raise HTTPException(401, "Invalid username or password")

    session_data = {
        "user_id": user.id,
        "user_role": user.role,
        "user_access": user.interface_access,
        "username": user.username,
    }
    if req.remember_me:
        # Flag inside the signed token so verify_session_token extends the
        # server-side validity window to match the 30-day cookie.
        session_data["_remember"] = True
    token = create_session_token(session_data)
    # remember_me=True → 30-day persistent cookie; False → session cookie (clears on browser close)
    cookie_max_age = 86400 * 30 if req.remember_me else None
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=cookie_max_age)
    return {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "interface_access": user.interface_access,
    }


@app.post("/api/auth/logout")
async def api_auth_logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(LOGIN_COOKIE)
    return {"ok": True}


@app.post("/api/auth/emergency-reset")
async def api_emergency_reset(request: Request, db: AsyncSession = Depends(get_db)):
    """Emergency admin password reset — requires the SECRET_KEY as proof of server access.
    Only usable when locked out; protected by SECRET_KEY which is server-side only.
    """
    body = await request.json()
    provided_key = body.get("secret_key", "")
    new_password = body.get("password", "")
    new_email = body.get("email", "")

    if not provided_key or not secrets.compare_digest(provided_key, settings.SECRET_KEY):
        raise HTTPException(403, "Invalid secret key")
    if len(new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    result = await db.execute(select(User).where(User.username == "admin").limit(1))
    admin_user = result.scalar_one_or_none()
    if admin_user:
        admin_user.hashed_password = _hash_password(new_password)
        admin_user.is_active = True
        if new_email:
            admin_user.email = new_email
        await db.commit()
        logger.warning("Admin password reset via emergency endpoint")
        return {"ok": True, "message": "Admin password updated. You can now sign in."}
    else:
        # Create admin from scratch
        db.add(User(
            username="admin",
            email=new_email or None,
            hashed_password=_hash_password(new_password),
            role="admin",
            interface_access="both",
            is_active=True,
        ))
        await db.commit()
        logger.warning("Admin account created via emergency endpoint")
        return {"ok": True, "message": "Admin account created. You can now sign in."}


@app.get("/api/auth/me")
async def api_auth_me(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    session = verify_session_token(token) if token else None
    if not session:
        raise HTTPException(401, "Not authenticated")
    user_id = session.get("user_id")
    if not user_id:
        raise HTTPException(401, "Not authenticated")
    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")
    return {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "interface_access": user.interface_access,
    }


async def require_admin(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    if session.get("user_role") != "admin":
        raise HTTPException(403, "Admin access required")
    # The signed cookie can outlive a demotion/deactivation by up to 30 days —
    # re-verify against the DB so revoked admins lose access immediately.
    uid = session.get("user_id")
    if uid:
        user = await db.get(User, uid)
        if not user or not user.is_active or user.role != "admin":
            raise HTTPException(403, "Admin access required")


# ── User management endpoints (admin only) ────────────────────────────────────

@app.get("/api/users")
async def api_list_users(request: Request, db: AsyncSession = Depends(get_db)):
    await require_admin(request, db)
    from sqlalchemy import func as _func
    result = await db.execute(select(User).order_by(User.created_at))
    users = result.scalars().all()
    out = []
    for u in users:
        page_res = await db.execute(
            select(_func.count()).select_from(UserPageAssignment).where(UserPageAssignment.user_id == u.id)
        )
        client_res = await db.execute(
            select(_func.count()).select_from(UserClientAssignment).where(UserClientAssignment.user_id == u.id)
        )
        out.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "interface_access": u.interface_access,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat(),
            "page_count": page_res.scalar() or 0,
            "client_count": client_res.scalar() or 0,
        })
    return out


@app.post("/api/users", status_code=201)
async def api_create_user(req: UserCreateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    await require_admin(request, db)
    # Trim — login strips the identifier, so a username saved with stray
    # whitespace could never log in.
    username = (req.username or "").strip()
    email = (req.email or "").strip() or None
    if not username:
        raise HTTPException(400, "Username is required")
    if len(req.password or "") < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    existing = await db.execute(select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Username already exists")
    user = User(
        username=username,
        email=email,
        hashed_password=_hash_password(req.password),
        role=req.role,
        interface_access=req.interface_access,
    )
    db.add(user)
    try:
        await db.commit()
    except Exception:
        # Concurrent create with the same username — surface a clean 400
        # instead of a raw IntegrityError 500.
        await db.rollback()
        raise HTTPException(400, "Username already exists")
    await db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role, "interface_access": user.interface_access}


@app.put("/api/users/{user_id}")
async def api_update_user(user_id: int, req: UserUpdateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    await require_admin(request, db)
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if req.role is not None:
        user.role = req.role
    if req.interface_access is not None:
        user.interface_access = req.interface_access
    if req.is_active is not None:
        user.is_active = req.is_active
    if req.password:
        user.hashed_password = _hash_password(req.password)
    if req.email is not None:
        user.email = req.email
    await db.commit()
    return {"ok": True}


@app.delete("/api/users/{user_id}")
async def api_delete_user(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    await require_admin(request, db)
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.is_active = False
    await db.commit()
    return {"ok": True}


# ── Page assignment endpoints ─────────────────────────────────────────────────

@app.get("/api/users/{user_id}/pages")
async def api_get_user_pages(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    # Admin can see anyone's pages; user can only see their own
    if session.get("user_role") != "admin" and session.get("user_id") != user_id:
        raise HTTPException(403, "Forbidden")
    result = await db.execute(
        select(UserPageAssignment).where(UserPageAssignment.user_id == user_id)
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "page_id": r.page_id,
            "page_name": r.page_name,
            "platform": r.platform,
            "meta_app_db_id": r.meta_app_db_id,
        }
        for r in rows
    ]


@app.post("/api/users/{user_id}/pages", status_code=201)
async def api_assign_page(user_id: int, req: PageAssignmentRequest, request: Request, db: AsyncSession = Depends(get_db)):
    await require_admin(request, db)
    assignment = UserPageAssignment(
        user_id=user_id,
        page_id=req.page_id,
        page_name=req.page_name,
        platform=req.platform,
        meta_app_db_id=req.meta_app_db_id,
    )
    db.add(assignment)
    await db.commit()
    await db.refresh(assignment)
    return {"id": assignment.id}


@app.delete("/api/users/{user_id}/pages/{assignment_id}")
async def api_remove_page_assignment(user_id: int, assignment_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    await require_admin(request, db)
    result = await db.execute(
        select(UserPageAssignment).where(
            UserPageAssignment.id == assignment_id,
            UserPageAssignment.user_id == user_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Assignment not found")
    await db.delete(row)
    await db.commit()
    return {"ok": True}


@app.get("/api/users/usage")
async def api_users_usage(request: Request, db: AsyncSession = Depends(get_db)):
    """Per-user durable API usage (Meta calls + AI tokens) — admin only.

    Returned as a map keyed by user_id so the dashboard can decorate user cards.
    Also merges in the live in-memory AI session counters where available.
    """
    await require_admin(request, db)
    result = await db.execute(select(UserApiUsage))
    rows = result.scalars().all()
    usage = {
        str(r.user_id): {
            "meta_calls": r.meta_calls or 0,
            "ai_input_tokens": r.ai_input_tokens or 0,
            "ai_output_tokens": r.ai_output_tokens or 0,
            "ai_total_tokens": (r.ai_input_tokens or 0) + (r.ai_output_tokens or 0),
            "ai_calls": r.ai_calls or 0,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in rows
    }
    return {"usage": usage}


# ── Posting event log (admin only) ───────────────────────────────────────────

@app.get("/api/admin/posting-events")
async def api_admin_posting_events(
    request: Request,
    db: AsyncSession = Depends(get_db),
    limit: int = 300,
    level: str = "",
    platform: str = "",
    event_type: str = "",
):
    """Persistent audit log of all posting/scheduling events — admin only."""
    await require_admin(request, db)
    limit = max(1, min(limit, 1000))
    q = select(PostingEventLog).order_by(PostingEventLog.created_at.desc()).limit(limit)
    if level:
        q = q.where(PostingEventLog.level == level)
    if platform:
        q = q.where(PostingEventLog.platform == platform)
    if event_type:
        q = q.where(PostingEventLog.event_type == event_type)
    result = await db.execute(q)
    rows = result.scalars().all()
    return {
        "count": len(rows),
        "events": [
            {
                "id": e.id,
                "ts": e.created_at.isoformat() if e.created_at else None,
                "level": e.level,
                "event_type": e.event_type,
                "platform": e.platform,
                "username": e.username,
                "user_id": e.user_id,
                "page_id": e.page_id,
                "page_name": e.page_name,
                "post_id": e.post_id,
                "job_id": e.job_id,
                "message": e.message,
                "detail": e.detail,
            }
            for e in rows
        ],
    }


@app.delete("/api/admin/posting-events")
async def api_admin_clear_posting_events(request: Request, db: AsyncSession = Depends(get_db)):
    """Clear all posting event log entries — admin only."""
    await require_admin(request, db)
    from sqlalchemy import delete as _delete
    result = await db.execute(_delete(PostingEventLog))
    await db.commit()
    return {"deleted": result.rowcount}


# ── Client assignment endpoints ───────────────────────────────────────────────

@app.get("/api/users/{user_id}/clients")
async def api_get_user_clients(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    await require_admin(request, db)
    result = await db.execute(
        select(UserClientAssignment, Client)
        .join(Client, UserClientAssignment.client_id == Client.id)
        .where(UserClientAssignment.user_id == user_id)
    )
    rows = result.all()
    return [
        {"id": r.UserClientAssignment.id, "client_id": r.Client.id, "client_name": r.Client.name, "color_tag": r.Client.color_tag}
        for r in rows
    ]


@app.post("/api/users/{user_id}/clients", status_code=201)
async def api_assign_client(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    await require_admin(request, db)
    body = await request.json()
    client_id = body.get("client_id")
    if not client_id:
        raise HTTPException(400, "client_id required")
    existing = await db.execute(
        select(UserClientAssignment).where(
            UserClientAssignment.user_id == user_id,
            UserClientAssignment.client_id == client_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Already assigned")
    assignment = UserClientAssignment(user_id=user_id, client_id=client_id)
    db.add(assignment)
    await db.commit()
    await db.refresh(assignment)
    return {"id": assignment.id}


@app.delete("/api/users/{user_id}/clients/{assignment_id}")
async def api_remove_client_assignment(user_id: int, assignment_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    await require_admin(request, db)
    result = await db.execute(
        select(UserClientAssignment).where(
            UserClientAssignment.id == assignment_id,
            UserClientAssignment.user_id == user_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Client assignment not found")
    await db.delete(row)
    await db.commit()
    return {"ok": True}


# ── Meta app pages endpoint (for admin panel page assignments) ─────────────────

@app.get("/api/meta-apps/{meta_app_id}/pages")
async def api_get_app_pages(
    meta_app_id: int,
    request: Request,
    platform: str = "facebook",
    db: AsyncSession = Depends(get_db),
):
    """Return FB pages or IG accounts connected via a specific Meta app (admin only)."""
    await require_admin(request, db)
    result = await db.execute(
        select(ConnectedMetaAccount).where(
            ConnectedMetaAccount.meta_app_db_id == meta_app_id,
            ConnectedMetaAccount.is_active == True,
        )
    )
    accounts = result.scalars().all()

    pages = []
    for acc in accounts:
        try:
            token = encryption.decrypt(acc.encrypted_long_token)
            if platform == "facebook":
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.get(
                        f"https://graph.facebook.com/{settings.META_API_VERSION}/me/accounts",
                        params={"access_token": token, "fields": "id,name,access_token"},
                    )
                    if r.status_code == 200:
                        for p in r.json().get("data", []):
                            if not any(x["id"] == p["id"] for x in pages):
                                pages.append({"id": p["id"], "name": p.get("name", p["id"])})
            else:  # instagram
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.get(
                        f"https://graph.facebook.com/{settings.META_API_VERSION}/me/accounts",
                        params={"access_token": token, "fields": "id,name,instagram_business_account"},
                    )
                    if r.status_code == 200:
                        for p in r.json().get("data", []):
                            ig = p.get("instagram_business_account")
                            if ig and not any(x["id"] == ig["id"] for x in pages):
                                pages.append({"id": ig["id"], "name": p.get("name", ig["id"])})
        except Exception:
            pass

    result2 = await db.execute(
        select(ConnectedPostingAccount).where(
            ConnectedPostingAccount.meta_app_db_id == meta_app_id,
            ConnectedPostingAccount.is_active == True,
        )
    )
    posting_accounts = result2.scalars().all()
    for acc in posting_accounts:
        try:
            token = encryption.decrypt(acc.encrypted_long_token)
            if platform == "facebook":
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.get(
                        f"https://graph.facebook.com/{settings.META_API_VERSION}/me/accounts",
                        params={"access_token": token, "fields": "id,name"},
                    )
                    if r.status_code == 200:
                        for p in r.json().get("data", []):
                            if not any(x["id"] == p["id"] for x in pages):
                                pages.append({"id": p["id"], "name": p.get("name", p["id"])})
            else:
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.get(
                        f"https://graph.facebook.com/{settings.META_API_VERSION}/me/accounts",
                        params={"access_token": token, "fields": "id,name,instagram_business_account"},
                    )
                    if r.status_code == 200:
                        for p in r.json().get("data", []):
                            ig = p.get("instagram_business_account")
                            if ig and not any(x["id"] == ig["id"] for x in pages):
                                pages.append({"id": ig["id"], "name": p.get("name", ig["id"])})
        except Exception:
            pass

    return pages


_frontend_html: str | None = None

@app.get("/", response_class=HTMLResponse)
async def root_redirect():
    return RedirectResponse(url="/admin", status_code=302)

@app.get("/ads", response_class=HTMLResponse)
async def frontend(request: Request):
    global _frontend_html
    if _frontend_html is None:
        html_path = Path("frontend/index.html")
        _frontend_html = html_path.read_text(encoding="utf-8") if html_path.exists() else "<h1>Uplinx Meta Manager</h1><p>Frontend not found.</p>"
    return HTMLResponse(_frontend_html, headers={"Cache-Control": "no-store"})

# ── Meta OAuth ────────────────────────────────────────────────────────────────

META_SCOPES = ",".join([
    "ads_management", "ads_read", "pages_show_list",
    "pages_read_engagement", "pages_manage_ads", "pages_manage_posts",
    "read_insights", "instagram_content_publish",
    "instagram_manage_insights", "business_management",
])

@app.get("/auth/meta")
async def auth_meta(
    request: Request,
    response: Response,
    app: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
):
    """Initiate Meta OAuth for the Ads app.

    ``?app={id}`` selects a specific MetaApp row from the database.
    If omitted, falls back to the first active ads app in the DB,
    then to the META_APP_ID environment variable.
    """
    app_id_val = ""
    # Derive redirect_uri from the actual request host (respecting proxy
    # X-Forwarded-* headers) so it always matches the live domain rather than a
    # stale BASE_URL / localhost default.
    fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    fwd_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    scheme = fwd_proto or request.url.scheme
    host = fwd_host or request.url.netloc
    redirect_uri_val = f"{scheme}://{host}/auth/meta/callback"
    if host.startswith("localhost") or host.startswith("127.0.0.1"):
        # Local dev — honour the configured value (may be a tunnel URL).
        redirect_uri_val = settings.meta_redirect_uri

    if app:
        result = await db.execute(
            select(MetaApp).where(MetaApp.id == app, MetaApp.app_type == "ads", MetaApp.is_active == True)
        )
        db_app = result.scalar_one_or_none()
        if not db_app:
            return RedirectResponse("/?error=ads_app_not_found")
        app_id_val = db_app.app_id
        response.set_cookie("oauth_meta_app_id", str(app), max_age=600, httponly=True, samesite="lax")
    else:
        # Fall back to first active DB app, then env var
        result = await db.execute(
            select(MetaApp).where(MetaApp.app_type == "ads", MetaApp.is_active == True)
            .order_by(MetaApp.sort_order).limit(1)
        )
        db_app = result.scalar_one_or_none()
        if db_app:
            app_id_val = db_app.app_id
            response.set_cookie("oauth_meta_app_id", str(db_app.id), max_age=600, httponly=True, samesite="lax")
        else:
            app_id_val = settings.META_APP_ID

    if not app_id_val:
        return RedirectResponse("/?error=meta_app_not_configured")

    state = generate_oauth_state()
    response.set_cookie("oauth_state", state, max_age=600, httponly=True, samesite="lax")
    response.set_cookie("oauth_meta_redirect_uri", redirect_uri_val, max_age=600, httponly=True, samesite="lax")

    # Facebook Login for Business apps require the config_id flow (no scope —
    # permissions come from the dashboard configuration). Classic apps use the
    # scope-based flow. We pick based on whether a config_id is configured.
    config_id = settings.META_CONFIG_ID.strip()
    if config_id:
        params = urllib.parse.urlencode({
            "client_id": app_id_val,
            "config_id": config_id,
            "redirect_uri": redirect_uri_val,
            "response_type": "code",
            "override_default_response_type": "true",
            "state": state,
        })
        oauth_base = f"https://www.facebook.com/{settings.META_API_VERSION}/dialog/oauth"
    else:
        params = urllib.parse.urlencode({
            "client_id": app_id_val,
            "redirect_uri": redirect_uri_val,
            "scope": META_SCOPES,
            "response_type": "code",
            "state": state,
        })
        oauth_base = "https://www.facebook.com/dialog/oauth"
    return RedirectResponse(f"{oauth_base}?{params}", headers=response.headers)

@app.get("/auth/meta/callback")
async def auth_meta_callback(
    request: Request,
    response: Response,
    code: str = "",
    state: str = "",
    error: str = "",
    db: AsyncSession = Depends(get_db),
):
    if error:
        return RedirectResponse(f"/?error={urllib.parse.quote(error)}")

    expected_state = request.cookies.get("oauth_state", "")
    if not verify_oauth_state(state, expected_state):
        return RedirectResponse("/?error=invalid_state")

    # Resolve app credentials: DB app (from cookie) → env var fallback
    _app_id = settings.META_APP_ID
    _app_secret = settings.META_APP_SECRET
    _app_db_id_cookie = request.cookies.get("oauth_meta_app_id")
    if _app_db_id_cookie:
        try:
            _res = await db.execute(
                select(MetaApp).where(MetaApp.id == int(_app_db_id_cookie), MetaApp.is_active == True)
            )
            _db_app = _res.scalar_one_or_none()
            if _db_app:
                _app_id = _db_app.app_id
                _app_secret = encryption.decrypt(_db_app.encrypted_app_secret)
        except Exception:
            pass

    # Exchange code → short-lived token. Must reuse the exact redirect_uri sent
    # in the authorize step (stored in a cookie), or Meta rejects the exchange.
    _redirect_uri = request.cookies.get("oauth_meta_redirect_uri") or settings.meta_redirect_uri
    short = await meta_api.exchange_code_for_token(
        code, _app_id, _app_secret, _redirect_uri
    )
    if not short.get("success"):
        return RedirectResponse(f"/?error={urllib.parse.quote(short.get('error', 'token_exchange_failed'))}")

    short_token = short["data"].get("access_token", "")

    # Exchange → long-lived token
    long = await meta_api.exchange_for_long_lived_token(
        short_token, _app_id, _app_secret
    )
    if not long.get("success"):
        return RedirectResponse("/?error=long_token_failed")

    long_token = long["data"].get("access_token", "")
    expires_in = long["data"].get("expires_in", 5184000)

    # Fetch user info
    user = await meta_api.get_user_info(long_token)
    if not user.get("success"):
        return RedirectResponse("/?error=user_info_failed")

    uid = user["data"].get("id", "")
    name = user["data"].get("name", "")
    email = user["data"].get("email", "")

    # Store in DB
    result = await db.execute(
        select(ConnectedMetaAccount).where(ConnectedMetaAccount.facebook_user_id == uid)
    )
    acc = result.scalar_one_or_none()
    now = datetime.utcnow()
    # Record which DB MetaApp this account was connected through (None = env app)
    # so /api/meta-apps/{id}/pages can filter accounts by app.
    try:
        _meta_app_db_id = int(_app_db_id_cookie) if _app_db_id_cookie else None
    except (TypeError, ValueError):
        _meta_app_db_id = None
    if acc:
        acc.encrypted_short_token = encryption.encrypt(short_token)
        acc.encrypted_long_token = encryption.encrypt(long_token)
        acc.token_expiry = now + timedelta(seconds=expires_in)
        acc.user_name = name
        acc.user_email = email
        acc.is_active = True
        acc.last_used_at = now
        acc.meta_app_db_id = _meta_app_db_id
    else:
        acc = ConnectedMetaAccount(
            facebook_user_id=uid,
            user_name=name,
            user_email=email,
            encrypted_short_token=encryption.encrypt(short_token),
            encrypted_long_token=encryption.encrypt(long_token),
            token_expiry=now + timedelta(seconds=expires_in),
            created_at=now,
            last_used_at=now,
            is_active=True,
            meta_app_db_id=_meta_app_db_id,
        )
        db.add(acc)
    await db.commit()

    # Merge meta_user_id into existing session so user auth cookie is preserved
    existing_token = request.cookies.get(SESSION_COOKIE)
    existing_session = (verify_session_token(existing_token) if existing_token else None) or {}
    session_data = {**existing_session, "meta_user_id": uid}
    session_token = create_session_token(session_data)
    redirect = RedirectResponse("/auth/done?type=meta")
    redirect.set_cookie(
        SESSION_COOKIE, session_token,
        max_age=_session_cookie_max_age(session_data), httponly=True, samesite="lax"
    )
    redirect.delete_cookie("oauth_state")
    redirect.delete_cookie("oauth_meta_app_id")
    return redirect

# ── Google OAuth ──────────────────────────────────────────────────────────────

GOOGLE_SCOPES = " ".join([
    "openid", "email", "profile",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/documents.readonly",
    "https://www.googleapis.com/auth/spreadsheets.readonly",
])

@app.get("/auth/google")
async def auth_google(request: Request, response: Response):
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        return RedirectResponse("/?error=google_not_configured")
    state = generate_oauth_state()
    # Derive redirect_uri from the actual request host so it works on any deployment.
    # Respect X-Forwarded-Proto/Host because proxies (Render, Fly, etc.) terminate
    # TLS and forward to the app as plain HTTP — otherwise scheme would read "http"
    # and Google would reject the https URI registered in the console.
    fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    fwd_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    scheme = fwd_proto or request.url.scheme
    host = fwd_host or request.url.netloc
    redirect_uri = f"{scheme}://{host}/auth/google/callback"
    response.set_cookie("oauth_state_google", state, max_age=600, httponly=True, samesite="lax")
    response.set_cookie("google_redirect_uri", redirect_uri, max_age=600, httponly=True, samesite="lax")
    params = urllib.parse.urlencode({
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": GOOGLE_SCOPES,
        "response_type": "code",
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    })
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{params}", headers=response.headers)

@app.get("/auth/google/callback")
async def auth_google_callback(
    request: Request,
    response: Response,
    code: str = "",
    state: str = "",
    error: str = "",
    db: AsyncSession = Depends(get_db),
):
    if error:
        return RedirectResponse(f"/?error={urllib.parse.quote(error)}")

    expected = request.cookies.get("oauth_state_google", "")
    if not verify_oauth_state(state, expected):
        return RedirectResponse("/?error=invalid_state")

    redirect_uri = request.cookies.get("google_redirect_uri") or settings.GOOGLE_REDIRECT_URI
    tokens = await google_api.exchange_code_for_tokens(
        code, settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET, redirect_uri
    )
    if not tokens.get("success"):
        return RedirectResponse(f"/?error=google_token_failed")

    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    expires_in = tokens.get("expires_in", 3600)

    user = await google_api.get_user_info(access_token)
    if not user.get("success"):
        return RedirectResponse("/?error=google_user_failed")

    uid = user.get("id", "")
    email = user.get("email", "")
    name = user.get("name", "")

    from database import ConnectedGoogleAccount
    result = await db.execute(
        select(ConnectedGoogleAccount).where(ConnectedGoogleAccount.google_user_id == uid)
    )
    acc = result.scalar_one_or_none()
    now = datetime.utcnow()
    if acc:
        acc.encrypted_access_token = encryption.encrypt(access_token)
        if refresh_token:
            acc.encrypted_refresh_token = encryption.encrypt(refresh_token)
        acc.token_expiry = now + timedelta(seconds=expires_in)
        acc.is_active = True
    else:
        acc = ConnectedGoogleAccount(
            google_user_id=uid,
            user_email=email,
            user_name=name,
            encrypted_access_token=encryption.encrypt(access_token),
            encrypted_refresh_token=encryption.encrypt(refresh_token) if refresh_token else "",
            token_expiry=now + timedelta(seconds=expires_in),
            created_at=now,
            is_active=True,
        )
        db.add(acc)
    await db.commit()

    # Merge google_user_id into existing session or create new one
    existing_token = request.cookies.get(SESSION_COOKIE)
    existing_session = (verify_session_token(existing_token) if existing_token else None) or {}
    existing_session["google_user_id"] = uid
    session_token = create_session_token(existing_session)
    redirect = RedirectResponse("/auth/done?type=google")
    redirect.set_cookie(SESSION_COOKIE, session_token, max_age=_session_cookie_max_age(existing_session), httponly=True, samesite="lax")
    redirect.delete_cookie("oauth_state_google")
    return redirect

@app.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"success": True}


@app.get("/auth/done", response_class=HTMLResponse)
async def auth_done(type: str = "meta"):
    """OAuth completion page: closes popup and notifies opener, or redirects if no popup."""
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>Connected</title></head>
<body><script>
if (window.opener && !window.opener.closed) {{
  window.opener.postMessage({{oauthConnected: '{type}'}}, window.location.origin);
  window.close();
}} else {{
  window.location.href = '/?connected={type}';
}}
</script><p style="font-family:sans-serif;text-align:center;margin-top:40px">Connected! You can close this tab.</p></body></html>
""")


# ── Shared request models ──────────────────────────────────────────────────────

class DirectTokenRequest(BaseModel):
    access_token: str

class MetaAppCreateRequest(BaseModel):
    name: str
    app_type: str        # "ads" or "posting"
    app_id: str
    app_secret: str

class MetaAppUpdateRequest(BaseModel):
    name: Optional[str] = None
    app_secret: Optional[str] = None   # App ID is immutable after creation

# ── Posting Account API routes ─────────────────────────────────────────────────

@app.get("/api/accounts/posting")
async def api_posting_accounts(request: Request, db: AsyncSession = Depends(get_db)):
    """List connected Posting app Meta accounts (no tokens exposed).

    Non-admin users only see accounts they connected themselves (owner_user_id
    matches their user_id).  Admins see all connected accounts.  Legacy accounts
    with no owner (owner_user_id IS NULL) are visible to everyone so nothing
    breaks for existing deployments.
    """
    session = get_session(request)
    is_admin = session.get("user_role") == "admin"
    app_user_id: Optional[int] = session.get("user_id")

    q = select(ConnectedPostingAccount).where(ConnectedPostingAccount.is_active == True)
    if not is_admin and app_user_id:
        # Show accounts owned by this user OR legacy accounts with no owner.
        q = q.where(
            or_(
                ConnectedPostingAccount.owner_user_id == app_user_id,
                ConnectedPostingAccount.owner_user_id.is_(None),
            )
        )
    result = await db.execute(q)
    accounts = result.scalars().all()
    return [
        {
            "id": a.id,
            "facebook_user_id": a.facebook_user_id,
            "user_name": a.user_name,
            "user_email": a.user_email,
            "token_expiry": a.token_expiry.isoformat() if a.token_expiry else None,
            "last_used_at": a.last_used_at.isoformat() if a.last_used_at else None,
            "is_current": a.facebook_user_id == session.get("posting_user_id"),
            "owner_user_id": a.owner_user_id,
        }
        for a in accounts
    ]


class SwitchPostingAccountRequest(BaseModel):
    facebook_user_id: str


@app.post("/api/accounts/posting/switch")
async def api_switch_posting_account(
    req: SwitchPostingAccountRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Switch the current session to a different connected posting account.

    Enforces ownership: non-admin users can only switch to accounts they own,
    or legacy accounts with no recorded owner.
    """
    session = get_session(request)
    is_admin = session.get("user_role") == "admin"
    app_user_id: Optional[int] = session.get("user_id")

    result = await db.execute(
        select(ConnectedPostingAccount).where(
            ConnectedPostingAccount.facebook_user_id == req.facebook_user_id,
            ConnectedPostingAccount.is_active == True,
        )
    )
    acc = result.scalar_one_or_none()
    if not acc:
        raise HTTPException(404, "Account not found or disconnected")

    # Ownership check: block non-admin users from switching to someone else's account.
    if not is_admin and acc.owner_user_id is not None and app_user_id and acc.owner_user_id != app_user_id:
        raise HTTPException(403, "You do not have access to that account")
    existing = get_session(request)
    session_data = {**dict(existing), "posting_user_id": acc.facebook_user_id}
    response = JSONResponse({"success": True, "user_name": acc.user_name or acc.facebook_user_id})
    response.set_cookie(
        SESSION_COOKIE,
        create_session_token(session_data),
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
    )
    return response


@app.delete("/api/accounts/posting/{account_id}")
async def api_disconnect_posting(
    account_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    confirm: bool = False,
):
    """Disconnect a posting account.

    If the account has pending scheduled posts that will be orphaned, the
    endpoint returns HTTP 409 with the post count unless ``?confirm=true`` is
    passed.  Ownership is enforced: non-admins may only disconnect their own
    accounts.
    """
    session = get_session(request)
    is_admin = session.get("user_role") == "admin"
    app_user_id: Optional[int] = session.get("user_id")

    result = await db.execute(select(ConnectedPostingAccount).where(ConnectedPostingAccount.id == account_id))
    acc = result.scalar_one_or_none()
    if not acc:
        raise HTTPException(404, "Account not found")

    # Ownership guard.
    if not is_admin and acc.owner_user_id is not None and app_user_id and acc.owner_user_id != app_user_id:
        raise HTTPException(403, "You do not have permission to disconnect that account")

    # Count pending scheduled posts that will be stranded. The owner uid lives
    # inside the generic JSON job_data column, so we filter in Python rather than
    # with the PostgreSQL-only `.astext` operator (which raises on SQLite).
    pending_result = await db.execute(
        select(ScheduledPost).where(
            ScheduledPost.status == "pending",
            ScheduledPost.job_data.isnot(None),
        )
    )
    pending_count: int = sum(
        1 for p in pending_result.scalars().all()
        if (p.job_data or {}).get("posting_user_id") == acc.facebook_user_id
    )

    if pending_count > 0 and not confirm:
        return JSONResponse(
            status_code=409,
            content={
                "message": (
                    f"This account has {pending_count} pending scheduled "
                    f"Instagram post{'s' if pending_count != 1 else ''} that will "
                    "fail if you disconnect. Pass ?confirm=true to disconnect anyway."
                ),
                "pending_count": pending_count,
            },
        )

    acc.is_active = False
    await db.commit()
    return {"success": True, "pending_posts_cancelled": pending_count}


@app.post("/api/accounts/posting/token")
async def api_posting_direct_token(
    req: DirectTokenRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Connect a Posting account using a direct access token (no OAuth required)."""
    token = req.access_token.strip()
    if not token:
        raise HTTPException(400, "access_token is required")

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{settings.meta_graph_base_url}/me",
            params={"fields": "id,name,email", "access_token": token},
        )
    if r.status_code != 200:
        detail = r.json().get("error", {}).get("message", "Invalid token")
        raise HTTPException(400, f"Meta rejected the token: {detail}")

    data = r.json()
    user_id: str = data.get("id", "")
    user_name: str = data.get("name", "")
    user_email: str = data.get("email", "")

    if not user_id:
        raise HTTPException(400, "Could not retrieve user ID from Meta")

    result = await db.execute(
        select(ConnectedPostingAccount).where(ConnectedPostingAccount.facebook_user_id == user_id)
    )
    acc = result.scalar_one_or_none()
    encrypted = encryption.encrypt(token)

    session = get_session(request)
    connecting_user_id: Optional[int] = session.get("user_id")

    if acc:
        acc.encrypted_short_token = encrypted
        acc.encrypted_long_token = encrypted
        acc.user_name = user_name
        acc.user_email = user_email
        acc.token_expiry = None
        acc.is_active = True
        acc.last_used_at = datetime.utcnow()
        if acc.owner_user_id is None and connecting_user_id:
            acc.owner_user_id = connecting_user_id
    else:
        acc = ConnectedPostingAccount(
            facebook_user_id=user_id,
            user_name=user_name,
            user_email=user_email,
            encrypted_short_token=encrypted,
            encrypted_long_token=encrypted,
            token_expiry=None,
            created_at=datetime.utcnow(),
            last_used_at=datetime.utcnow(),
            is_active=True,
            owner_user_id=connecting_user_id,
        )
        db.add(acc)

    await db.commit()

    existing = get_session(request)
    session_data = {**dict(existing), "posting_user_id": user_id}
    session_token = create_session_token(session_data)
    response.set_cookie(
        SESSION_COOKIE, session_token,
        httponly=True, samesite="lax", max_age=86400 * 30,
    )
    return {"success": True, "user_id": user_id, "user_name": user_name}


# ── Meta Developer Apps CRUD ───────────────────────────────────────────────────

@app.get("/api/meta-apps")
async def api_list_meta_apps(
    request: Request,
    app_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List Meta developer apps. Secrets are never returned."""
    q = (
        select(MetaApp)
        .where(MetaApp.is_active == True)
        .order_by(MetaApp.app_type, MetaApp.sort_order, MetaApp.created_at)
    )
    if app_type:
        q = q.where(MetaApp.app_type == app_type)
    result = await db.execute(q)
    apps = result.scalars().all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "app_type": a.app_type,
            "app_id": a.app_id,
            "has_secret": bool(a.encrypted_app_secret),
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in apps
    ]


@app.post("/api/meta-apps")
async def api_create_meta_app(
    req: MetaAppCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a new Meta developer app credential entry."""
    if req.app_type not in ("ads", "posting"):
        raise HTTPException(400, "app_type must be 'ads' or 'posting'")
    if not req.app_id.strip():
        raise HTTPException(400, "app_id is required")
    if not req.app_secret.strip():
        raise HTTPException(400, "app_secret is required")
    result = await db.execute(
        select(MetaApp).where(MetaApp.app_type == req.app_type, MetaApp.is_active == True)
    )
    sort_order = len(result.scalars().all())
    app_obj = MetaApp(
        name=req.name.strip() or f"{req.app_type.title()} App",
        app_type=req.app_type,
        app_id=req.app_id.strip(),
        encrypted_app_secret=encryption.encrypt(req.app_secret.strip()),
        sort_order=sort_order,
        is_active=True,
    )
    db.add(app_obj)
    await db.commit()
    await db.refresh(app_obj)
    return {"success": True, "id": app_obj.id}


@app.put("/api/meta-apps/{meta_app_id}")
async def api_update_meta_app(
    meta_app_id: int,
    req: MetaAppUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update a Meta developer app — only name and/or secret can be changed."""
    result = await db.execute(select(MetaApp).where(MetaApp.id == meta_app_id))
    app_obj = result.scalar_one_or_none()
    if not app_obj:
        raise HTTPException(404, "App not found")
    if req.name is not None and req.name.strip():
        app_obj.name = req.name.strip()
    if req.app_secret and req.app_secret.strip():
        app_obj.encrypted_app_secret = encryption.encrypt(req.app_secret.strip())
    await db.commit()
    return {"success": True}


@app.delete("/api/meta-apps/{meta_app_id}")
async def api_delete_meta_app(
    meta_app_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Soft-delete a Meta developer app."""
    result = await db.execute(select(MetaApp).where(MetaApp.id == meta_app_id))
    app_obj = result.scalar_one_or_none()
    if not app_obj:
        raise HTTPException(404, "App not found")
    app_obj.is_active = False
    await db.commit()
    return {"success": True}


# ── Posting (Posts Manager) OAuth ─────────────────────────────────────────────

META_POSTING_SCOPES = ",".join([
    "pages_show_list", "pages_read_engagement", "pages_manage_posts",
    "instagram_content_publish", "instagram_manage_insights",
])

@app.get("/auth/meta/posting")
async def auth_meta_posting(
    request: Request,
    response: Response,
    app: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
):
    """Initiate Meta OAuth for the Posting app."""
    app_id_val = ""
    # Derive redirect_uri from the live request host (respecting proxy headers).
    fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    fwd_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    scheme = fwd_proto or request.url.scheme
    host = fwd_host or request.url.netloc
    posting_redirect_uri = f"{scheme}://{host}/auth/meta/posting/callback"
    if host.startswith("localhost") or host.startswith("127.0.0.1"):
        posting_redirect_uri = settings.meta_posting_redirect_uri

    if app:
        result = await db.execute(
            select(MetaApp).where(MetaApp.id == app, MetaApp.app_type == "posting", MetaApp.is_active == True)
        )
        db_app = result.scalar_one_or_none()
        if not db_app:
            return RedirectResponse("/?error=posting_app_not_found")
        app_id_val = db_app.app_id
        response.set_cookie("oauth_posting_app_id", str(app), max_age=600, httponly=True, samesite="lax")
    else:
        result = await db.execute(
            select(MetaApp).where(MetaApp.app_type == "posting", MetaApp.is_active == True)
            .order_by(MetaApp.sort_order).limit(1)
        )
        db_app = result.scalar_one_or_none()
        if db_app:
            app_id_val = db_app.app_id
            response.set_cookie("oauth_posting_app_id", str(db_app.id), max_age=600, httponly=True, samesite="lax")
        else:
            app_id_val = settings.META_POSTING_APP_ID

    if not app_id_val:
        return RedirectResponse("/?error=posting_app_not_configured")

    state = generate_oauth_state()
    response.set_cookie("oauth_state_posting", state, max_age=600, httponly=True, samesite="lax")
    response.set_cookie("oauth_posting_redirect_uri", posting_redirect_uri, max_age=600, httponly=True, samesite="lax")

    # Same logic as the ads app: use the Business-login config_id flow when a
    # configuration ID is set, otherwise the classic scope-based flow.
    posting_config_id = settings.META_POSTING_CONFIG_ID.strip()
    if posting_config_id:
        params = urllib.parse.urlencode({
            "client_id": app_id_val,
            "config_id": posting_config_id,
            "redirect_uri": posting_redirect_uri,
            "response_type": "code",
            "override_default_response_type": "true",
            "state": state,
        })
        oauth_base = f"https://www.facebook.com/{settings.META_API_VERSION}/dialog/oauth"
    else:
        params = urllib.parse.urlencode({
            "client_id": app_id_val,
            "redirect_uri": posting_redirect_uri,
            "scope": META_POSTING_SCOPES,
            "response_type": "code",
            "state": state,
        })
        oauth_base = "https://www.facebook.com/dialog/oauth"
    return RedirectResponse(f"{oauth_base}?{params}", headers=response.headers)


@app.get("/auth/meta/posting/callback")
async def auth_meta_posting_callback(
    request: Request,
    response: Response,
    code: str = "",
    state: str = "",
    error: str = "",
    db: AsyncSession = Depends(get_db),
):
    if error:
        return RedirectResponse(f"/?error={urllib.parse.quote(error)}")

    expected_state = request.cookies.get("oauth_state_posting", "")
    if not verify_oauth_state(state, expected_state):
        return RedirectResponse("/?error=invalid_state")

    _papp_id = settings.META_POSTING_APP_ID
    _papp_secret = settings.META_POSTING_APP_SECRET
    _papp_db_id_cookie = request.cookies.get("oauth_posting_app_id")
    if _papp_db_id_cookie:
        try:
            _pres = await db.execute(
                select(MetaApp).where(MetaApp.id == int(_papp_db_id_cookie), MetaApp.is_active == True)
            )
            _pdb_app = _pres.scalar_one_or_none()
            if _pdb_app:
                _papp_id = _pdb_app.app_id
                _papp_secret = encryption.decrypt(_pdb_app.encrypted_app_secret)
        except Exception:
            pass

    _posting_redirect_uri = request.cookies.get("oauth_posting_redirect_uri") or settings.meta_posting_redirect_uri
    short = await meta_api.exchange_code_for_token(
        code, _papp_id, _papp_secret, _posting_redirect_uri
    )
    if not short.get("success"):
        return RedirectResponse(f"/?error={urllib.parse.quote(short.get('error', 'token_exchange_failed'))}")

    short_token = short["data"].get("access_token", "")

    long = await meta_api.exchange_for_long_lived_token(
        short_token, _papp_id, _papp_secret
    )
    if not long.get("success"):
        return RedirectResponse("/?error=posting_long_token_failed")

    long_token = long["data"].get("access_token", "")
    expires_in = long["data"].get("expires_in", 5184000)

    user = await meta_api.get_user_info(long_token)
    if not user.get("success"):
        return RedirectResponse("/?error=posting_user_info_failed")

    uid = user["data"].get("id", "")
    name = user["data"].get("name", "")
    email = user["data"].get("email", "")

    result = await db.execute(
        select(ConnectedPostingAccount).where(ConnectedPostingAccount.facebook_user_id == uid)
    )
    acc = result.scalar_one_or_none()
    now = datetime.utcnow()
    # Resolve the app-user performing this OAuth so we can link the account.
    existing_token = request.cookies.get(SESSION_COOKIE)
    existing_session = (verify_session_token(existing_token) if existing_token else None) or {}
    connecting_user_id: Optional[int] = existing_session.get("user_id")
    try:
        _posting_app_db_id = int(_papp_db_id_cookie) if _papp_db_id_cookie else None
    except (TypeError, ValueError):
        _posting_app_db_id = None
    if acc:
        acc.encrypted_short_token = encryption.encrypt(short_token)
        acc.encrypted_long_token = encryption.encrypt(long_token)
        acc.token_expiry = now + timedelta(seconds=expires_in)
        acc.user_name = name
        acc.user_email = email
        acc.is_active = True
        acc.last_used_at = now
        acc.meta_app_db_id = _posting_app_db_id
        # Update owner only if not set yet, or if an admin re-connects on behalf.
        if acc.owner_user_id is None and connecting_user_id:
            acc.owner_user_id = connecting_user_id
    else:
        acc = ConnectedPostingAccount(
            facebook_user_id=uid,
            user_name=name,
            user_email=email,
            encrypted_short_token=encryption.encrypt(short_token),
            encrypted_long_token=encryption.encrypt(long_token),
            token_expiry=now + timedelta(seconds=expires_in),
            created_at=now,
            last_used_at=now,
            is_active=True,
            owner_user_id=connecting_user_id,
            meta_app_db_id=_posting_app_db_id,
        )
        db.add(acc)
    await db.commit()

    # Merge posting_user_id into existing session so user auth cookie is preserved
    session_data = {**existing_session, "posting_user_id": uid}
    session_token = create_session_token(session_data)
    redirect = RedirectResponse("/auth/done?type=posting")
    redirect.set_cookie(
        SESSION_COOKIE, session_token,
        max_age=_session_cookie_max_age(session_data), httponly=True, samesite="lax"
    )
    redirect.delete_cookie("oauth_state_posting")
    redirect.delete_cookie("oauth_posting_app_id")
    return redirect

# ── Account API routes ─────────────────────────────────────────────────────────

@app.get("/api/accounts/meta")
async def api_meta_accounts(request: Request, db: AsyncSession = Depends(get_db)):
    """List connected Meta accounts (no tokens exposed)."""
    session = get_session(request)
    result = await db.execute(
        select(ConnectedMetaAccount).where(ConnectedMetaAccount.is_active == True)
    )
    accounts = result.scalars().all()
    return [
        {
            "id": a.id,
            "facebook_user_id": a.facebook_user_id,
            "user_name": a.user_name,
            "user_email": a.user_email,
            "token_expiry": a.token_expiry.isoformat() if a.token_expiry else None,
            "last_used_at": a.last_used_at.isoformat() if a.last_used_at else None,
            "is_current": a.facebook_user_id == session.get("meta_user_id"),
        }
        for a in accounts
    ]


@app.delete("/api/accounts/meta/{account_id}")
async def api_disconnect_meta(account_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ConnectedMetaAccount).where(ConnectedMetaAccount.id == account_id))
    acc = result.scalar_one_or_none()
    if not acc:
        raise HTTPException(404, "Account not found")
    acc.is_active = False
    await db.commit()
    return {"success": True}


@app.post("/api/accounts/meta/token")
async def api_meta_direct_token(
    req: DirectTokenRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Connect a Meta account using a direct access token (no OAuth required).

    Accepts a system user token or any long-lived Meta access token.
    Validates it against the Graph API, then stores it exactly like an
    OAuth-obtained token and creates a session.
    """
    token = req.access_token.strip()
    if not token:
        raise HTTPException(400, "access_token is required")

    # Validate token and fetch user info from Graph API
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{settings.meta_graph_base_url}/me",
            params={"fields": "id,name,email", "access_token": token},
        )
    if r.status_code != 200:
        detail = r.json().get("error", {}).get("message", "Invalid token")
        raise HTTPException(400, f"Meta rejected the token: {detail}")

    data = r.json()
    user_id: str = data.get("id", "")
    user_name: str = data.get("name", "")
    user_email: str = data.get("email", "")

    if not user_id:
        raise HTTPException(400, "Could not retrieve user ID from Meta")

    # Upsert the account record
    result = await db.execute(
        select(ConnectedMetaAccount).where(
            ConnectedMetaAccount.facebook_user_id == user_id
        )
    )
    acc = result.scalar_one_or_none()
    encrypted = encryption.encrypt(token)

    if acc:
        acc.encrypted_short_token = encrypted
        acc.encrypted_long_token = encrypted
        acc.user_name = user_name
        acc.user_email = user_email
        acc.token_expiry = None  # system user tokens don't expire
        acc.is_active = True
        acc.last_used_at = datetime.utcnow()
    else:
        acc = ConnectedMetaAccount(
            facebook_user_id=user_id,
            user_name=user_name,
            user_email=user_email,
            encrypted_short_token=encrypted,
            encrypted_long_token=encrypted,
            token_expiry=None,
            is_active=True,
        )
        db.add(acc)

    await db.commit()

    # Create session
    session_token = create_session_token({"meta_user_id": user_id})
    response.set_cookie(
        SESSION_COOKIE, session_token,
        httponly=True, samesite="lax", max_age=86400 * 30,
    )
    return {
        "success": True,
        "user_id": user_id,
        "user_name": user_name,
    }


@app.get("/api/accounts/google")
async def api_google_accounts(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    result = await db.execute(
        select(ConnectedGoogleAccount).where(ConnectedGoogleAccount.is_active == True)
    )
    accounts = result.scalars().all()
    return [
        {
            "id": a.id,
            "google_user_id": a.google_user_id,
            "user_name": a.user_name,
            "user_email": a.user_email,
            "token_expiry": a.token_expiry.isoformat() if a.token_expiry else None,
            "is_current": a.google_user_id == session.get("google_user_id"),
        }
        for a in accounts
    ]


@app.delete("/api/accounts/google/{account_id}")
async def api_disconnect_google(account_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ConnectedGoogleAccount).where(ConnectedGoogleAccount.id == account_id))
    acc = result.scalar_one_or_none()
    if not acc:
        raise HTTPException(404, "Account not found")
    acc.is_active = False
    await db.commit()
    return {"success": True}


@app.get("/api/meta/ad-accounts")
async def api_ad_accounts(request: Request, db: AsyncSession = Depends(get_db)):
    token = await get_meta_token(request, db)
    uid = get_session(request).get("meta_user_id", "anon")
    # Bust the agent's account cache so next chat turn gets fresh data
    invalidate_account_cache(uid)
    result = await meta_api.get_ad_accounts(token)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    await api_tracker.record_call(uid)
    await bump_user_usage(db, get_session(request).get("user_id"), meta_calls=1)
    return result["data"]


@app.get("/api/meta/pages")
async def api_pages(request: Request, db: AsyncSession = Depends(get_db)):
    token = await get_meta_token(request, db)
    uid = get_session(request).get("meta_user_id", "anon")
    invalidate_account_cache(uid)
    result = await meta_api.get_pages(token)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    await api_tracker.record_call(uid)
    await bump_user_usage(db, get_session(request).get("user_id"), meta_calls=1)
    return result["data"]


@app.get("/api/meta/pixels/{ad_account_id}")
async def api_pixels(ad_account_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    token = await get_meta_token(request, db)
    clean_id = ad_account_id[4:] if ad_account_id.startswith("act_") else ad_account_id
    result = await meta_api.get_pixels(token, clean_id)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    uid = get_session(request).get("meta_user_id", "anon")
    await api_tracker.record_call(uid)
    await bump_user_usage(db, get_session(request).get("user_id"), meta_calls=1)
    return result["data"]


@app.get("/api/meta/instagram/{page_id}")
async def api_instagram(page_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    token = await get_meta_token(request, db)
    # Instagram Business Account lookup requires the page-scoped token, not the user token
    page_token = await meta_api.get_page_access_token(token, page_id)
    result = await meta_api.get_instagram_accounts(token, page_id, page_token=page_token)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    uid = get_session(request).get("meta_user_id", "anon")
    await api_tracker.record_call(uid)
    await bump_user_usage(db, get_session(request).get("user_id"), meta_calls=1)
    return result["data"]


# ── Client CRUD ────────────────────────────────────────────────────────────────

@app.get("/api/clients")
async def api_list_clients(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Client).where(Client.is_archived == False).order_by(Client.sort_order, Client.name)
    )
    clients = result.scalars().all()
    out = []
    for c in clients:
        ad_result = await db.execute(
            select(ClientAdAccount).where(ClientAdAccount.client_id == c.id).order_by(ClientAdAccount.sort_order)
        )
        ad_accounts = ad_result.scalars().all()
        out.append({
            "id": c.id, "name": c.name, "industry": c.industry,
            "website": c.website, "notes": c.notes, "color_tag": c.color_tag,
            "is_archived": c.is_archived, "sort_order": c.sort_order,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "ad_accounts": [
                {
                    "id": a.id, "nickname": a.nickname,
                    "meta_account_id": a.meta_account_id,
                    "default_page_id": a.default_page_id,
                    "default_page_name": a.default_page_name,
                    "default_pixel_id": a.default_pixel_id,
                    "default_pixel_name": a.default_pixel_name,
                    "default_instagram_id": a.default_instagram_id,
                    "default_instagram_username": a.default_instagram_username,
                    "default_daily_budget": a.default_daily_budget,
                    "default_countries": a.default_countries,
                    "default_age_min": a.default_age_min,
                    "default_age_max": a.default_age_max,
                    "default_timezone": a.default_timezone,
                    "default_objective": a.default_objective,
                    "is_default": a.is_default,
                }
                for a in ad_accounts
            ],
        })
    return out


@app.post("/api/clients", status_code=201)
async def api_create_client(body: CreateClientRequest, request: Request, db: AsyncSession = Depends(get_db)):
    client = Client(
        name=sanitize_text(body.name, 200),
        industry=body.industry,
        website=body.website,
        notes=sanitize_text(body.notes or "", 5000),
        color_tag=body.color_tag,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(client)
    await db.commit()
    await db.refresh(client)
    return {"id": client.id, "name": client.name}


@app.put("/api/clients/{client_id}")
async def api_update_client(client_id: int, body: UpdateClientRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Client).where(Client.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")
    if body.name is not None:
        client.name = sanitize_text(body.name, 200)
    if body.industry is not None:
        client.industry = body.industry
    if body.website is not None:
        client.website = body.website
    if body.notes is not None:
        client.notes = sanitize_text(body.notes, 5000)
    if body.color_tag is not None:
        client.color_tag = body.color_tag
    if body.is_archived is not None:
        client.is_archived = body.is_archived
    if body.sort_order is not None:
        client.sort_order = body.sort_order
    client.updated_at = datetime.utcnow()
    await db.commit()
    return {"success": True}


@app.delete("/api/clients/{client_id}")
async def api_delete_client(client_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Client).where(Client.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")
    await db.execute(delete(ClientAdAccount).where(ClientAdAccount.client_id == client_id))
    await db.execute(delete(Conversation).where(Conversation.client_id == client_id))
    await db.delete(client)
    await db.commit()
    return {"success": True}


@app.post("/api/clients/{client_id}/ad-accounts", status_code=201)
async def api_add_ad_account(client_id: int, body: CreateAdAccountRequest, request: Request, db: AsyncSession = Depends(get_db)):
    acc = ClientAdAccount(
        client_id=client_id,
        nickname=sanitize_text(body.nickname, 200),
        meta_account_id=body.meta_account_id,
        default_page_id=body.default_page_id,
        default_page_name=body.default_page_name,
        default_pixel_id=body.default_pixel_id,
        default_pixel_name=body.default_pixel_name,
        default_instagram_id=body.default_instagram_id,
        default_instagram_username=body.default_instagram_username,
        default_daily_budget=body.default_daily_budget,
        default_countries=body.default_countries,
        default_age_min=body.default_age_min,
        default_age_max=body.default_age_max,
        default_timezone=body.default_timezone,
        default_objective=body.default_objective,
        is_default=body.is_default,
        created_at=datetime.utcnow(),
    )
    db.add(acc)
    await db.commit()
    await db.refresh(acc)
    return {"id": acc.id}


@app.delete("/api/clients/{client_id}/ad-accounts/{account_id}")
async def api_delete_ad_account(client_id: int, account_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    await db.execute(
        delete(ClientAdAccount).where(
            ClientAdAccount.id == account_id,
            ClientAdAccount.client_id == client_id,
        )
    )
    await db.commit()
    return {"success": True}


# ── Conversations ──────────────────────────────────────────────────────────────

@app.get("/api/conversations")
async def api_list_conversations(request: Request, client_id: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    query = select(Conversation).where(Conversation.is_archived == False)
    if client_id:
        query = query.where(Conversation.client_id == client_id)
    query = query.order_by(Conversation.is_pinned.desc(), Conversation.updated_at.desc())
    result = await db.execute(query)
    convs = result.scalars().all()
    return [
        {
            "id": c.id, "title": c.title, "client_id": c.client_id,
            "client_ad_account_id": c.client_ad_account_id,
            "is_pinned": c.is_pinned, "is_archived": c.is_archived,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        }
        for c in convs
    ]


@app.post("/api/conversations", status_code=201)
async def api_create_conversation(body: CreateConversationRequest, request: Request, db: AsyncSession = Depends(get_db)):
    conv = Conversation(
        client_id=body.client_id,
        client_ad_account_id=body.client_ad_account_id,
        title=sanitize_text(body.title, 500),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(conv)
    await db.flush()
    ctx = ActiveContext(
        conversation_id=conv.id,
        updated_at=datetime.utcnow(),
    )
    db.add(ctx)
    await db.commit()
    await db.refresh(conv)
    return {"id": conv.id, "title": conv.title}


@app.get("/api/conversations/{conv_id}")
async def api_get_conversation(conv_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Conversation).where(Conversation.id == conv_id))
    conv = result.scalar_one_or_none()
    if not conv:
        raise HTTPException(404, "Conversation not found")
    msg_result = await db.execute(
        select(Message).where(Message.conversation_id == conv_id).order_by(Message.created_at).limit(100)
    )
    messages = msg_result.scalars().all()
    return {
        "id": conv.id, "title": conv.title, "client_id": conv.client_id,
        "is_pinned": conv.is_pinned,
        "messages": [
            {
                "id": m.id, "role": m.role, "content": m.content,
                "created_at": m.created_at.isoformat() if m.created_at else None,
            }
            for m in messages
        ],
    }


@app.put("/api/conversations/{conv_id}")
async def api_update_conversation(conv_id: int, body: UpdateConversationRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Conversation).where(Conversation.id == conv_id))
    conv = result.scalar_one_or_none()
    if not conv:
        raise HTTPException(404, "Conversation not found")
    if body.title is not None:
        conv.title = sanitize_text(body.title, 500)
    if body.is_pinned is not None:
        conv.is_pinned = body.is_pinned
    if body.is_archived is not None:
        conv.is_archived = body.is_archived
    conv.updated_at = datetime.utcnow()
    await db.commit()
    return {"success": True}


@app.delete("/api/conversations/{conv_id}")
async def api_delete_conversation(conv_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    await db.execute(delete(Message).where(Message.conversation_id == conv_id))
    await db.execute(delete(ActiveContext).where(ActiveContext.conversation_id == conv_id))
    await db.execute(delete(Conversation).where(Conversation.id == conv_id))
    await db.commit()
    return {"success": True}


@app.get("/api/conversations/{conv_id}/context")
async def api_get_context(conv_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ActiveContext).where(ActiveContext.conversation_id == conv_id))
    ctx = result.scalar_one_or_none()
    if not ctx:
        return {}
    return {
        "selected_meta_account_id": ctx.selected_meta_account_id,
        "selected_ad_account_id": ctx.selected_ad_account_id,
        "selected_page_id": ctx.selected_page_id,
        "selected_pixel_id": ctx.selected_pixel_id,
        "selected_instagram_id": ctx.selected_instagram_id,
        "selected_timezone": ctx.selected_timezone,
        "overrides": ctx.overrides,
    }


@app.put("/api/conversations/{conv_id}/context")
async def api_update_context(conv_id: int, body: UpdateContextRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ActiveContext).where(ActiveContext.conversation_id == conv_id))
    ctx = result.scalar_one_or_none()
    if not ctx:
        ctx = ActiveContext(conversation_id=conv_id, updated_at=datetime.utcnow())
        db.add(ctx)
    if body.selected_meta_account_id is not None:
        ctx.selected_meta_account_id = body.selected_meta_account_id
    if body.selected_ad_account_id is not None:
        ctx.selected_ad_account_id = body.selected_ad_account_id
    if body.selected_page_id is not None:
        ctx.selected_page_id = body.selected_page_id
    if body.selected_pixel_id is not None:
        ctx.selected_pixel_id = body.selected_pixel_id
    if body.selected_instagram_id is not None:
        ctx.selected_instagram_id = body.selected_instagram_id
    if body.selected_timezone is not None:
        ctx.selected_timezone = body.selected_timezone
    if body.overrides is not None:
        ctx.overrides = body.overrides
    ctx.updated_at = datetime.utcnow()
    await db.commit()
    invalidate_system_prompt(conv_id)
    return {"success": True}


# ── Chat (SSE streaming) ───────────────────────────────────────────────────────

@app.post("/api/chat/{conv_id}")
@limiter.limit("60/minute")
async def api_chat(conv_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    if agent._provider == "none":
        reason = getattr(agent, "_init_error", None) or "No AI provider configured — add an API key (Claude, OpenAI or Groq) in Settings first. A Meta connection is NOT required to chat."
        raise HTTPException(400, reason)

    body = await request.json()
    message = sanitize_text(body.get("message", ""), 50000)
    if not message:
        raise HTTPException(400, "Message is required")

    session = get_session(request)

    async def event_stream():
        async for chunk in agent.stream_response(conv_id, message, session, db):
            yield chunk

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── File uploads ───────────────────────────────────────────────────────────────

_session_uploads: dict[str, list[dict]] = {}


def _upload_session_key(session: dict) -> str:
    """Per-user key for the upload tray.

    Keyed by the app login user id first — meta_user_id is only present when
    the Ads OAuth ran in this browser session, so keying by it alone dumped
    every posting-only user into one shared "anon" bucket (cross-user leak).
    """
    return str(session.get("user_id") or session.get("meta_user_id") or "anon")


@app.post("/api/upload")
@limiter.limit("30/minute")
async def api_upload(request: Request, file: UploadFile = File(...)):
    session = get_session(request)
    session_key = _upload_session_key(session)

    if not validate_file_extension(file.filename or ""):
        raise HTTPException(400, "File type not allowed")

    file_bytes = await file.read()
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(file_bytes) > max_bytes:
        raise HTTPException(400, f"File too large (max {settings.MAX_UPLOAD_SIZE_MB}MB)")

    if not validate_mime_type(file_bytes, file.filename or ""):
        raise HTTPException(400, "File MIME type does not match extension")

    result = await process_uploaded_file(file_bytes, file.filename or "upload")
    if not result.get("success"):
        raise HTTPException(500, result.get("error", "Upload failed"))

    upload_info = {
        "file_id": result["stored_path"].split("/")[-1],
        "name": result["original_name"],
        "type": result["file_type"],
        "path": result["stored_path"],
        "sha256": result["sha256"],
    }
    _session_uploads.setdefault(session_key, []).append(upload_info)
    return upload_info


@app.get("/api/uploads")
async def api_list_uploads(request: Request):
    session = get_session(request)
    session_key = _upload_session_key(session)
    return _session_uploads.get(session_key, [])


_UPLOAD_MIME_BY_SUFFIX = {
    ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".mp4": "video/mp4", ".mov": "video/quicktime",
}


@app.get("/api/uploads/{file_id}")
async def api_get_upload(file_id: str, request: Request):
    """Serve an uploaded or Drive-cached media file from the uploads dir.

    Used by the calendar to show scheduled-post thumbnails (chips + preview
    modal reference /api/uploads/<local_file_id|cache_file_id>). Serves
    straight from disk so it works for drivecache_* files and survives
    server restarts (unlike the in-memory _session_uploads tray).
    Auth comes from the session cookie, which browsers send with <img> requests.
    """
    if "/" in file_id or "\\" in file_id or file_id in (".", "..") or file_id.startswith("."):
        raise HTTPException(404, "File not found")
    path = _UPLOAD_DIR / file_id
    if not path.is_file():
        raise HTTPException(404, "File not found")
    mime = _UPLOAD_MIME_BY_SUFFIX.get(path.suffix.lower())
    if not mime:
        # drivecache_* files are stored without an extension — sniff the magic
        # bytes (the global nosniff header stops the browser doing it for us).
        async with aiofiles.open(path, "rb") as fh:
            head = await fh.read(16)
        if head.startswith(b"\xff\xd8\xff"):
            mime = "image/jpeg"
        elif head.startswith(b"\x89PNG"):
            mime = "image/png"
        elif head.startswith(b"GIF8"):
            mime = "image/gif"
        elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            mime = "image/webp"
        elif head[4:8] == b"ftyp":
            mime = "video/mp4"
        else:
            mime = "application/octet-stream"

    async def _iter():
        async with aiofiles.open(path, "rb") as fh:
            while chunk := await fh.read(65536):
                yield chunk

    return StreamingResponse(_iter(), media_type=mime, headers={"Cache-Control": "private, max-age=300"})


@app.delete("/api/uploads/{file_id}")
async def api_delete_upload(file_id: str, request: Request):
    session = get_session(request)
    session_key = _upload_session_key(session)
    uploads = _session_uploads.get(session_key, [])
    path = None
    for u in uploads:
        if u["file_id"] == file_id:
            path = u["path"]
            break
    if path:
        # Never delete a file that a pending/scheduled post still needs —
        # otherwise that post is guaranteed to fail at publish time. The file
        # is removed from the user's upload tray either way; the physical file
        # stays on disk until the post publishes (then the hourly purge gets it).
        protected = await _protected_upload_ids()
        if protected is not None and file_id not in protected:
            import os
            try:
                os.unlink(path)
            except OSError:
                pass
        _session_uploads[session_key] = [u for u in uploads if u["file_id"] != file_id]
    return {"success": True}


# ── Skills ─────────────────────────────────────────────────────────────────────

@app.get("/api/skills")
async def api_list_skills(request: Request, client_id: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    skills = await get_all_skills(db, client_id)
    return skills


@app.post("/api/skills", status_code=201)
async def api_create_skill(body: CreateSkillRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await create_skill(
        sanitize_text(body.name, 200),
        body.description,
        body.content,
        body.client_id,
        db,
    )
    if not result.get("success"):
        raise HTTPException(500, result.get("error", "Failed to create skill"))
    _system_prompt_cache.clear()
    return result


@app.put("/api/skills/{skill_id}")
async def api_update_skill(skill_id: int, body: UpdateSkillRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await update_skill(skill_id, body.content, db)
    if not result.get("success"):
        raise HTTPException(500, result.get("error", "Failed to update skill"))
    _system_prompt_cache.clear()
    return result


@app.patch("/api/skills/{skill_id}/toggle")
async def api_toggle_skill(skill_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    is_active = body.get("is_active", True)
    result = await toggle_skill(skill_id, is_active, db)
    _system_prompt_cache.clear()
    return result


@app.delete("/api/skills/{skill_id}")
async def api_delete_skill(skill_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await delete_skill(skill_id, db)
    _system_prompt_cache.clear()
    return result


# ── Quick Commands ─────────────────────────────────────────────────────────────

@app.get("/api/quick-commands")
async def api_list_commands(request: Request, client_id: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    commands = await get_quick_commands(client_id, db)
    return commands


@app.post("/api/quick-commands", status_code=201)
async def api_create_command(body: CreateQuickCommandRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await create_quick_command(
        body.trigger, body.name, body.description,
        body.prompt_template, body.client_id, db,
    )
    return result


@app.delete("/api/quick-commands/{cmd_id}")
async def api_delete_command(cmd_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(QuickCommand).where(QuickCommand.id == cmd_id))
    cmd = result.scalar_one_or_none()
    if cmd:
        await db.delete(cmd)
        await db.commit()
    return {"success": True}


@app.get("/api/quick-commands/export")
async def api_export_commands(request: Request, db: AsyncSession = Depends(get_db)):
    commands = await get_quick_commands(None, db)
    return JSONResponse(content=commands, headers={"Content-Disposition": "attachment; filename=quick-commands.json"})


@app.post("/api/quick-commands/import")
async def api_import_commands(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    if not isinstance(body, list):
        raise HTTPException(400, "Expected a JSON array")
    imported = 0
    for cmd in body:
        try:
            await create_quick_command(
                cmd["trigger"], cmd["name"], cmd.get("description"),
                cmd["prompt_template"], cmd.get("client_id"), db,
            )
            imported += 1
        except Exception:
            pass
    return {"imported": imported}


# ── Campaigns (proxy) ──────────────────────────────────────────────────────────

@app.get("/api/campaigns/{ad_account_id}")
async def api_get_campaigns(ad_account_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    token = await get_meta_token(request, db)
    result = await meta_api.get_campaigns(token, ad_account_id)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    return result["data"]


@app.post("/api/campaigns")
async def api_create_campaign(body: CreateCampaignRequest, request: Request, db: AsyncSession = Depends(get_db)):
    token = await get_meta_token(request, db)
    result = await meta_api.create_campaign(
        token, body.ad_account_id, body.name, body.objective, body.status
    )
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    return result["data"]


@app.patch("/api/campaigns/{campaign_id}/pause")
async def api_pause_campaign(campaign_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    token = await get_meta_token(request, db)
    result = await meta_api.pause_campaign(token, campaign_id)
    return result


@app.patch("/api/campaigns/{campaign_id}/activate")
async def api_activate_campaign(campaign_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    token = await get_meta_token(request, db)
    result = await meta_api.activate_campaign(token, campaign_id)
    return result


@app.delete("/api/campaigns/{campaign_id}")
async def api_delete_campaign(campaign_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    token = await get_meta_token(request, db)
    result = await meta_api.delete_campaign(token, campaign_id)
    return result


# ── Posting-specific endpoints ────────────────────────────────────────────────

@app.get("/api/posting/debug")
async def api_posting_debug(request: Request, db: AsyncSession = Depends(get_db)):
    """Diagnostic: show granted permissions and raw pages result for the posting token."""
    import traceback as _tb
    out: dict = {"steps": {}}
    # Step 1: resolve token
    token = None
    try:
        token = await get_posting_token(request, db)
        out["steps"]["get_token"] = "ok"
        out["token_prefix"] = token[:20] + "..." if token else None
    except HTTPException as e:
        out["steps"]["get_token"] = f"HTTPException {e.status_code}: {e.detail}"
        return out
    except Exception as e:
        out["steps"]["get_token"] = f"Exception: {_tb.format_exc()}"
        return out
    # Step 2: permissions
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            rp = await client.get(
                f"{settings.meta_graph_base_url}/me/permissions",
                params={"access_token": token},
            )
            out["permissions"] = rp.json() if rp.status_code == 200 else {"status": rp.status_code, "body": rp.text}
            out["steps"]["permissions"] = f"status {rp.status_code}"
    except Exception as e:
        out["steps"]["permissions"] = f"Exception: {_tb.format_exc()}"
    # Step 3: /me/accounts
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            ra = await client.get(
                f"{settings.meta_graph_base_url}/me/accounts",
                params={"fields": "id,name,category,access_token", "access_token": token},
            )
            out["me_accounts"] = ra.json() if ra.status_code == 200 else {"status": ra.status_code, "body": ra.text}
            out["steps"]["me_accounts"] = f"status {ra.status_code}"
    except Exception as e:
        out["steps"]["me_accounts"] = f"Exception: {_tb.format_exc()}"
    # Step 4: /me (who is the token owner)
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            rm = await client.get(
                f"{settings.meta_graph_base_url}/me",
                params={"fields": "id,name", "access_token": token},
            )
            out["me"] = rm.json() if rm.status_code == 200 else {"status": rm.status_code, "body": rm.text}
            out["steps"]["me"] = f"status {rm.status_code}"
    except Exception as e:
        out["steps"]["me"] = f"Exception: {_tb.format_exc()}"
    # Step 5: which OAuth flow is configured + app id (no secrets)
    out["oauth_flow"] = "business_login (config_id)" if settings.META_POSTING_CONFIG_ID.strip() else "classic_scope"
    out["app_id"] = settings.META_POSTING_APP_ID or "(none)"
    # Step 5b: base URL used for Instagram media proxy (MUST be publicly reachable)
    out["base_url"] = {
        "from_request": _public_base_url(request),
        "from_settings": (settings.BASE_URL or "").strip().rstrip("/") or "(not set)",
        "effective_for_scheduled_posts": _effective_base_url() or "(empty — scheduled IG posts will use job's base_url)",
        "warning": (
            "⚠️ BASE_URL appears to be localhost — Instagram publishing will FAIL because Meta cannot reach localhost."
            if (_effective_base_url() or _public_base_url(request)).startswith("http://localhost") or
               (_effective_base_url() or _public_base_url(request)).startswith("http://127.")
            else "✓ URL looks deployable" if (_effective_base_url() or _public_base_url(request)).startswith("https://")
            else "⚠️ URL is HTTP (not HTTPS) — Meta may reject it for Instagram media"
        ),
    }
    # Step 6: business portfolios the token owner belongs to
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            rb = await client.get(
                f"{settings.meta_graph_base_url}/me/businesses",
                params={"fields": "id,name", "access_token": token},
            )
            out["me_businesses"] = rb.json() if rb.status_code == 200 else {"status": rb.status_code, "body": rb.text}
            out["steps"]["me_businesses"] = f"status {rb.status_code}"
    except Exception as e:
        out["steps"]["me_businesses"] = f"Exception: {_tb.format_exc()}"
    # Step 7: token debug — granted scopes & whether token is valid/which app issued it
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            rd = await client.get(
                f"{settings.meta_graph_base_url}/debug_token",
                params={"input_token": token, "access_token": token},
            )
            if rd.status_code == 200:
                d = rd.json().get("data", {})
                out["token_debug"] = {
                    "app_id": d.get("app_id"),
                    "type": d.get("type"),
                    "is_valid": d.get("is_valid"),
                    "scopes": d.get("scopes"),
                    "granular_scopes": d.get("granular_scopes"),
                }
            else:
                out["token_debug"] = {"status": rd.status_code, "body": rd.text}
            out["steps"]["token_debug"] = f"status {rd.status_code}"
    except Exception as e:
        out["steps"]["token_debug"] = f"Exception: {_tb.format_exc()}"
    # Step 8: probe every connected Instagram account directly with this token.
    # A code-2 (or permission error) here means the token cannot post to that
    # account, regardless of media URLs or Content-Length.
    try:
        result = await db.execute(
            select(ConnectedPostingAccount).where(ConnectedPostingAccount.is_active == True)
        )
        posting_accs = result.scalars().all()
        ig_probes: list[dict] = []
        async with httpx.AsyncClient(timeout=20) as client:
            for acc in posting_accs:
                acc_token = encryption.decrypt(acc.encrypted_long_token)
                # List Instagram accounts linked to each FB page this token can see.
                accs_r = await client.get(
                    f"{settings.meta_graph_base_url}/me/accounts",
                    params={"fields": "id,name,instagram_business_account", "limit": 100,
                            "access_token": acc_token},
                )
                if accs_r.status_code != 200:
                    ig_probes.append({"posting_account": acc.facebook_user_id,
                                      "error": f"HTTP {accs_r.status_code}: {accs_r.text[:200]}"})
                    continue
                pages = (accs_r.json() or {}).get("data", [])
                for pg in pages:
                    ig_biz = pg.get("instagram_business_account", {})
                    ig_id = ig_biz.get("id") if isinstance(ig_biz, dict) else None
                    if not ig_id:
                        continue
                    # Try a direct read of the IG account — verifies the token has
                    # the right to call /{ig_id}/media (publish will fail if this does).
                    pr = await client.get(
                        f"{settings.meta_graph_base_url}/{ig_id}",
                        params={"fields": "id,name,username,followers_count", "access_token": acc_token},
                    )
                    pr_data = pr.json() if pr.content else {}
                    # Also check granular scopes for instagram_content_publish on this account
                    gs_r = await client.get(
                        f"{settings.meta_graph_base_url}/debug_token",
                        params={"input_token": acc_token, "access_token": acc_token},
                    )
                    gs_data = {}
                    if gs_r.status_code == 200:
                        gs_data = gs_r.json().get("data", {})
                    ig_probes.append({
                        "posting_user": acc.facebook_user_id,
                        "fb_page": pg.get("id"),
                        "fb_page_name": pg.get("name"),
                        "ig_id": ig_id,
                        "read_status": pr.status_code,
                        "read_result": pr_data,
                        "has_instagram_content_publish": "instagram_content_publish" in (gs_data.get("scopes") or []),
                        "granular_ig_scopes": [
                            s for s in (gs_data.get("granular_scopes") or [])
                            if "instagram" in s.get("scope", "").lower()
                        ],
                        "verdict": (
                            "✓ Token can read this IG account"
                            if pr.status_code == 200
                            else f"⚠️ Token CANNOT read this IG account (HTTP {pr.status_code}) — publishing will fail"
                        ),
                    })
        out["ig_account_access"] = ig_probes if ig_probes else "(no connected posting accounts found)"
        out["steps"]["ig_account_access"] = f"{len(ig_probes)} IG accounts probed"
    except Exception as e:
        out["steps"]["ig_account_access"] = f"Exception: {_tb.format_exc()}"
    return out


# 1x1 white JPEG — used by the media self-test below.
_TEST_JPEG = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb0043000a07070807060a"
    "0808080b0a0a0b0e18100e0d0d0e1d15161118231f2524221f2221262b372f26"
    "293429212230413134393b3e3e3e252e4449433c48373d3e3bffdb0043010a0b"
    "0b0e0d0e1c10101c3b2822283b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b"
    "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3bffc0"
    "0011080001000103012200021101031101ffc4001f0000010501010101010100"
    "000000000000000102030405060708090a0bffc400b510000201030302040305"
    "0504040000017d01020300041105122131410613516107227114328191a10823"
    "42b1c11552d1f02433627282090a161718191a25262728292a3435363738393a"
    "434445464748494a535455565758595a636465666768696a737475767778797a"
    "838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7"
    "b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1"
    "f2f3f4f5f6f7f8f9faffc4001f01000301010101010101010100000000000001"
    "02030405060708090a0bffc400b5110002010204040304070504040001027700"
    "0102031104052131061241510761711322328108144291a1b1c109233352f015"
    "6272d10a162434e125f11718191a262728292a35363738393a43444546474849"
    "4a535455565758595a636465666768696a737475767778797a82838485868788"
    "898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4"
    "c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9"
    "faffda000c03010002110311003f00f66a28a2803fffd9"
)


@app.get("/api/posting/debug/media-test")
async def api_posting_media_selftest(request: Request, db: AsyncSession = Depends(get_db)):
    """Fetch our own public /media URL the way Meta would and report what we get.

    Writes a 1x1 JPEG to the upload dir, mints a media token for it, then
    requests {public_base_url}/media/{token} over the real internet path.
    Shows status, Content-Length, Content-Type — i.e. exactly what Meta's
    fetcher sees when it tries to download IG media from this server.
    """
    get_session(request)  # require a logged-in session
    out: dict = {"base_url": _public_base_url(request)}
    test_id = f"selftest_{secrets.token_hex(8)}.jpg"
    path = _UPLOAD_DIR / test_id
    tok = ""
    try:
        async with aiofiles.open(path, "wb") as fh:
            await fh.write(_TEST_JPEG)
        tok = await media_bridge.mint_media_token(
            db, f"local:{test_id}", "", "image/jpeg", "selftest.jpg", ttl_seconds=120)
        await db.commit()
        url = f"{out['base_url']}/media/{tok}"
        out["test_url"] = url
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            r = await client.get(url, headers={"User-Agent": "facebookexternalhit/1.1"})
        out["fetch"] = {
            "status": r.status_code,
            "content_type": r.headers.get("content-type", "(missing)"),
            "content_length_header": r.headers.get("content-length", "(MISSING — Meta may reject this)"),
            "transfer_encoding": r.headers.get("transfer-encoding", "(none)"),
            "body_bytes": len(r.content),
            "body_matches": r.content == _TEST_JPEG or r.content[:3] == b"\xff\xd8\xff",
        }
        ok = (r.status_code == 200 and r.headers.get("content-length")
              and r.content[:3] == b"\xff\xd8\xff")
        out["verdict"] = ("✓ Media URL is publicly fetchable with Content-Length — Meta should accept it"
                          if ok else "⚠️ PROBLEM — see fetch details; this is what breaks Instagram publishing")
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["verdict"] = ("⚠️ The server could NOT fetch its own public URL — Meta can't either. "
                          "Check that BASE_URL matches the real public domain.")
    finally:
        try:
            if tok:
                await media_bridge.revoke_media_token(db, tok)
                await db.commit()
        except Exception:
            pass
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
    return out


@app.get("/api/posting/pages")
async def api_posting_pages(request: Request, db: AsyncSession = Depends(get_db)):
    """Get FB pages accessible via the Posting app token."""
    token = await get_posting_token(request, db)
    result = await meta_api.get_pages(token)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    # get_pages returns {"success": True, "data": {"data": [...]}} — unwrap to list
    raw = result["data"]
    return raw["data"] if isinstance(raw, dict) else raw


@app.get("/api/posting/instagram")
async def api_posting_instagram(request: Request, db: AsyncSession = Depends(get_db)):
    """Get Instagram Business accounts accessible via the Posting app token."""
    token = await get_posting_token(request, db)
    result = await meta_api.get_pages(token)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    raw = result["data"]
    pages = raw["data"] if isinstance(raw, dict) else raw
    # IG accounts now come back inline with the single get_pages call (no N+1).
    ig_accounts = []
    for page in pages:
        iba = page.get("instagram_business_account")
        if iba:
            ig_accounts.append({
                "id": iba["id"],
                "name": iba.get("name", ""),
                "username": iba.get("username", ""),
                "page_id": page["id"],
                "page_name": page.get("name", ""),
            })
    return ig_accounts


# Simple in-process TTL cache for the pages+IG combined result.
# Key: facebook_user_id (or token hash); Value: (timestamp, pages_list)
_pages_cache: dict[str, tuple[float, list]] = {}
_PAGES_CACHE_TTL = 300  # 5 minutes


async def _get_pages_cached(token: str, cache_key: str) -> dict:
    """Call get_pages with a 5-minute in-memory cache keyed by cache_key."""
    now = time.time()
    cached = _pages_cache.get(cache_key)
    if cached and now - cached[0] < _PAGES_CACHE_TTL:
        return {"success": True, "data": {"data": cached[1]}}
    result = await meta_api.get_pages(token)
    if result.get("success"):
        raw = result["data"]
        pages = raw["data"] if isinstance(raw, dict) else raw
        _pages_cache[cache_key] = (now, pages)
    return result


@app.get("/api/posting/pages-and-ig")
async def api_posting_pages_and_ig(request: Request, db: AsyncSession = Depends(get_db)):
    """Combined endpoint — returns both FB pages and IG accounts in one Meta API call."""
    token = await get_posting_token(request, db)
    session = get_session(request)
    cache_key = session.get("posting_user_id") or hashlib.sha256(token.encode()).hexdigest()[:16]
    result = await _get_pages_cached(token, cache_key)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    raw = result["data"]
    pages = raw["data"] if isinstance(raw, dict) else raw
    # Flatten the nested picture object so the frontend gets a plain URL.
    out_pages = []
    for page in pages:
        pic = (page.get("picture") or {}).get("data", {}).get("url", "")
        out_pages.append({
            **page,
            "picture_url": pic,
        })
    ig_accounts = []
    for page in pages:
        iba = page.get("instagram_business_account")
        if iba:
            ig_accounts.append({
                "id": iba["id"],
                "name": iba.get("name", ""),
                "username": iba.get("username", ""),
                "picture_url": iba.get("profile_picture_url", ""),
                "page_id": page["id"],
                "page_name": page.get("name", ""),
            })
    return {"pages": out_pages, "ig_accounts": ig_accounts}


# ── Public media proxy — lets Meta fetch Drive media without disk storage ──────

def _ensure_jpeg_sync(data: bytes, mime: str, filename: str) -> tuple[bytes, str, str]:
    """Normalize an image for Instagram ingestion.

    IG's media fetcher is strict: it accepts only JPEG, mishandles CMYK and
    progressive encodings, and rejects very large dimensions. Re-encode every
    image as a baseline RGB JPEG capped at 1920px on the longest side, with
    EXIF orientation applied. Returns input unchanged on any decode failure so
    unexpected formats degrade to the old passthrough behaviour.
    """
    try:
        import io
        from PIL import Image, ImageOps
        img = Image.open(io.BytesIO(data))
        img.load()
        img = ImageOps.exif_transpose(img)
        if img.mode != "RGB":
            img = img.convert("RGB")
        w, h = img.size
        max_dim = 1920
        if max(w, h) > max_dim:
            scale = max_dim / max(w, h)
            img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=90, progressive=False, optimize=True)
        new_name = (filename.rsplit(".", 1)[0] if "." in filename else filename) + ".jpg"
        return buf.getvalue(), "image/jpeg", new_name
    except Exception:
        return data, mime, filename


@app.get("/media/{token}")
async def media_proxy(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Stream a Google Drive file through to whoever fetches this URL (e.g. Meta).

    Public + tokenised. The token maps (in the DB, so it works across workers) to
    a Drive file id and the Google account that can read it. We resolve a fresh
    Google token at fetch time and stream the bytes through. Used for Instagram
    publishing, where Meta requires a public URL it can fetch itself.

    Meta-compat requirements handled here:
      - Content-Length must be present (Meta's fetcher rejects chunked
        responses without it — the source of opaque code-2 publish errors).
      - Images are converted to JPEG (IG's API officially supports only JPEG).
    Every fetch is recorded in the posting event log so failed publishes can
    be correlated with whether Meta ever fetched the media at all.
    """
    _ua = request.headers.get("user-agent", "")[:200]
    mapping = await media_bridge.resolve_media_token(db, token)
    if mapping is None:
        await log_posting_event(db, "media_fetch", "Media proxy: token expired or unknown (404)",
            level="warning", platform="system", detail=f"ua={_ua}")
        raise HTTPException(404, "Media link expired or not found")
    _is_image = (mapping.mime_type or "").startswith("image/")
    # Local-file path: drive_file_id is stored as "local:<file_id>"
    if mapping.drive_file_id.startswith("local:"):
        local_id = mapping.drive_file_id[6:]
        path: Optional[Path] = None
        for uploads in _session_uploads.values():
            entry = next((u for u in uploads if u["file_id"] == local_id), None)
            if entry:
                path = Path(entry["path"])
                break
        if path is None:
            path = _UPLOAD_DIR / local_id
        if not path.exists():
            await log_posting_event(db, "media_fetch", f"Media proxy: local file {local_id} not found (404)",
                level="error", platform="system", detail=f"ua={_ua}")
            raise HTTPException(404, "Local media file not found")
        if _is_image:
            async with aiofiles.open(path, "rb") as fh:
                data = await fh.read()
            data, out_mime, out_name = await asyncio.to_thread(
                _ensure_jpeg_sync, data, mapping.mime_type, mapping.filename)
            await log_posting_event(db, "media_fetch",
                f"Media proxy: served local image {out_name} ({len(data)} bytes)",
                level="info", platform="system", detail=f"ua={_ua} mime={out_mime}")
            return Response(content=data, media_type=out_mime,
                headers={"Content-Disposition": f'inline; filename="{out_name}"'})
        # Video / other: FileResponse sets Content-Length from the file size.
        await log_posting_event(db, "media_fetch",
            f"Media proxy: serving local file {mapping.filename}",
            level="info", platform="system", detail=f"ua={_ua} mime={mapping.mime_type}")
        return FileResponse(path, media_type=mapping.mime_type,
            headers={"Content-Disposition": f'inline; filename="{mapping.filename}"'})
    try:
        google_token = await _google_token_for_uid(mapping.google_user_id, db)
    except Exception as exc:
        logger.warning("media_proxy could not resolve Google token: %s", exc)
        await log_posting_event(db, "token_error",
            f"Media proxy: could not resolve Google token for user {mapping.google_user_id}",
            level="error", platform="google", detail=str(exc)[:500])
        raise HTTPException(502, "Could not access source media")
    # Images: buffer fully so we can convert to JPEG and send Content-Length.
    if _is_image:
        dl = await google_api.download_drive_file(mapping.drive_file_id, google_token)
        if not dl.get("success"):
            await log_posting_event(db, "drive_error",
                f"Media proxy: Drive image download failed for {mapping.drive_file_id}",
                level="error", platform="system", detail=f"ua={_ua} err={dl.get('error','')[:300]}")
            raise HTTPException(502, "Source media unavailable")
        data, out_mime, out_name = await asyncio.to_thread(
            _ensure_jpeg_sync, dl["bytes"], mapping.mime_type, mapping.filename)
        await log_posting_event(db, "media_fetch",
            f"Media proxy: served Drive image {out_name} ({len(data)} bytes)",
            level="info", platform="system", detail=f"ua={_ua} mime={out_mime}")
        return Response(content=data, media_type=out_mime,
            headers={"Content-Disposition": f'inline; filename="{out_name}"'})
    # Verify Drive answered 200 before we start the response — otherwise Meta
    # receives a 200 with a broken body and reports an opaque fetch error.
    try:
        status_code, body, content_length = await media_bridge.open_drive_stream(
            mapping.drive_file_id, google_token)
    except Exception as exc:
        logger.warning("media_proxy Drive connect failed for %s: %s", mapping.drive_file_id, exc)
        await log_posting_event(db, "drive_error",
            f"Media proxy: Drive connect failed for {mapping.drive_file_id}",
            level="error", platform="system", detail=str(exc)[:500])
        raise HTTPException(502, "Could not reach source media")
    if body is None:
        logger.warning("media_proxy: Drive returned %s for %s", status_code, mapping.drive_file_id)
        await log_posting_event(db, "drive_error",
            f"Media proxy: Drive returned HTTP {status_code} for {mapping.drive_file_id}",
            level="error", platform="system",
            detail=f"google_user_id={mapping.google_user_id}")
        raise HTTPException(502, f"Source media unavailable (Drive HTTP {status_code})")
    _hdrs = {"Content-Disposition": f'inline; filename="{mapping.filename}"'}
    if content_length:
        _hdrs["Content-Length"] = str(content_length)
    await log_posting_event(db, "media_fetch",
        f"Media proxy: streaming Drive video {mapping.filename} ({content_length or 'unknown'} bytes)",
        level="info", platform="system", detail=f"ua={_ua} mime={mapping.mime_type}")
    return StreamingResponse(body, media_type=mapping.mime_type, headers=_hdrs)


# ── Bulk Drive → Meta posting ──────────────────────────────────────────────────

def _public_base_url(request: Request) -> str:
    """Best-effort public base URL for building media-proxy links Meta can reach."""
    # Prefer BASE_URL from config (set in .env / environment) if it is a real
    # deployment URL and not the localhost default.
    configured = (settings.BASE_URL or "").strip().rstrip("/")
    if configured and not configured.startswith("http://localhost") and not configured.startswith("http://127."):
        return configured
    # Honour proxy headers (Render, Railway, etc. terminate TLS upstream).
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}"


def _effective_base_url() -> str:
    """Public base URL for use in background workers (no Request available).

    Uses BASE_URL from settings if it looks like a real deployment URL.
    Falls back to an empty string which will cause media URLs to be
    relative — acceptable only if the scheduler never runs in that case.
    """
    configured = (settings.BASE_URL or "").strip().rstrip("/")
    if configured and not configured.startswith("http://localhost") and not configured.startswith("http://127."):
        return configured
    return ""


async def _get_page_token(user_token: str, page_id: str) -> str:
    """Exchange the user posting token for a page-scoped token.

    Tries the direct page-node lookup first, then falls back to scanning
    ``/me/accounts`` — the direct lookup fails for some page/permission
    combinations where the page (with its token) is still present in the
    accounts list. Surfaces Meta's real error so failures are diagnosable.
    """
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{settings.meta_graph_base_url}/{page_id}",
            params={"fields": "access_token", "access_token": user_token},
        )
        if r.status_code == 200:
            tok = r.json().get("access_token")
            if tok:
                return tok
        # Capture the direct-lookup error before trying the fallback.
        try:
            err = r.json().get("error", {})
            direct_err = f"{err.get('message', r.text[:200])} (code {err.get('code')}/{err.get('error_subcode', 0)})"
        except Exception:
            direct_err = f"HTTP {r.status_code}: {r.text[:200]}"
        # Fallback: the page token is usually available via /me/accounts.
        fr = await client.get(
            f"{settings.meta_graph_base_url}/me/accounts",
            params={"fields": "id,access_token", "limit": 100, "access_token": user_token},
        )
        if fr.status_code == 200:
            for pg in fr.json().get("data", []):
                if pg.get("id") == page_id and pg.get("access_token"):
                    return pg["access_token"]
    raise HTTPException(
        502,
        f"Could not retrieve page token for page {page_id}: {direct_err}. "
        "Make sure this page was selected when connecting the posting account "
        "and the account has pages_manage_posts permission — reconnecting the "
        "posting account usually fixes this.",
    )


def _parse_scheduled_ts(scheduled_time: Optional[str]) -> Optional[int]:
    if not scheduled_time:
        return None
    try:
        dt = datetime.fromisoformat(scheduled_time.replace("Z", "+00:00"))
        return int(dt.timestamp())
    except Exception:
        raise HTTPException(400, "Invalid scheduled_time — use ISO 8601 format")


class DriveMediaItem(BaseModel):
    drive_file_id: str = ""
    local_file_id: str = ""   # alternative: locally-uploaded file
    cache_file_id: str = ""   # disk backup of Drive media, made at schedule time
    mime_type: str = "application/octet-stream"
    filename: str = "media"


class BulkPostItem(BaseModel):
    platform: str                       # "facebook" or "instagram"
    page_id: str = ""                   # FB page id (required for facebook)
    instagram_id: str = ""              # IG business id (required for instagram)
    caption: str = ""
    hashtags: list[str] = []            # appended to caption
    media: list[DriveMediaItem] = []    # 1 = single, >1 = carousel
    media_type: str = "IMAGE"           # IMAGE | REELS | VIDEO | STORIES
    scheduled_time: Optional[str] = None


class BulkPublishRequest(BaseModel):
    items: list[BulkPostItem]


def _compose_caption(caption: str, hashtags: list[str]) -> str:
    tags = " ".join(h if h.startswith("#") else f"#{h}" for h in hashtags if h.strip())
    if tags and caption:
        return f"{caption}\n\n{tags}"
    return caption or tags


async def _resolve_media_bytes(m: DriveMediaItem, google_token: str) -> dict:
    """Download bytes from Drive or read from local upload storage."""
    if m.local_file_id:
        # Local file: read from disk
        path = _UPLOAD_DIR / m.local_file_id
        if not path.exists():
            # Try to find by scanning _session_uploads values
            for uploads in _session_uploads.values():
                entry = next((u for u in uploads if u["file_id"] == m.local_file_id), None)
                if entry:
                    path = Path(entry["path"])
                    break
        if not path.exists():
            return {"success": False, "error": f"Local file {m.local_file_id} not found"}
        try:
            async with aiofiles.open(path, "rb") as fh:
                data = await fh.read()
            return {"success": True, "bytes": data}
        except OSError as exc:
            return {"success": False, "error": str(exc)}
    # Disk-cached Drive media: read locally — callers pass an empty
    # google_token when every item is cached, so going to Drive here failed.
    if m.cache_file_id:
        cpath = _UPLOAD_DIR / m.cache_file_id
        if cpath.exists():
            try:
                async with aiofiles.open(cpath, "rb") as fh:
                    data = await fh.read()
                return {"success": True, "bytes": data}
            except OSError:
                pass  # fall through to Drive
    return await google_api.download_drive_file(m.drive_file_id, google_token)


async def _publish_facebook_drive(item: BulkPostItem, user_token: str, google_token: str) -> dict:
    if not item.page_id:
        return {"success": False, "error": "page_id required for facebook"}
    if not item.media:
        return {"success": False, "error": "no media provided"}
    page_token = await _get_page_token(user_token, item.page_id)
    caption = _compose_caption(item.caption, item.hashtags)
    scheduled_ts = _parse_scheduled_ts(item.scheduled_time)
    # Meta requires FB scheduled_publish_time to be at least 10 minutes in the future.
    # If the job was delayed and the window has passed, publish immediately instead.
    if scheduled_ts and scheduled_ts < int(datetime.now(timezone.utc).timestamp()) + 600:
        scheduled_ts = None

    def _fb_err(res: dict) -> dict:
        """Translate a meta_api failure dict to a user-friendly error."""
        raw = res.get("error", "publish failed")
        # meta_api already returns the error message string; classify it.
        try:
            # If it's a dict (shouldn't be, but defensive), stringify.
            if isinstance(raw, dict):
                human, _ = _classify_meta_error(raw)
                return {"success": False, "error": human}
        except Exception:
            pass
        return {"success": False, "error": raw}

    # Single video (REELS/VIDEO both post as a Page video)
    if len(item.media) == 1 and item.media_type in ("VIDEO", "REELS"):
        m = item.media[0]
        dl = await _resolve_media_bytes(m, google_token)
        if not dl.get("success"):
            return {"success": False, "error": f"Media download failed: {dl.get('error')}"}
        res = await meta_api.publish_page_video_bytes(
            page_token, item.page_id, dl["bytes"], caption=caption,
            filename=m.filename, scheduled_publish_time=scheduled_ts,
        )
        if not res["success"]:
            return _fb_err(res)
        return {"success": True, "scheduled": bool(scheduled_ts), "post_id": res["data"].get("post_id") or res["data"].get("id")}

    # Single photo — upload as unpublished then attach to a feed post so it
    # appears in Business Suite's Content section (not just the Photos library)
    # and is NOT indexed as an ad asset. Same approach as carousel items.
    if len(item.media) == 1 and item.media_type == "IMAGE":
        m = item.media[0]
        dl = await _resolve_media_bytes(m, google_token)
        if not dl.get("success"):
            return {"success": False, "error": f"Media download failed: {dl.get('error')}"}
        up = await meta_api.upload_unpublished_page_photo_bytes(
            page_token, item.page_id, dl["bytes"], filename=m.filename
        )
        if not up["success"]:
            return _fb_err(up)
        res = await meta_api.publish_page_carousel(
            page_token, item.page_id, [up["data"]["media_id"]], caption=caption,
            scheduled_publish_time=scheduled_ts,
        )
        if not res["success"]:
            return _fb_err(res)
        return {"success": True, "scheduled": bool(scheduled_ts), "post_id": res["data"].get("id")}

    # Carousel (multiple photos)
    if item.media_type == "IMAGE":
        media_ids: list[str] = []
        for m in item.media:
            dl = await _resolve_media_bytes(m, google_token)
            if not dl.get("success"):
                return {"success": False, "error": f"Media download failed: {dl.get('error')}"}
            up = await meta_api.upload_unpublished_page_photo_bytes(
                page_token, item.page_id, dl["bytes"], filename=m.filename
            )
            if not up["success"]:
                return _fb_err(up)
            media_ids.append(up["data"]["media_id"])
        res = await meta_api.publish_page_carousel(
            page_token, item.page_id, media_ids, caption=caption,
            scheduled_publish_time=scheduled_ts,
        )
        if not res["success"]:
            return _fb_err(res)
        return {"success": True, "scheduled": bool(scheduled_ts), "post_id": res["data"].get("id")}

    return {"success": False, "error": f"Unsupported facebook media_type: {item.media_type}"}


async def _publish_instagram_drive(
    item: BulkPostItem, user_token: str, google_uid: str, base_url: str, db: AsyncSession
) -> dict:
    if not item.instagram_id:
        return {"success": False, "error": "instagram_id required for instagram"}
    if not item.media:
        return {"success": False, "error": "no media provided"}
    # google_uid only required if any media item must stream live from Drive —
    # items with a local upload or a schedule-time disk backup don't need Drive.
    has_drive = any(
        m.drive_file_id and not m.local_file_id
        and not (m.cache_file_id and (_UPLOAD_DIR / m.cache_file_id).exists())
        for m in item.media
    )
    if has_drive and not google_uid:
        return {"success": False, "error": "Google Drive must be connected"}
    caption = _compose_caption(item.caption, item.hashtags)
    base = settings.meta_graph_base_url
    minted: list[str] = []
    prefetched_paths: list[Path] = []

    async def _mint(m: DriveMediaItem) -> str:
        # For local uploads, store as "local:<file_id>" so the proxy reads from disk.
        # A disk backup made at schedule time is preferred over live Drive
        # streaming — the post then publishes even if Drive is disconnected.
        mime = m.mime_type or ""
        if m.local_file_id:
            file_ref = f"local:{m.local_file_id}"
        elif m.cache_file_id and (_UPLOAD_DIR / m.cache_file_id).exists():
            file_ref = f"local:{m.cache_file_id}"
        else:
            file_ref = m.drive_file_id
            # Pre-download Drive images to disk so Meta's fetch is served
            # instantly from local storage. Streaming from Drive during Meta's
            # fetch added seconds of latency; when Meta's fetcher timed out it
            # surfaced as an opaque code-2 publish error — carousels (two
            # fetches) failed almost every time. Images also get normalized
            # (RGB baseline JPEG) once here instead of on every fetch.
            if mime.startswith("image/"):
                try:
                    gtok = await _google_token_for_uid(google_uid, db)
                    dl = await google_api.download_drive_file(m.drive_file_id, gtok)
                    if dl.get("success"):
                        data, mime, _name = await asyncio.to_thread(
                            _ensure_jpeg_sync, dl["bytes"], mime, m.filename)
                        cache_id = f"igprefetch_{secrets.token_hex(8)}.jpg"
                        ppath = _UPLOAD_DIR / cache_id
                        async with aiofiles.open(ppath, "wb") as fh:
                            await fh.write(data)
                        prefetched_paths.append(ppath)
                        file_ref = f"local:{cache_id}"
                except Exception as exc:
                    logger.warning("IG prefetch failed for %s, falling back to live Drive stream: %s",
                                   m.drive_file_id, exc)
        tok = await media_bridge.mint_media_token(db, file_ref, google_uid or "", mime, m.filename)
        # Commit immediately so the public /media endpoint (a separate request,
        # possibly on another worker) can resolve the token when Meta fetches it.
        await db.commit()
        minted.append(tok)
        return f"{base_url}/media/{tok}"

    if not base_url:
        return {
            "success": False,
            "error": (
                "Instagram publishing requires a publicly reachable server URL — "
                "BASE_URL is not set. Go to Admin → Settings and set BASE_URL to "
                "the public HTTPS URL of this server (e.g. https://myapp.onrender.com) "
                "so Meta can fetch the media files."
            ),
        }
    if base_url.startswith("http://localhost") or base_url.startswith("http://127."):
        return {
            "success": False,
            "error": (
                f"Instagram publishing cannot work from a local URL ({base_url}). "
                "Meta's servers cannot reach localhost. Use a tunnel (ngrok, Cloudflare Tunnel) "
                "or deploy to a cloud host and set BASE_URL to the public HTTPS address."
            ),
        }

    try:
        # Single image / reel / story
        if len(item.media) == 1:
            m = item.media[0]
            public_url = await _mint(m)
            container: dict = {"access_token": user_token}
            if caption:
                container["caption"] = caption
            is_video = (m.mime_type or "").startswith("video")
            if item.media_type == "REELS":
                container["media_type"] = "REELS"
                container["video_url"] = public_url
            elif item.media_type == "STORIES":
                # Meta rejects image_url pointing at a video — pick by mime.
                container["media_type"] = "STORIES"
                container["video_url" if is_video else "image_url"] = public_url
            elif is_video or item.media_type == "VIDEO":
                # Single feed video must go through the REELS container type
                # (Meta deprecated plain VIDEO media); image_url would 4xx.
                container["media_type"] = "REELS"
                container["video_url"] = public_url
            else:
                container["image_url"] = public_url
            async with httpx.AsyncClient(timeout=60) as client:
                cr = await _meta_post_retry(client, f"{base}/{item.instagram_id}/media", container)
            if cr.status_code not in (200, 201):
                _err_body = cr.json() if cr.content else {}
                _human_msg, _ = _classify_meta_error(_err_body)
                _media_url = container.get("image_url") or container.get("video_url") or ""
                _detail_suffix = f" | media_url={_media_url}" if _media_url else ""
                return {"success": False, "error": f"{_human_msg}{_detail_suffix}"}
            creation_id = cr.json().get("id")
            return await _ig_publish_container(item.instagram_id, creation_id, user_token, base)

        # Carousel
        child_ids: list[str] = []
        async with httpx.AsyncClient(timeout=120) as client:
            for m in item.media:
                public_url = await _mint(m)
                child_payload = {"access_token": user_token, "is_carousel_item": "true"}
                if (m.mime_type or "").startswith("video"):
                    child_payload["media_type"] = "VIDEO"
                    child_payload["video_url"] = public_url
                else:
                    child_payload["image_url"] = public_url
                cr = await _meta_post_retry(client, f"{base}/{item.instagram_id}/media", child_payload)
                if cr.status_code not in (200, 201):
                    _err_body = cr.json() if cr.content else {}
                    _human_msg, _ = _classify_meta_error(_err_body)
                    _cu = child_payload.get("image_url") or child_payload.get("video_url") or ""
                    return {"success": False, "error": f"{_human_msg}" + (f" | media_url={_cu}" if _cu else "")}
                child_ids.append(cr.json().get("id"))
            parent_payload = {
                "access_token": user_token,
                "media_type": "CAROUSEL",
                "children": ",".join(child_ids),
            }
            if caption:
                parent_payload["caption"] = caption
            pr = await _meta_post_retry(client, f"{base}/{item.instagram_id}/media", parent_payload)
        if pr.status_code not in (200, 201):
            _err_body = pr.json() if pr.content else {}
            _human_msg, _ = _classify_meta_error(_err_body)
            return {"success": False, "error": _human_msg}
        return await _ig_publish_container(item.instagram_id, pr.json().get("id"), user_token, base)
    finally:
        # Tokens can be revoked after publish completes; IG has already fetched.
        if minted:
            try:
                for tok in minted:
                    await media_bridge.revoke_media_token(db, tok)
                await db.commit()
            except Exception:
                pass  # TTL purge will clean these up anyway
        for ppath in prefetched_paths:
            try:
                ppath.unlink(missing_ok=True)
            except Exception:
                pass  # the hourly upload purge will get it


async def _ig_publish_container(ig_id: str, creation_id: str, token: str, base: str) -> dict:
    if not creation_id:
        return {"success": False, "error": "no creation_id from container step"}
    # Poll container status — video/carousel need processing before publish.
    # If the container lands in ERROR/EXPIRED, publishing it yields Meta's
    # useless "An unknown error has occurred" — catch it here with the real
    # status instead, which almost always means Meta couldn't fetch or
    # process the media from our public URL.
    last_status = ""
    async with httpx.AsyncClient(timeout=30) as client:
        for _ in range(30):
            sr = await client.get(
                f"{base}/{creation_id}",
                params={"fields": "status_code,status", "access_token": token},
            )
            if sr.status_code == 200:
                body = sr.json()
                last_status = body.get("status_code") or ""
                if last_status == "FINISHED":
                    break
                if last_status in ("ERROR", "EXPIRED"):
                    detail = body.get("status") or ""
                    return {
                        "success": False,
                        "error": f"Instagram could not process the media (container status "
                                 f"{last_status}{': ' + detail if detail else ''}) — usually Meta "
                                 "failed to fetch the media URL; check the file and that the "
                                 "server's BASE_URL is publicly reachable.",
                    }
            await asyncio.sleep(3)
        # Guard: don't attempt media_publish if the container never reached FINISHED.
        # Publishing an IN_PROGRESS container causes Meta to return the cryptic
        # "An unexpected error has occurred" (code 2) with no useful diagnosis.
        if last_status and last_status != "FINISHED":
            return {
                "success": False,
                "error": (
                    f"Instagram media container timed out in '{last_status}' state after 90s — "
                    "the media may be too large, in an unsupported format, or the server's "
                    "BASE_URL is not publicly reachable by Meta."
                ),
            }
        pub = await _meta_post_retry(
            client,
            f"{base}/{ig_id}/media_publish",
            {"creation_id": creation_id, "access_token": token},
        )
    if pub.status_code not in (200, 201):
        _err_body = pub.json() if pub.content else {}
        _human_msg, _ = _classify_meta_error(_err_body)
        if last_status and last_status != "FINISHED":
            _human_msg = f"{_human_msg} (media container status was {last_status}, not FINISHED)"
        return {"success": False, "error": _human_msg}
    return {"success": True, "media_id": pub.json().get("id")}


@app.post("/api/posting/bulk/drive")
async def api_bulk_publish_drive(
    req: BulkPublishRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Queue a bulk publish job and return its id immediately.

    The actual publishing happens in a background worker, one item at a time, so
    an employee can submit 12–22 posts and walk away. Multiple users' jobs queue
    up; poll ``GET /api/posting/jobs/{id}`` for live progress and queue position.
    """
    if not req.items:
        raise HTTPException(400, "No posts to publish")
    # Validate connections up front so the user gets immediate feedback.
    # Also resolves the active posting account — needed for scheduled posts
    # where the session may not carry posting_user_id (e.g. portfolio users).
    await get_posting_token(request, db)
    # Google is only needed when some item streams from Drive — device-upload
    # jobs must work even when no Google account is connected.
    if any(m.drive_file_id and not m.local_file_id for it in req.items for m in it.media):
        await get_google_token(request, db)
    base_url = _public_base_url(request)
    session = get_session(request)

    # Resolve the posting account UID. Session has it when the user connected
    # Meta in this browser tab; fall back to the most recent active account
    # (same logic as get_posting_token) so scheduled jobs always have it.
    posting_user_id = session.get("posting_user_id")
    if not posting_user_id:
        result = await db.execute(
            select(ConnectedPostingAccount)
            .where(ConnectedPostingAccount.is_active == True)
            .order_by(ConnectedPostingAccount.id.desc())
        )
        acc = result.scalars().first()
        if acc:
            posting_user_id = acc.facebook_user_id

    # Same app-wide fallback for Google Drive: the session may have lost its
    # google_user_id (expired cookie), but the connected account in the DB is
    # what scheduled posts will actually use — record it on the job.
    google_user_id = session.get("google_user_id")
    if not google_user_id:
        result = await db.execute(
            select(ConnectedGoogleAccount)
            .where(ConnectedGoogleAccount.is_active == True)
            .order_by(ConnectedGoogleAccount.id.desc())
        )
        gacc = result.scalars().first()
        if gacc:
            google_user_id = gacc.google_user_id

    job = PublishJob(
        created_by=str(session.get("user_id") or ""),
        created_by_name=session.get("username") or "",
        status="queued",
        total=len(req.items),
        completed=0, succeeded=0, failed=0, scheduled_count=0,
        items=[it.dict() for it in req.items],
        results=[],
        posting_user_id=posting_user_id,
        google_user_id=google_user_id,
        base_url=base_url,
    )
    db.add(job)
    await db.flush()
    position = await _job_queue_position(job, db)
    # Each queued item turns into at least one Meta API publish call.
    await bump_user_usage(db, session.get("user_id"), meta_calls=len(req.items))
    # Warn at schedule time if the DB can't outlive a redeploy.
    has_future = any(
        _parse_scheduled_ts(it.scheduled_time) and
        _parse_scheduled_ts(it.scheduled_time) > int(datetime.now(timezone.utc).timestamp()) + 60
        for it in req.items
    )
    warning = ""
    if has_future and settings.DATABASE_URL.startswith("sqlite"):
        warning = (
            "⚠️ This server stores scheduled posts in a temporary SQLite database — "
            "they will be LOST if the server redeploys before the scheduled time. "
            "Set DATABASE_URL to PostgreSQL for durable scheduling."
        )
    return {
        "job_id": job.id,
        "queued": True,
        "total": job.total,
        "position": position,
        "warning": warning,
        "message": "Queued — publishing will start shortly." if position == 0
                   else f"Queued behind {position} other job(s).",
    }


async def _job_queue_position(job: PublishJob, db: AsyncSession) -> int:
    """How many queued/running jobs are ahead of this one (0 = next/now)."""
    result = await db.execute(
        select(func.count()).select_from(PublishJob).where(
            PublishJob.status.in_(["queued", "running"]),
            PublishJob.created_at < job.created_at,
        )
    )
    return int(result.scalar() or 0)


def _job_public_view(job: PublishJob, position: int = 0) -> dict:
    return {
        "id": job.id,
        "status": job.status,
        "total": job.total,
        "completed": job.completed,
        "succeeded": job.succeeded,
        "failed": job.failed,
        "scheduled_count": job.scheduled_count,
        "published_count": max(job.succeeded - job.scheduled_count, 0),
        "position": position,
        "created_by_name": job.created_by_name or "Someone",
        "results": job.results or [],
        "error": job.error,
        "created_at": job.created_at.isoformat() if job.created_at else None,
    }


@app.get("/api/posting/jobs/{job_id}")
async def api_get_publish_job(job_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Live status of a bulk publish job (progress, queue position, per-item results)."""
    job = await db.get(PublishJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    position = await _job_queue_position(job, db) if job.status == "queued" else 0
    return _job_public_view(job, position)


@app.get("/api/posting/jobs")
async def api_list_active_jobs(request: Request, db: AsyncSession = Depends(get_db)):
    """All in-flight jobs (queued/running) + recently finished — so every user
    can see what the server is working on and whether they need to wait."""
    result = await db.execute(
        select(PublishJob)
        .where(PublishJob.status.in_(["queued", "running"]))
        .order_by(PublishJob.created_at)
    )
    active = result.scalars().all()
    return {
        "active": [_job_public_view(j) for j in active],
        "count": len(active),
    }


# Per-file cap for disk backups of scheduled Drive media — protects the
# persistent disk from being filled by one huge video.
_DRIVE_CACHE_MAX_BYTES = 300 * 1024 * 1024

# Global cap for all drivecache_* files combined. Keeps the 1 GB persistent
# disk safe when hundreds of posts are scheduled far into the future — only
# posts within a 24-hour window are cached, so this cap is rarely hit.
_DRIVE_CACHE_TOTAL_MAX_BYTES = 600 * 1024 * 1024


async def _cache_drive_media_to_disk(job: dict, google_uid: str, db: AsyncSession) -> None:
    """Download Drive media of a scheduled post to the uploads dir (best-effort).

    Once cached, the post can publish even if Google Drive is disconnected,
    rate-limited or unreachable at publish time — the media proxy serves the
    disk copy instead. Failures here are non-fatal: Drive streaming remains
    the fallback path.
    """
    sched_uid = job.get("sched_uid", "")
    if not sched_uid:
        # Legacy rows (pre-checkpoint) have no sched_uid; without it every
        # such post would share the same drivecache__N filenames and one
        # post's media would overwrite another's. Skip — they stream live.
        return
    media = job.get("media") or []
    try:
        token = await _google_token_for_uid(google_uid, db)
    except Exception as exc:
        logger.warning("Drive cache skipped (no token): %s", exc)
        return
    _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    for j, m in enumerate(media):
        if m.get("local_file_id") or m.get("cache_file_id") or not m.get("drive_file_id"):
            continue
        cache_id = f"drivecache_{sched_uid}_{j}"
        tmp = _UPLOAD_DIR / (cache_id + ".part")
        dest = _UPLOAD_DIR / cache_id
        try:
            written = 0
            async with aiofiles.open(tmp, "wb") as fh:
                async for chunk in media_bridge.stream_drive_file(m["drive_file_id"], token):
                    written += len(chunk)
                    if written > _DRIVE_CACHE_MAX_BYTES:
                        raise RuntimeError(f"file exceeds {_DRIVE_CACHE_MAX_BYTES // (1024*1024)}MB cache cap")
                    await fh.write(chunk)
            tmp.rename(dest)
            m["cache_file_id"] = cache_id
            logger.info("Cached Drive media %s → %s (%d bytes)", m["drive_file_id"], cache_id, written)
        except Exception as exc:
            logger.warning("Drive cache failed for %s: %s", m.get("filename") or m.get("drive_file_id"), exc)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                await log_posting_event(db, "drive_error",
                    f"Drive cache failed for {m.get('filename') or m.get('drive_file_id','?')}",
                    level="warning", platform="system",
                    detail=str(exc)[:500])
            except Exception:
                pass


def _purge_drive_cache(job: dict) -> None:
    """Delete disk backups of a scheduled post's Drive media after publish."""
    for m in (job or {}).get("media", []):
        cid = m.get("cache_file_id")
        if cid and cid.startswith("drivecache_"):
            try:
                (_UPLOAD_DIR / cid).unlink(missing_ok=True)
            except OSError:
                pass


async def _precache_drive_posts(db: AsyncSession) -> None:
    """Cache Drive media to disk for pending posts scheduled within the next 24 hours.

    Called by ``_drive_precache_loop`` every 15 minutes. Only processes posts
    that fire soon so that scheduling hundreds of future posts never fills the
    persistent disk — at any moment only ~1 day of posts are cached.
    """
    # Abort if the global Drive-cache quota is already used up.
    try:
        total_cache = sum(
            f.stat().st_size
            for f in _UPLOAD_DIR.glob("drivecache_*")
            if not f.name.endswith(".part")
        )
    except OSError:
        total_cache = 0
    if total_cache >= _DRIVE_CACHE_TOTAL_MAX_BYTES:
        logger.warning(
            "Drive cache total %.0f MB ≥ %.0f MB cap — skipping precache run",
            total_cache / 1024 / 1024,
            _DRIVE_CACHE_TOTAL_MAX_BYTES / 1024 / 1024,
        )
        return

    window = datetime.utcnow() + timedelta(hours=24)
    # Skip posts due in the next 2 minutes — the publish worker may claim them
    # while we're still downloading, wasting the download and stranding the file.
    near_cutoff = datetime.utcnow() + timedelta(minutes=2)
    result = await db.execute(
        select(ScheduledPost).where(
            ScheduledPost.status == "pending",
            ScheduledPost.scheduled_time <= window,
            ScheduledPost.scheduled_time > near_cutoff,
        )
    )
    posts = result.scalars().all()
    for post in posts:
        jd = post.job_data
        if not jd:
            continue
        media = jd.get("media", [])
        needs_cache = any(
            m.get("drive_file_id")
            and not m.get("local_file_id")
            and not (m.get("cache_file_id") and (_UPLOAD_DIR / m["cache_file_id"]).exists())
            for m in media
        )
        if not needs_cache:
            continue
        google_uid = jd.get("google_user_id") or jd.get("posting_user_id")
        if not google_uid:
            continue
        await _cache_drive_media_to_disk(jd, google_uid, db)
        # Re-check the row is still pending before persisting cache ids — the
        # publish worker may have claimed it during a long download. The cached
        # file itself stays either way; age-based cleanup removes orphans.
        await db.refresh(post)
        if post.status != "pending":
            continue
        post.job_data = dict(jd)
        flag_modified(post, "job_data")
        await db.commit()


async def _drive_precache_loop() -> None:
    """Background loop: pre-cache Drive media for posts firing within 24 hours."""
    await asyncio.sleep(25)  # let startup settle
    while True:
        try:
            async for db in get_db():
                await _precache_drive_posts(db)
                break
        except Exception as exc:
            logger.warning("Drive precache loop error: %s", exc)
        await asyncio.sleep(900)  # 15 min


async def _schedule_ig_job(
    item: BulkPostItem,
    scheduled_ts: int,
    posting_uid: Optional[str],
    google_uid: Optional[str],
    base_url: str,
    db: AsyncSession,
) -> int:
    """Queue an Instagram post for self-scheduled publishing. Returns row id."""
    if not google_uid and any(m.drive_file_id and not m.local_file_id for m in item.media):
        raise HTTPException(400, "Google Drive must be connected to schedule Drive media")
    job = {
        "sched_uid": secrets.token_hex(16),   # stable identity for checkpoint restore
        "media": [m.dict() for m in item.media],
        "hashtags": item.hashtags,
        "media_type": item.media_type,
        "instagram_id": item.instagram_id,
        "page_id": item.page_id,
        "posting_user_id": posting_uid,
        "google_user_id": google_uid,
        "base_url": base_url,
    }
    row = ScheduledPost(
        platform="instagram",
        instagram_id=item.instagram_id,
        caption=_compose_caption(item.caption, item.hashtags),
        media_type=item.media_type,
        scheduled_time=datetime.fromtimestamp(scheduled_ts, tz=timezone.utc),
        timezone="UTC",
        status="pending",
        job_data=job,
    )
    db.add(row)
    await db.flush()
    # Checkpoint immediately so the new post is durable before the next loop tick.
    await _save_checkpoint(db)
    return row.id


# ── Drive scan — list media + parse captions for the bulk composer ─────────────

class DriveScanRequest(BaseModel):
    folder_url: str
    text_url: str = ""


_CAPTION_SEPARATOR = re.compile(r"\n\s*(?:---+|===+|###+|\*\*\*+)\s*\n")

# "Schedule:", "Date:", "Posting time -" … prefixes before a date in a captions doc.
_SCHED_LABEL = re.compile(
    r"^\s*(?:schedule[d]?|date(?:\s*&?\s*time)?|time|when|post(?:ing)?\s*(?:date|time|at)?)\s*[:\-–]\s*",
    re.I,
)
_SCHED_LABEL_TAIL = re.compile(
    r"(?:schedule[d]?|date(?:\s*&?\s*time)?|time|when|post(?:ing)?\s*(?:date|time|at)?)\s*[:\-–]?\s*$",
    re.I,
)
# Date + optional time anywhere in a block (used when the date isn't on its own line).
_INLINE_SCHED = re.compile(
    r"(\d{1,2}[/.\-]\d{1,2}[/.\-]\d{4}|\d{4}-\d{1,2}-\d{1,2})"
    r"(?:[T ,]+(\d{1,2}:\d{2}(?::\d{2})?\s*(?:[ap]\.?m\.?)?))?",
    re.I,
)
_SCHED_TOKEN_PATTERNS = [
    # 2026-06-10 13:00 / 2026-06-10T13:00:00
    (re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ,]+(\d{1,2}):(\d{2})(?::\d{2})?\s*([ap]\.?m\.?)?)?$", re.I), "ymd"),
    # 06/10/2026 01:00 PM (or 06-10-2026 13:00); day-first assumed when first number > 12
    (re.compile(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{4})(?:[T ,]+(\d{1,2}):(\d{2})(?::\d{2})?\s*([ap]\.?m\.?)?)?$", re.I), "mdy"),
    # 10.06.2026 13:00 (day first)
    (re.compile(r"^(\d{1,2})\.(\d{1,2})\.(\d{4})(?:[T ,]+(\d{1,2}):(\d{2})(?::\d{2})?\s*([ap]\.?m\.?)?)?$", re.I), "dmy"),
    # 14/05 — short date with no year (content calendars). Day-first by default;
    # month-first when only that is valid. Year resolved to the nearest future-ish one.
    (re.compile(r"^(\d{1,2})[/.\-](\d{1,2})(?:[T ,]+(\d{1,2}):(\d{2})(?::\d{2})?\s*([ap]\.?m\.?)?)?$", re.I), "dm_short"),
]


def _parse_schedule_token(s: str, day_first: bool = False) -> Optional[str]:
    """Parse a date(/time) string into naive local ``YYYY-MM-DDTHH:MM``.

    Returns None if the string is not a recognised date. Date-only values
    default to 09:00 so a scheduled post never fires at midnight. ``day_first``
    resolves ambiguous numeric dates (01/06/2026): column-based callers detect
    the convention from the whole date column.
    """
    s = (s or "").strip().rstrip(".")
    for rx, order in _SCHED_TOKEN_PATTERNS:
        m = rx.match(s)
        if not m:
            continue
        g = m.groups()
        if order == "ymd":
            y, mo, d = int(g[0]), int(g[1]), int(g[2])
        elif order == "mdy":
            a, b, y = int(g[0]), int(g[1]), int(g[2])
            if a > 12:
                d, mo = a, b
            elif b > 12:
                mo, d = a, b
            elif day_first:
                d, mo = a, b
            else:
                mo, d = a, b
        elif order == "dm_short":
            a, b = int(g[0]), int(g[1])
            d, mo = (a, b) if a > 12 or b <= 12 else (b, a)
            now = datetime.now()
            y = now.year
            try:
                # If the date is far in the past, the calendar means next year.
                if datetime(y, mo, d) < now - timedelta(days=90):
                    y += 1
            except ValueError:
                return None
        else:
            d, mo, y = int(g[0]), int(g[1]), int(g[2])
        th, tm, tap = (g[2], g[3], g[4]) if order == "dm_short" else (g[3], g[4], g[5])
        hh = int(th) if th else 9
        mm = int(tm) if tm else 0
        ampm = (tap or "").lower().replace(".", "")
        if ampm.startswith("p") and hh < 12:
            hh += 12
        elif ampm.startswith("a") and hh == 12:
            hh = 0
        try:
            datetime(y, mo, d, hh, mm)
        except ValueError:
            return None
        return f"{y:04d}-{mo:02d}-{d:02d}T{hh:02d}:{mm:02d}"
    return None


# Column-header synonyms for content-calendar sheets. Matched per header cell
# (word-boundary), in priority order — the caption column is required, others
# are optional. Columns like "type"/"title" are deliberately NOT folded into
# the caption: only the caption column is published.
_COL_SYNONYMS: list[tuple[str, list[str]]] = [
    ("caption", ["caption", "copy", "post text", "body", "content", "text", "description"]),
    ("date", ["posting date", "publish date", "date", "day", "when", "schedule"]),
    ("time", ["posting time", "publish time", "time", "hour"]),
    ("file", ["file name", "filename", "image name", "image", "file", "visual", "creative", "asset", "design", "graphic", "media"]),
    ("type", ["post type", "content type", "format", "type", "post format"]),
    # Claimed so a Title/Hook column is never folded into the caption; used only
    # as a fallback when the caption cell of a row is empty.
    ("title", ["post title", "title", "headline", "hook", "subject", "topic", "theme"]),
]

# Normalise a sheet's "type" cell ("Static post", "Reel", "Carousel post"…)
# to the wizard's three post kinds. Empty string = unknown/unspecified.
_TYPE_REEL_RE = re.compile(r"\b(reels?|videos?)\b", re.I)
_TYPE_CAROUSEL_RE = re.compile(r"carr?ou?sell?", re.I)
_TYPE_IMAGE_RE = re.compile(r"\b(static|image|photo|single|picture)\b", re.I)


def _normalize_post_type(cell: str) -> str:
    s = (cell or "").strip()
    if not s:
        return ""
    if _TYPE_CAROUSEL_RE.search(s):
        return "carousel"
    if _TYPE_REEL_RE.search(s):
        return "reel"
    if _TYPE_IMAGE_RE.search(s):
        return "image"
    return ""


def _detect_calendar_header(rows: list) -> tuple[Optional[int], Optional[dict]]:
    """Find a header row labelling a caption column (within the first 5 rows).

    Returns ``(header_row_index, {role: column_index})`` or ``(None, None)``.
    """
    for ri, row in enumerate(rows[:5]):
        # Header labels are short — a long cell matching "caption"/"text" is
        # post content, not a header.
        cells = [str(c or "").strip().lower() for c in row]
        cells = [c if len(c) <= 30 else "" for c in cells]
        cols: dict[str, int] = {}
        taken: set[int] = set()
        for role, keys in _COL_SYNONYMS:
            for key in keys:
                hit = next(
                    (ci for ci, cell in enumerate(cells)
                     if ci not in taken and cell and re.search(rf"\b{re.escape(key)}\b", cell)),
                    None,
                )
                if hit is not None:
                    cols[role] = hit
                    taken.add(hit)
                    break
        if "caption" in cols:
            return ri, cols
    return None, None


def _infer_calendar_columns(rows: list) -> Optional[dict]:
    """Infer calendar columns by content when no labelled header exists.

    The date column is the one whose values mostly parse as dates, the file
    column mostly looks like filenames, and the caption column is the longest
    free-text column. Needs a caption plus at least one other signal so plain
    text tables aren't misread as calendars.
    """
    if len(rows) < 2:
        return None
    ncols = max(len(r) for r in rows)
    if ncols < 2:
        return None
    date_col = file_col = caption_col = type_col = None
    best_len = 0.0
    lens: dict[int, float] = {}
    for ci in range(ncols):
        vals = [str(r[ci]).strip() for r in rows if ci < len(r) and str(r[ci] or "").strip()]
        if not vals:
            continue
        n = len(vals)
        dates = sum(1 for v in vals if _parse_schedule_token(v, day_first=True))
        with_ext = sum(1 for v in vals if re.search(r"\.[a-z0-9]{2,4}$", v, re.I))
        nameish = sum(1 for v in vals if re.fullmatch(r"[\w.\-]{3,60}", v) and not v.isdigit())
        typed = sum(1 for v in vals if _normalize_post_type(v))
        lens[ci] = sum(len(v) for v in vals) / n
        if date_col is None and dates / n >= 0.6 and lens[ci] < 40:
            date_col = ci
        # Post-type column: short cells like "Static post" / "Reel" / "Carousel".
        # Must not look like filenames ("carousel1.png" belongs to the file column).
        if type_col is None and lens[ci] < 30 and typed / n >= 0.6 and with_ext == 0:
            type_col = ci
            continue
        # Filename column: mostly extension-bearing values, or mostly
        # space-free tokens with at least one real file extension among them.
        if file_col is None and lens[ci] < 80 and (
            with_ext / n >= 0.5 or (with_ext >= 1 and nameish / n >= 0.6)
        ):
            file_col = ci
    for ci, avg in lens.items():
        if ci in (date_col, file_col, type_col):
            continue
        if avg > best_len:
            best_len, caption_col = avg, ci
    if caption_col is None or best_len < 40:
        return None
    if date_col is None and file_col is None and type_col is None:
        return None
    cols: dict = {"caption": caption_col}
    if date_col is not None:
        cols["date"] = date_col
    if file_col is not None:
        cols["file"] = file_col
    if type_col is not None:
        cols["type"] = type_col
    return cols


def _captions_from_rows_loose(rows: list) -> Optional[list[dict]]:
    """Last-resort per-row parsing when no column structure was detected.

    Classifies each cell on its own — a date-parsing cell becomes the
    schedule, a short type-looking cell ("Reel", "Static post") the post
    type, an extension-bearing token the filename, and the longest free-text
    cell the caption. Cells are never concatenated, so date/type/title/notes
    columns can't leak into the published caption even when header detection
    and column inference both fail. Returns None when the data isn't really
    tabular (mostly single-cell rows — a plain captions doc).
    """
    filled = [r for r in rows if any(str(c or "").strip() for c in r)]
    multi = [r for r in filled if sum(1 for c in r if str(c or "").strip()) >= 2]
    if len(filled) < 2 or len(multi) < max(2, len(filled) // 2):
        return None
    out: list[dict] = []
    for row in filled:
        cells = [str(c or "").strip() for c in row]
        schedule: Optional[str] = None
        ptype = file = caption = ""
        for c in cells:
            if not c:
                continue
            if not schedule:
                s = _parse_schedule_token(c, day_first=True)
                if s:
                    schedule = s
                    continue
            if not ptype and len(c) <= 30 and _normalize_post_type(c):
                ptype = _normalize_post_type(c)
                continue
            if not file and len(c) <= 80 and " " not in c and re.search(r"\.[a-z0-9]{2,4}$", c, re.I):
                file = c
                continue
            if len(c) > len(caption):
                caption = c
        if len(caption) < 20:
            continue  # header rows, stray labels
        # The caption cell itself may still carry a "14/05 Static post " prefix.
        caption, s2, t2 = _strip_block_prefix(caption)
        schedule = schedule or s2
        ptype = ptype or t2
        if not ptype:
            ptype = ""
        tags = re.findall(r"#\w+", caption)
        out.append({"caption": caption, "hashtags": tags, "schedule": schedule,
                    "file": file, "type": ptype})
    return out or None


def _captions_from_rows(rows: list) -> Optional[list[dict]]:
    """Build caption blocks from a content-calendar sheet.

    Columns come from a labelled header row when present, otherwise they are
    inferred from the content. Uses ONLY the caption column for the published
    text, the date(+time) columns for the schedule, and the image/file column
    for filename matching. Falls back to per-row cell classification
    (``_captions_from_rows_loose``) so multi-column sheets are never flattened
    into blobs; returns None only when the data isn't tabular at all.
    """
    hi, cols = _detect_calendar_header(rows)
    data_rows = rows[hi + 1:] if cols is not None else rows
    if cols is None:
        cols = _infer_calendar_columns(rows)
        if cols is None:
            return _captions_from_rows_loose(rows)
        # Inferred columns keep all rows — drop a leading header-looking row
        # (short caption cell, unparseable date cell).
        if data_rows:
            first = [str(c or "").strip() for c in data_rows[0]]
            cci, dci0 = cols.get("caption"), cols.get("date")
            cap0 = first[cci] if cci is not None and cci < len(first) else ""
            d0 = first[dci0] if dci0 is not None and dci0 < len(first) else ""
            if len(cap0) < 40 and (not d0 or not _parse_schedule_token(d0, day_first=True)):
                data_rows = data_rows[1:]
    # Decide the date convention from the whole column: any value with the
    # first number > 12 proves day-first; only the second > 12 proves
    # month-first; all-ambiguous columns default to day-first (dd/mm).
    day_first = True
    dci = cols.get("date")
    if dci is not None:
        pairs = []
        for row in data_rows:
            if dci < len(row):
                mm_ = re.match(r"\s*(\d{1,2})[/.\-](\d{1,2})", str(row[dci] or ""))
                if mm_:
                    pairs.append((int(mm_.group(1)), int(mm_.group(2))))
        if any(b > 12 for _, b in pairs) and not any(a > 12 for a, _ in pairs):
            day_first = False
    out: list[dict] = []
    for row in data_rows:
        cells = [str(c or "").strip() for c in row]
        def cell(role: str) -> str:
            ci = cols.get(role)
            return cells[ci] if ci is not None and ci < len(cells) else ""
        caption = cell("caption")
        if not caption:
            # Row with an empty caption cell: fall back to the title column,
            # then to the longest unclaimed cell — so the post isn't dropped
            # and left captionless in the preview.
            caption = cell("title")
        if not caption:
            claimed = {ci for ci in cols.values()}
            free = [c_ for i_, c_ in enumerate(cells)
                    if i_ not in claimed and len(c_) >= 20 and not _parse_schedule_token(c_)]
            caption = max(free, key=len) if free else ""
        if not caption:
            continue
        d, t = cell("date"), cell("time")
        schedule = None
        if d:
            schedule = (_parse_schedule_token(f"{d} {t}".strip(), day_first)
                        or _parse_schedule_token(d, day_first))
        if not schedule:
            caption, schedule = _extract_block_schedule(caption)
        tags = re.findall(r"#\w+", caption)
        out.append({
            "caption": caption, "hashtags": tags, "schedule": schedule,
            "file": cell("file"), "type": _normalize_post_type(cell("type")),
        })
    return out or _captions_from_rows_loose(rows)


def _extract_block_schedule(block: str) -> tuple[str, Optional[str]]:
    """Pull a schedule date/time out of a caption block, if present.

    Tries a dedicated line first (optionally labelled "Schedule:", "Date:" …,
    time optional), then an inline date+time anywhere in the text. Returns
    ``(caption_without_the_date, "YYYY-MM-DDTHH:MM" | None)``.
    """
    lines = block.split("\n")
    for idx, line in enumerate(lines):
        candidate = _SCHED_LABEL.sub("", line.strip())
        sched = _parse_schedule_token(candidate)
        if sched:
            del lines[idx]
            return "\n".join(lines).strip(), sched
    m = _INLINE_SCHED.search(block)
    if m and m.group(2):  # inline matches need an explicit time to avoid false positives
        sched = _parse_schedule_token(m.group(0))
        if sched:
            start, end = m.span()
            label = _SCHED_LABEL_TAIL.search(block[:start])
            if label:
                start = label.start()
            cleaned = (block[:start].rstrip() + " " + block[end:].lstrip()).strip()
            return cleaned, sched
    return block, None


# A caption block that begins with a calendar row's leftover prefix —
# "14/05 Static post Actual caption…" — carries the date and type inline
# (happens when a sheet's columns couldn't be detected and rows were flattened).
_LEAD_DATE = re.compile(
    r"^\s*(\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[/.\-]\d{1,2}(?:[/.\-]\d{2,4})?)"
    r"(?:[\s,]+(\d{1,2}:\d{2}(?::\d{2})?\s*(?:[ap]\.?m\.?)?))?[\s:,\-–—]+"
)
_LEAD_TYPE = re.compile(
    r"^\s*(static(?:\s+post)?|carr?ou?sell?(?:\s+post)?|reels?(?:\s+post)?|video(?:\s+post)?)\b[\s:,\-–—]*",
    re.I,
)


def _strip_block_prefix(block: str) -> tuple[str, Optional[str], str]:
    """Strip a leading "14/05 Static post " calendar prefix from a caption block.

    Returns ``(cleaned_block, schedule|None, type)``. The type token is only
    stripped when a date came right before it, or when it is a whole line by
    itself — captions that legitimately start with "Video…" are left alone.
    """
    schedule = None
    ptype = ""
    m = _LEAD_DATE.match(block)
    if m:
        token = m.group(1) + ((" " + m.group(2)) if m.group(2) else "")
        sched = _parse_schedule_token(token, day_first=True)
        if sched:
            schedule = sched
            block = block[m.end():]
    t = _LEAD_TYPE.match(block)
    if t:
        first_line = block.split("\n", 1)[0].strip()
        if schedule or t.end() >= len(first_line):
            ptype = _normalize_post_type(t.group(1))
            block = block[t.end():]
    return block.strip(), schedule, ptype


def _split_caption_blocks(text: str) -> list[dict]:
    """Split a captions doc into per-post blocks, separating trailing hashtags.

    Blocks are separated by --- / === / ### / *** lines (or blank lines as a
    fallback). Each block returns ``{"caption", "hashtags", "schedule"}`` where
    ``schedule`` is a naive local ``YYYY-MM-DDTHH:MM`` string parsed from the
    block (or None) — the browser interprets it in the user's timezone.
    """
    text = (text or "").strip()
    if not text:
        return []
    blocks = _CAPTION_SEPARATOR.split(text)
    if len(blocks) <= 1:
        # Fallback: split on blank lines
        blocks = re.split(r"\n\s*\n", text)
    out: list[dict] = []
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        block, schedule, ptype = _strip_block_prefix(block)
        if not schedule:
            block, schedule = _extract_block_schedule(block)
        if not block and not schedule:
            continue
        # Collect hashtags but keep them in caption too (user can trim in UI)
        tags = re.findall(r"#\w+", block)
        out.append({"caption": block, "hashtags": tags, "schedule": schedule, "type": ptype})
    return out


@app.post("/api/posting/drive/scan")
async def api_posting_drive_scan(
    req: DriveScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List image/video files in a Drive folder + parse a captions doc/sheet.

    Returns media (sorted by name) and caption blocks so the frontend can
    auto-match them and let the user adjust before bulk-publishing.
    """
    google_token = await get_google_token(request, db)
    media: list[dict] = []
    folder_raw = req.folder_url.strip()
    # Captions-only scans pass an empty folder_url (or reuse the doc link in
    # older clients) — skip the folder listing instead of asking Drive to list
    # a document as a folder, which fails with "File not found".
    folder_id = google_api.extract_folder_id_from_url(folder_raw)
    if not folder_id and folder_raw and folder_raw != req.text_url.strip():
        folder_id = folder_raw
    if folder_id:
        media = await _list_folder_media(folder_id, google_token)

    captions: list[dict] = []
    if req.text_url.strip():
        captions = await _read_captions_from_drive(req.text_url.strip(), google_token)

    return {"media": media, "captions": captions}


def _media_entry(f: dict, group: str = "") -> dict:
    mime = f.get("mimeType", "")
    entry = {
        "id": f["id"],
        "name": f.get("name", ""),
        "mime_type": mime,
        "size": f.get("size"),
        "is_video": mime.startswith("video/"),
    }
    if group:
        entry["group"] = group
    return entry


# Carousel naming convention — tolerant of carousel/carrousel/carousell.
_CAROUSEL_NAME_RE = re.compile(r"carr?ou?sell?", re.I)


async def _list_folder_media(folder_id: str, google_token: str) -> list[dict]:
    """List a folder's media including carousel subfolders one level down.

    Only subfolders that follow the carousel convention are auto-imported:
    the folder name contains "carousel" (any spelling), or at least half of
    the files inside do. Their files carry ``group: <subfolder name>`` so the
    frontend bundles them into one multi-image post ordered by filename.
    Other subfolders (other clients' materials, asset archives) are left
    alone — select them explicitly if needed.
    """
    listing = await google_api.list_drive_folder(folder_id, google_token)
    if not listing.get("success"):
        raise HTTPException(502, listing.get("error") or "Could not list Drive folder")
    media: list[dict] = []
    subfolders: list[dict] = []
    for f in listing["files"]:
        mime = f.get("mimeType", "")
        if mime == "application/vnd.google-apps.folder":
            subfolders.append(f)
        elif mime.startswith(("image/", "video/")):
            media.append(_media_entry(f))
    media.sort(key=lambda m: m["name"].lower())
    for sf in subfolders[:40]:
        sub = await google_api.list_drive_folder(sf["id"], google_token)
        if not sub.get("success"):
            continue
        items = [
            f for f in sub.get("files", [])
            if f.get("mimeType", "").startswith(("image/", "video/"))
        ]
        if not items:
            continue
        sub_name = sf.get("name", "")
        named_caro = bool(_CAROUSEL_NAME_RE.search(sub_name))
        files_caro = sum(1 for f in items if _CAROUSEL_NAME_RE.search(f.get("name", "")))
        if not named_caro and files_caro < max(1, len(items) / 2):
            continue  # not carousel-named — don't swallow unrelated materials
        group = (sub_name or "carousel") if len(items) > 1 else ""
        entries = [_media_entry(f, group=group) for f in items]
        entries.sort(key=lambda m: m["name"].lower())
        media.extend(entries)
    return media


async def _read_captions_from_drive(text_url: str, google_token: str) -> list[dict]:
    """Read a captions source from Drive into caption blocks.

    Handles native Google Docs/Sheets directly; uploaded Word/Excel/CSV/PDF/
    text files are downloaded and parsed with the same extractors the device
    upload path uses, so any caption format works from Drive too.
    """
    text_result = await google_api.read_by_url(text_url, google_token)
    raw_text = ""
    content = text_result.get("content")
    rows = None
    if isinstance(content, dict) and content.get("rows"):
        rows = content["rows"]
    elif text_result.get("rows"):
        rows = text_result["rows"]
    if rows:
        # Labelled content calendar → per-column parsing (caption/date/file).
        structured = _captions_from_rows(rows)
        if structured is not None:
            return structured
        # Cell-per-line so a leading date/type cell stays strippable as a prefix.
        raw_text = "\n---\n".join(
            "\n".join(str(c).strip() for c in row if str(c or "").strip()) for row in rows
        )
    if not raw_text and isinstance(content, str):
        raw_text = content
    elif not raw_text and isinstance(content, dict):
        raw_text = content.get("text", "")
    if not raw_text:
        # Binary / non-native file (docx, xlsx, csv, pdf, txt): download + extract.
        name = text_result.get("name", "")
        data = content if isinstance(content, (bytes, bytearray)) else None
        if data is None:
            fid = google_api.extract_file_id_from_url(text_url)
            if fid:
                if not name:
                    meta = await google_api.get_file_metadata(fid, google_token)
                    if meta.get("success"):
                        name = meta.get("name", "")
                dl = await google_api.download_drive_file(fid, google_token)
                if dl.get("success"):
                    data = dl.get("bytes")
        if data:
            try:
                # Tabular files get the same per-column calendar parsing as
                # native Google Sheets before falling back to text blocks.
                ext = Path(name or "").suffix.lower()
                tab_rows: list = []
                if ext == ".xlsx":
                    tab_rows = _extract_xlsx_rows(bytes(data))
                elif ext in (".csv", ".tsv"):
                    import csv as _csv
                    import io as _io
                    sep = "\t" if ext == ".tsv" else ","
                    tab_rows = list(_csv.reader(
                        _io.StringIO(bytes(data).decode("utf-8", errors="replace")), delimiter=sep))
                if tab_rows:
                    structured = _captions_from_rows(tab_rows)
                    if structured is not None:
                        return structured
                raw_text = _extract_caption_text(bytes(data), name or "captions.txt")
            except Exception as exc:
                logger.warning("Caption extraction failed for %s: %s", name, exc)
    return _split_caption_blocks(raw_text)


class AiMatchPost(BaseModel):
    index: int
    files: list[str] = []
    kind: str = ""       # "image" | "reel" | "carousel" — derived from the media
    drive_id: str = ""   # first image's Drive file id — lets the AI *see* the image
    local_id: str = ""   # first image's local upload id (device uploads)


class AiMatchCaption(BaseModel):
    index: int
    caption: str = ""
    schedule: Optional[str] = None
    type: str = ""       # "image" | "reel" | "carousel" from the sheet's type column
    file: str = ""       # the sheet's image/file column value, if any


class AiMatchRequest(BaseModel):
    posts: list[AiMatchPost]
    captions: list[AiMatchCaption]


def _local_thumb_b64(local_id: str) -> Optional[tuple[str, str]]:
    """Downscale a locally-uploaded image to ≤512px and return (b64, mime)."""
    path = _UPLOAD_DIR / local_id
    if not path.exists():
        for uploads in _session_uploads.values():
            entry = next((u for u in uploads if u["file_id"] == local_id), None)
            if entry:
                path = Path(entry["path"])
                break
    if not path.exists():
        return None
    try:
        import base64
        import io
        from PIL import Image
        img = Image.open(path)
        img.thumbnail((512, 512))
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=80)
        return base64.b64encode(buf.getvalue()).decode(), "image/jpeg"
    except Exception:
        return None


@app.post("/api/posting/ai/match")
@limiter.limit("20/minute")
async def api_posting_ai_match(
    req: AiMatchRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    """Match upload posts to caption blocks with the configured AI model.

    When the provider supports vision (Claude), each post's first image is
    attached as a thumbnail so the model matches by what the image actually
    shows — not just filenames. Returns ``{"success": true, "assignments":
    [[post_index, caption_index|null], …]}`` or ``{"success": false}`` — the
    frontend keeps its heuristic matching then.
    """
    if not req.posts or not req.captions:
        return {"success": False, "error": "nothing to match"}
    if len(req.posts) > 60 or len(req.captions) > 60:
        return {"success": False, "error": "too many items"}
    def _post_line(p) -> str:
        kind = f" [{p.kind}]" if p.kind else ""
        return f"POST {p.index}{kind}: files = {', '.join(p.files[:12]) or '(unnamed)'}"

    def _cap_line(c) -> str:
        bits = []
        if c.type:
            bits.append(f"type={c.type}")
        if c.schedule:
            bits.append(f"scheduled {c.schedule}")
        if c.file:
            bits.append(f"file_ref={c.file!r}")
        tag = f" [{', '.join(bits)}]" if bits else ""
        return f"CAPTION {c.index}{tag}: {(c.caption or '')[:600]}"

    post_lines = "\n".join(_post_line(p) for p in req.posts)
    cap_lines = "\n".join(_cap_line(c) for c in req.captions)
    system = (
        "You match social-media posts (groups of image/video files) to caption blocks "
        "from a captions document. When images are attached, LOOK at each image and pick "
        "the caption whose text genuinely describes that image's content — products, "
        "people, scenes, or text visible in the design. Also consider numbering and "
        "keywords in filenames, dates in captions, and the natural document order as a "
        "tie-breaker. HARD CONSTRAINT on types: a caption marked type=reel may only go "
        "to a [reel] post, type=carousel only to a [carousel] post, and type=image only "
        "to an [image] post; captions without a type may go to any post. When a caption "
        "has a file_ref, strongly prefer the post whose filename matches it. "
        "Each post gets at most one caption and each caption is used at most "
        "once. Reply with ONLY a JSON object, no prose: "
        '{"assignments": [[post_index, caption_index_or_null], ...]} covering every post.'
    )
    user = f"POSTS:\n{post_lines}\n\nCAPTION BLOCKS:\n{cap_lines}"

    # Vision pass: attach each post's first image thumbnail when Claude is in use.
    text = None
    if agent.supports_vision and len(req.posts) <= 16:
        import base64
        google_token = None
        try:
            google_token = await get_google_token(request, db)
        except Exception:
            pass
        blocks: list = []
        attached = 0
        for p in req.posts:
            img = None
            if p.drive_id and google_token:
                thumb = await google_api.get_drive_thumbnail(p.drive_id, google_token)
                if thumb:
                    img = (base64.b64encode(thumb[0]).decode(), thumb[1])
            elif p.local_id:
                img = _local_thumb_b64(p.local_id)
            blocks.append({
                "type": "text",
                "text": _post_line(p) + ("" if img else " (no image preview available)"),
            })
            if img:
                attached += 1
                blocks.append({"type": "image", "source": {"type": "base64", "media_type": img[1], "data": img[0]}})
        if attached:
            blocks.append({"type": "text", "text": f"CAPTION BLOCKS:\n{cap_lines}"})
            try:
                text = await agent.complete_vision(system, blocks, max_tokens=1500)
            except Exception as exc:
                logger.warning("ai/match vision pass failed, falling back to text: %s", exc)
                text = None

    if text is None:
        try:
            text = await agent.complete_text(system, user, max_tokens=1500)
        except Exception as exc:
            logger.warning("ai/match completion failed: %s", exc)
            return {"success": False, "error": str(exc)}
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    m = re.search(r"\{.*\}", cleaned, re.S)
    if not m:
        return {"success": False, "error": "no JSON in model reply"}
    try:
        data = json.loads(m.group(0))
        raw = data.get("assignments", [])
    except Exception:
        return {"success": False, "error": "unparseable model reply"}
    valid_posts = {p.index for p in req.posts}
    valid_caps = {c.index for c in req.captions}
    post_kind = {p.index: p.kind for p in req.posts}
    cap_type = {c.index: c.type for c in req.captions}
    assignments = []
    used_caps: set = set()
    for pair in raw:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        pi, ci = pair
        if pi not in valid_posts:
            continue
        if ci is not None and (ci not in valid_caps or ci in used_caps):
            ci = None
        # Enforce the type constraint even if the model ignored it.
        if ci is not None:
            pk, ct = post_kind.get(pi, ""), cap_type.get(ci, "")
            if pk and ct and pk != ct:
                ci = None
        if ci is not None:
            used_caps.add(ci)
        assignments.append([pi, ci])
    if not assignments:
        return {"success": False, "error": "empty assignment"}
    return {"success": True, "assignments": assignments}


class WizardAssistRequest(BaseModel):
    message: str
    context: dict = {}


_WIZARD_ASSIST_SYSTEM = """\
You are the inline assistant of a social-media post upload wizard. The user is \
partway through the wizard and typed a chat message. You receive the wizard state \
as JSON:
- step 2 = content sources: the user provides Google Drive folder link(s) for \
images, optionally a captions doc link and extra instructions, then builds a preview.
- step 3 = preview & schedule: prepared posts (index, type, files, caption, \
per-platform schedule) that can be rescheduled, re-captioned or removed before \
publishing. A null schedule means "post immediately on publish".
Dates/times are the user's local wall-clock: dates are YYYY-MM-DD, times HH:MM \
(24h). "now" in the state is the current local datetime and "weekday" its day name.

Decide whether the message is a wizard command expressible with the actions below.
If yes, reply ONLY with JSON (no prose, no markdown fences):
{"handled": true, "reply": "<short confirmation in the user's language>", "actions": [...]}
If the message is NOT something these actions can do (a general question, asking \
the AI to choose files by looking at their content, etc.), reply ONLY:
{"handled": false}

Actions (use exactly these shapes):
- {"type":"set_time","posts":[1,2]|"all","platform":"facebook"|"instagram"|"both",\
"date":"YYYY-MM-DD","time":"HH:MM","now":true}
  posts is 1-based ("P1","P2"... as shown to the user). Omit "date" to keep each \
post's current date; omit "time" to keep its current time; "now":true clears the \
schedule so the post publishes immediately (then omit date/time).
- {"type":"spread_times","posts":[..]|"all","platform":"...","start":"YYYY-MM-DDTHH:MM","interval_minutes":60}
  First selected post at start, each following post interval_minutes later.
- {"type":"delete_post","posts":[3]}
- {"type":"set_caption","post":2,"caption":"new caption text"}
Step-2-only actions:
- {"type":"set_folder","link":"https://drive.google.com/..."}  (images folder link)
- {"type":"set_captions_doc","link":"https://docs.google.com/..."}
- {"type":"set_instructions","text":"..."}
- {"type":"build_preview"}  (scan the given sources and build the posts preview)
- {"type":"ai_handle"}  (hand the whole job to the full AI agent — use when the \
user asks the AI to pick/scan the Drive files itself AND a folder link or picked \
files already exist in the state or their message)

Rules:
- Resolve relative dates ("tomorrow", "next friday") using "now"/"weekday".
- If the user names a platform, apply only to it; otherwise use "both".
- Never invent Drive links. If the user wants the AI to pick files but no folder \
link exists anywhere, reply handled:true asking for the folder link, with no actions.
- If the user asks to publish, reply handled:true telling them to press the \
Publish button on the preview card when ready — publishing is manual by design.
- CRITICAL: If the state shows step:3 (a "posts" array is present), NEVER return \
build_preview or ai_handle — those actions destroy all existing captions and \
schedules. At step 3, only set_time, spread_times, delete_post, and set_caption \
are valid.
- Multiple actions are allowed and run in order."""


@app.post("/api/posting/wizard/assist")
@limiter.limit("30/minute")
async def api_posting_wizard_assist(req: WizardAssistRequest, request: Request):
    """Interpret a chat message typed mid-wizard into structured wizard actions.

    Returns ``{"handled": false}`` when the message should fall through to the
    normal tool-using chat agent instead. The frontend applies the returned
    actions locally (reschedule, edit captions, fill sources…) — nothing here
    touches the publishing pipeline.
    """
    msg = (req.message or "").strip()
    if not msg or len(msg) > 4000:
        return {"success": False, "handled": False}
    try:
        ctx = json.dumps(req.context or {}, ensure_ascii=False)[:8000]
    except Exception:
        ctx = "{}"
    user = f"WIZARD STATE:\n{ctx}\n\nUSER MESSAGE:\n{msg}"
    try:
        text = await agent.complete_text(_WIZARD_ASSIST_SYSTEM, user, max_tokens=1200)
    except Exception as exc:
        logger.warning("wizard/assist completion failed: %s", exc)
        return {"success": False, "handled": False}
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    m = re.search(r"\{.*\}", cleaned, re.S)
    if not m:
        return {"success": False, "handled": False}
    try:
        data = json.loads(m.group(0))
    except Exception:
        return {"success": False, "handled": False}
    actions = data.get("actions") or []
    if not isinstance(actions, list):
        actions = []
    return {
        "success": True,
        "handled": bool(data.get("handled", False)),
        "reply": str(data.get("reply") or "")[:2000],
        "actions": actions[:40],
    }


@app.get("/api/posting/preview/pending")
async def api_posting_preview_pending(request: Request):
    """Hand the frontend a preview payload prepared by the chat agent's
    prepare_upload_preview tool. One-shot: the payload is removed on pickup."""
    import mcp_server
    session = get_session(request)
    uid = session.get("meta_user_id", "")
    payload = None
    for key in (uid, "", "anon"):
        payload = mcp_server.PENDING_PREVIEWS.pop(key, None)
        if payload:
            break
    if not payload:
        raise HTTPException(404, "No pending preview")
    return payload


@app.get("/api/posting/drive/preview/{file_id}")
async def api_posting_drive_preview(
    file_id: str,
    request: Request,
    mime: str = "image/jpeg",
    db: AsyncSession = Depends(get_db),
):
    """Stream a Drive image so the frontend can show a thumbnail before publishing.

    Authenticated to the current session's Google account; nothing is stored on
    disk and the bytes are streamed straight through to the browser.
    """
    safe_mime = mime if mime.startswith("image/") else "image/jpeg"
    google_token = await get_google_token(request, db)
    return StreamingResponse(
        media_bridge.stream_drive_file(file_id, google_token),
        media_type=safe_mime,
        headers={"Cache-Control": "private, max-age=300"},
    )


# Caption sources the picker should surface: native Google Docs/Sheets plus
# uploaded Word/Excel/CSV/PDF/text files (all parseable by _extract_caption_text).
_DOC_LIKE_MIMES = {
    "application/vnd.google-apps.document",
    "application/pdf",
    "text/plain",
    "text/markdown",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
}
_SHEET_LIKE_MIMES = {
    "application/vnd.google-apps.spreadsheet",
    "text/csv",
    "text/tab-separated-values",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel",
}


@app.get("/api/posting/drive/browse")
async def api_posting_drive_browse(
    request: Request,
    folder_id: str = "root",
    q: str = "",
    docs_mode: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """List/search folders and media files for the in-chat Drive browser.

    Without ``q`` it lists what's inside ``folder_id``. With ``q`` it searches
    the user's whole Drive by name (folders + media only).
    When ``docs_mode=true`` surfaces only Google Docs/Sheets (for captions picker).
    """
    google_token = await get_google_token(request, db)
    search = (q or "").strip()
    if search:
        safe = search.replace("\\", "\\\\").replace("'", "\\'")
        query = f"name contains '{safe}' and trashed=false"
    else:
        query = f"'{folder_id}' in parents and trashed=false"
    result = await google_api.list_drive_files(google_token, query=query)
    if not result.get("success"):
        raise HTTPException(502, result.get("error") or "Drive listing failed")
    items = []
    for f in result["files"]:
        mime = f.get("mimeType", "")
        is_folder = mime == "application/vnd.google-apps.folder"
        is_media = mime.startswith(("image/", "video/"))
        is_doc = mime in _DOC_LIKE_MIMES or mime in _SHEET_LIKE_MIMES
        if docs_mode:
            if not (is_folder or is_doc):
                continue
        elif search and not (is_folder or is_media):
            continue
        items.append({
            "id": f["id"],
            "name": f.get("name", ""),
            "mimeType": mime,
            "size": f.get("size"),
            "isFolder": is_folder,
            "isMedia": is_media,
            "isVideo": mime.startswith("video/"),
            "isDoc": mime in _DOC_LIKE_MIMES,
            "isSheet": mime in _SHEET_LIKE_MIMES,
            "modifiedTime": f.get("modifiedTime"),
        })
    items.sort(key=lambda x: (not x["isFolder"], x["name"].lower()))
    return {"items": items, "folder_id": folder_id, "query": search}


@app.post("/api/posting/upload/local")
@limiter.limit("20/minute")
async def api_posting_upload_local(
    request: Request,
    files: list[UploadFile] = File(...),
):
    """Upload files from the user's device for use in the posting wizard.

    Returns media items in the same shape as Drive scan results so the
    frontend can feed them straight into _uwRenderPreview().
    """
    session = get_session(request)
    session_key = _upload_session_key(session)
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    media = []
    skipped = []
    for f in files:
        name = f.filename or "upload"
        if not validate_file_extension(name):
            skipped.append({"name": name, "reason": "unsupported file type"})
            continue
        file_bytes = await f.read()
        if len(file_bytes) > max_bytes:
            skipped.append({"name": name, "reason": f"larger than {settings.MAX_UPLOAD_SIZE_MB} MB"})
            continue
        if not validate_mime_type(file_bytes, name):
            skipped.append({"name": name, "reason": "file content doesn't match its extension"})
            continue
        result = await process_uploaded_file(file_bytes, name)
        if not result.get("success"):
            skipped.append({"name": name, "reason": result.get("error") or "processing failed"})
            continue
        file_id = result["stored_path"].split("/")[-1]
        upload_info = {
            "file_id": file_id,
            "name": result["original_name"],
            "type": result["file_type"],
            "path": result["stored_path"],
            "sha256": result["sha256"],
        }
        _session_uploads.setdefault(session_key, []).append(upload_info)
        mime = f.content_type or ("video/mp4" if result["file_type"] == "video" else "image/jpeg")
        media.append({
            "id": f"local:{file_id}",
            "name": result["original_name"],
            "mime_type": mime,
            "size": len(file_bytes),
            "is_video": result["file_type"] == "video",
            "local_file_id": file_id,
        })
    return {"media": media, "captions": [], "skipped": skipped}


# Caption file extensions we can parse without extra runtime dependencies.
_CAPTION_FILE_EXTS = {".txt", ".md", ".csv", ".tsv", ".docx", ".xlsx", ".pdf"}


def _extract_docx_text(data: bytes) -> str:
    """Extract paragraph text from a .docx (Open XML) without python-docx."""
    import io
    import zipfile
    from xml.etree import ElementTree as ET

    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    paragraphs: list[str] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        xml = zf.read("word/document.xml")
    root = ET.fromstring(xml)
    for para in root.iter(f"{W}p"):
        texts = [node.text for node in para.iter(f"{W}t") if node.text]
        paragraphs.append("".join(texts))
    return "\n".join(paragraphs)


def _xlsx_cell_value(raw: str) -> str:
    """Render a numeric xlsx cell, converting plausible Excel date serials.

    Excel stores dates as days since 1899-12-30; without parsing cell styles we
    use a range heuristic (≈2023–2078) so schedule columns come through as
    readable dates instead of numbers like ``46091.54``.
    """
    try:
        num = float(raw)
    except (TypeError, ValueError):
        return raw or ""
    if 45000 <= num <= 65000:
        dt = datetime(1899, 12, 30) + timedelta(days=num)
        if num % 1:
            return dt.strftime("%m/%d/%Y %H:%M")
        return dt.strftime("%m/%d/%Y")
    return raw


def _extract_xlsx_rows(data: bytes) -> list[list[str]]:
    """Extract cell rows from a .xlsx (Open XML) without openpyxl.

    Cells are positioned by their column reference so empty cells keep the
    columns aligned (required for header-based calendar parsing).
    """
    import io
    import zipfile
    from xml.etree import ElementTree as ET

    S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in zf.namelist():
            sroot = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in sroot.iter(f"{S}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{S}t")))
        # First worksheet
        sheet_names = [n for n in zf.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml", n)]
        if not sheet_names:
            return []
        wroot = ET.fromstring(zf.read(sorted(sheet_names)[0]))

    def col_index(ref: str) -> Optional[int]:
        letters = "".join(ch for ch in (ref or "") if ch.isalpha()).upper()
        if not letters:
            return None
        idx = 0
        for ch in letters:
            idx = idx * 26 + (ord(ch) - 64)
        return idx - 1

    rows: list[list[str]] = []
    for row in wroot.iter(f"{S}row"):
        cells: dict[int, str] = {}
        pos = 0
        for c in row.iter(f"{S}c"):
            ci = col_index(c.get("r", ""))
            if ci is None:
                ci = pos
            pos = ci + 1
            if c.get("t") == "inlineStr":  # value lives in <is><t>, not <v>
                txt = "".join(t.text or "" for t in c.iter(f"{S}t"))
                if txt:
                    cells[ci] = txt
                continue
            v = c.find(f"{S}v")
            if v is None or v.text is None:
                continue
            if c.get("t") == "s":  # shared-string index
                try:
                    cells[ci] = shared[int(v.text)]
                except (ValueError, IndexError):
                    pass
            else:
                cells[ci] = _xlsx_cell_value(v.text)
        if cells:
            width = max(cells) + 1
            rows.append([cells.get(i, "") for i in range(width)])
    return rows


def _extract_xlsx_text(data: bytes) -> str:
    """Flatten .xlsx rows into caption blocks (fallback when no header row)."""
    rows = _extract_xlsx_rows(data)
    # Cell-per-line so a leading date/type cell stays strippable as a prefix.
    return "\n---\n".join("\n".join(c.strip() for c in row if c.strip()) for row in rows if any(row))


def _extract_caption_text(data: bytes, filename: str) -> str:
    """Best-effort plain-text extraction from an uploaded caption file."""
    ext = Path(filename or "").suffix.lower()
    if ext in (".txt", ".md"):
        return data.decode("utf-8", errors="replace")
    if ext in (".csv", ".tsv"):
        sep = "\t" if ext == ".tsv" else ","
        import csv
        import io
        rows = list(csv.reader(io.StringIO(data.decode("utf-8", errors="replace")), delimiter=sep))
        # Try column-aware calendar parsing first; fall back to cell-per-line blocks.
        return "\n---\n".join("\n".join(c.strip() for c in row if c.strip()) for row in rows if any(row))
    if ext == ".docx":
        return _extract_docx_text(data)
    if ext == ".xlsx":
        return _extract_xlsx_text(data)
    if ext == ".pdf":
        try:
            import pdfplumber
            import io
            with pdfplumber.open(io.BytesIO(data)) as pdf:
                return "\n".join((page.extract_text() or "") for page in pdf.pages)
        except Exception:
            return ""
    # Unknown — try utf-8 anyway.
    return data.decode("utf-8", errors="replace")


@app.post("/api/posting/upload/captions")
@limiter.limit("20/minute")
async def api_posting_upload_captions(
    request: Request,
    file: UploadFile = File(...),
):
    """Parse a captions file uploaded from the user's device into caption blocks.

    Accepts .txt/.md/.csv/.tsv/.docx/.xlsx/.pdf and returns the same
    ``{"captions": [...]}`` shape as the Drive scan, so the wizard can match
    captions to media by index regardless of where each came from.
    """
    ext = Path(file.filename or "").suffix.lower()
    if ext not in _CAPTION_FILE_EXTS:
        raise HTTPException(400, f"Unsupported caption file type '{ext}'. Use txt, csv, docx, xlsx or pdf.")
    data = await file.read()
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(data) > max_bytes:
        raise HTTPException(413, "Caption file is too large.")
    try:
        # Tabular files with a labelled header row get per-column parsing
        # (caption/date/time/image columns) — same as Google Sheets from Drive.
        rows: list = []
        if ext == ".xlsx":
            rows = _extract_xlsx_rows(data)
        elif ext in (".csv", ".tsv"):
            import csv
            import io
            sep = "\t" if ext == ".tsv" else ","
            rows = list(csv.reader(io.StringIO(data.decode("utf-8", errors="replace")), delimiter=sep))
        if rows:
            structured = _captions_from_rows(rows)
            if structured is not None:
                return {"captions": structured, "blocks": len(structured)}
        raw_text = _extract_caption_text(data, file.filename or "")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, f"Could not read caption file: {exc}")
    captions = _split_caption_blocks(raw_text)
    return {"captions": captions, "blocks": len(captions)}


@app.get("/api/posting/local/preview/{file_id}")
async def api_posting_local_preview(file_id: str, request: Request):
    """Serve a locally-uploaded file as an inline preview image."""
    session = get_session(request)
    session_key = _upload_session_key(session)
    uploads = _session_uploads.get(session_key, [])
    entry = next((u for u in uploads if u["file_id"] == file_id), None)
    if not entry:
        raise HTTPException(404, "File not found")
    path = Path(entry["path"])
    if not path.exists():
        raise HTTPException(404, "File not found on disk")
    mime = "image/jpeg"
    suffix = path.suffix.lower()
    if suffix in (".png",):
        mime = "image/png"
    elif suffix in (".gif",):
        mime = "image/gif"
    elif suffix in (".webp",):
        mime = "image/webp"
    async def _iter():
        async with aiofiles.open(path, "rb") as fh:
            while chunk := await fh.read(65536):
                yield chunk
    return StreamingResponse(_iter(), media_type=mime, headers={"Cache-Control": "private, max-age=300"})


class PublishFacebookRequest(BaseModel):
    page_id: str
    caption: str = ""
    media_url: str = ""
    scheduled_time: Optional[str] = None


class PublishInstagramRequest(BaseModel):
    instagram_id: str
    caption: str = ""
    media_url: str = ""
    media_type: str = "IMAGE"  # IMAGE, REELS, STORIES
    scheduled_time: Optional[str] = None


@app.post("/api/posting/publish/facebook")
async def api_publish_facebook(
    req: PublishFacebookRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Publish or schedule a Facebook Page post via the Posting app token."""
    token = await get_posting_token(request, db)

    # Exchange user token for page-specific access token (direct lookup with
    # /me/accounts fallback and real Meta error reporting).
    try:
        page_token = await _get_page_token(token, req.page_id)
    except HTTPException as exc:
        _sess_pt = get_session(request)
        await log_posting_event(db, "token_error", f"Facebook page token failed for page {req.page_id}",
            level="error", platform="facebook", page_id=req.page_id or "",
            username=_sess_pt.get("posting_username") or _sess_pt.get("username") or "",
            user_id=_sess_pt.get("user_id"), detail=str(exc.detail)[:1000])
        raise

    # Convert ISO datetime string → Unix timestamp for scheduled posts
    scheduled_ts: Optional[int] = None
    if req.scheduled_time:
        try:
            from datetime import timezone as _tz
            dt = datetime.fromisoformat(req.scheduled_time.replace("Z", "+00:00"))
            scheduled_ts = int(dt.timestamp())
        except Exception:
            raise HTTPException(400, "Invalid scheduled_time — use ISO 8601 format")
        # Meta requires scheduled_publish_time to be at least 10 minutes in the future.
        if scheduled_ts < int(datetime.now(timezone.utc).timestamp()) + 600:
            scheduled_ts = None

    base = settings.meta_graph_base_url
    async with httpx.AsyncClient(timeout=20) as client:
        if req.media_url:
            # Photo post
            payload: dict = {
                "url": req.media_url,
                "caption": req.caption,
                "access_token": page_token,
            }
            if scheduled_ts:
                payload["published"] = "false"
                payload["scheduled_publish_time"] = str(scheduled_ts)
            r = await _meta_post_retry(client, f"{base}/{req.page_id}/photos", payload)
        else:
            # Text / link post
            payload = {
                "message": req.caption,
                "access_token": page_token,
            }
            if scheduled_ts:
                payload["published"] = "false"
                payload["scheduled_publish_time"] = str(scheduled_ts)
            r = await _meta_post_retry(client, f"{base}/{req.page_id}/feed", payload)

    if r.status_code not in (200, 201):
        err = r.json().get("error", {}).get("message", "Failed to publish to Facebook")
        _sess = get_session(request)
        await log_posting_event(db, "publish_fail", f"Facebook post failed: {err}",
            level="error", platform="facebook", page_id=req.page_id or "",
            username=_sess.get("posting_username") or _sess.get("username") or "",
            user_id=_sess.get("user_id"),
            detail=f"HTTP {r.status_code}: {r.text[:500]}")
        raise HTTPException(502, err)
    data = r.json()
    _post_id = data.get("id") or data.get("post_id")
    _sess2 = get_session(request)
    _etype = "schedule_ok" if scheduled_ts else "publish_ok"
    await log_posting_event(db, _etype, f"Facebook post {'scheduled' if scheduled_ts else 'published'} to page {req.page_id}",
        level="info", platform="facebook", page_id=req.page_id or "",
        username=_sess2.get("posting_username") or _sess2.get("username") or "",
        user_id=_sess2.get("user_id"),
        detail=f"post_id={_post_id}")
    return {"success": True, "post_id": _post_id}


@app.post("/api/posting/publish/instagram")
async def api_publish_instagram(
    req: PublishInstagramRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Publish a post/reel/story to an Instagram Business account."""
    token = await get_posting_token(request, db)
    base = settings.meta_graph_base_url

    # Build container creation payload
    container_data: dict = {"access_token": token}
    if req.caption:
        container_data["caption"] = req.caption

    # No mime info on this endpoint — sniff video from the URL extension so
    # video stories / videos aren't sent as image_url (Meta rejects that).
    _url_path = (req.media_url or "").split("?")[0].lower()
    _looks_video = _url_path.endswith((".mp4", ".mov", ".m4v", ".webm"))
    if req.media_type == "REELS":
        container_data["media_type"] = "REELS"
        container_data["video_url"] = req.media_url
    elif req.media_type == "STORIES":
        container_data["media_type"] = "STORIES"
        container_data["video_url" if _looks_video else "image_url"] = req.media_url
    elif req.media_url and (req.media_type == "VIDEO" or _looks_video):
        container_data["media_type"] = "REELS"
        container_data["video_url"] = req.media_url
    else:
        # Standard image post
        if req.media_url:
            container_data["image_url"] = req.media_url

    # Pre-flight: Instagram requires Meta to fetch the media from a public URL.
    _media_in_req = container_data.get("image_url") or container_data.get("video_url") or ""
    if _media_in_req:
        _pu = _public_base_url(request)
        if not _pu or _pu.startswith("http://localhost") or _pu.startswith("http://127."):
            _sess_pre = get_session(request)
            _msg = (
                f"Instagram publishing requires a publicly reachable server URL — "
                f"this server appears to be running at {_pu or '(no URL)'}, "
                "which Meta cannot reach. Set BASE_URL to the public HTTPS URL of this server."
            )
            await log_posting_event(db, "publish_fail", _msg,
                level="error", platform="instagram", page_id=req.instagram_id or "",
                username=_sess_pre.get("posting_username") or _sess_pre.get("username") or "",
                user_id=_sess_pre.get("user_id"), detail=f"base_url={_pu}")
            raise HTTPException(502, _msg)

    # Step 1 — create media container
    async with httpx.AsyncClient(timeout=30) as client:
        cr = await _meta_post_retry(client, f"{base}/{req.instagram_id}/media", container_data)
    if cr.status_code not in (200, 201):
        _err_body_ig = cr.json() if cr.content else {}
        err = _err_body_ig.get("error", {}).get("message", "Failed to create Instagram media container")
        _full_err_ig, _ = _classify_meta_error(_err_body_ig)
        _sess_ig = get_session(request)
        _media_url_used = container_data.get("image_url") or container_data.get("video_url") or ""
        await log_posting_event(db, "publish_fail", f"Instagram container creation failed: {_full_err_ig}",
            level="error", platform="instagram", page_id=req.instagram_id or "",
            username=_sess_ig.get("posting_username") or _sess_ig.get("username") or "",
            user_id=_sess_ig.get("user_id"),
            detail=f"HTTP {cr.status_code}: {cr.text[:300]} | media_url={_media_url_used}")
        raise HTTPException(502, err)
    creation_id = cr.json().get("id")
    if not creation_id:
        raise HTTPException(502, "No creation_id returned from Instagram container step")

    # Step 2 — publish the container
    async with httpx.AsyncClient(timeout=30) as client:
        pr = await _meta_post_retry(
            client,
            f"{base}/{req.instagram_id}/media_publish",
            {"creation_id": creation_id, "access_token": token},
        )
    if pr.status_code not in (200, 201):
        err = pr.json().get("error", {}).get("message", "Failed to publish Instagram media")
        _sess_ig2 = get_session(request)
        await log_posting_event(db, "publish_fail", f"Instagram publish failed: {err}",
            level="error", platform="instagram", page_id=req.instagram_id or "",
            username=_sess_ig2.get("posting_username") or _sess_ig2.get("username") or "",
            user_id=_sess_ig2.get("user_id"),
            detail=f"HTTP {pr.status_code}: {pr.text[:500]}")
        raise HTTPException(502, err)
    _ig_media_id = pr.json().get("id")
    _sess_ig3 = get_session(request)
    await log_posting_event(db, "publish_ok", f"Instagram post published to {req.instagram_id}",
        level="info", platform="instagram", page_id=req.instagram_id or "",
        username=_sess_ig3.get("posting_username") or _sess_ig3.get("username") or "",
        user_id=_sess_ig3.get("user_id"),
        detail=f"media_id={_ig_media_id} type={req.media_type}")
    return {"success": True, "media_id": _ig_media_id}


@app.get("/api/posting/scheduled")
async def api_posting_scheduled(request: Request, db: AsyncSession = Depends(get_db)):
    """Return recent scheduled posts (last 20)."""
    result = await db.execute(
        select(ScheduledPost).order_by(ScheduledPost.created_at.desc()).limit(20)
    )
    posts = result.scalars().all()
    return [
        {
            "id": p.id,
            "platform": p.platform,
            "page_id": p.page_id or p.instagram_id or "",
            "content": p.caption or "",
            "scheduled_time": p.scheduled_time.isoformat() if p.scheduled_time else None,
            "status": p.status,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in posts
    ]


@app.get("/api/posting/my-pages")
async def api_posting_my_pages(request: Request, db: AsyncSession = Depends(get_db)):
    """Pages accessible to the current user: assigned pages for users, all Meta pages for admins."""
    session = get_session(request)
    user_id = session.get("user_id")
    role = session.get("user_role", "user")

    if role == "admin":
        try:
            token = await get_posting_token(request, db)
            pages_result = await meta_api.get_pages(token)
            if pages_result.get("success"):
                raw = pages_result["data"]
                pages = raw["data"] if isinstance(raw, dict) else raw
                out = [{"id": p["id"], "name": p.get("name", ""), "platform": "facebook"} for p in pages]
                async with httpx.AsyncClient(timeout=15) as client:
                    for p in pages:
                        r = await client.get(
                            f"{settings.meta_graph_base_url}/{p['id']}",
                            params={"fields": "instagram_business_account{id,name,username}", "access_token": token},
                        )
                        if r.status_code == 200:
                            iba = r.json().get("instagram_business_account")
                            if iba:
                                out.append({
                                    "id": iba["id"],
                                    "name": iba.get("name") or f"@{iba.get('username', '')}",
                                    "platform": "instagram",
                                    "page_id": p["id"],
                                })
                return out
        except HTTPException:
            pass
        # Fallback: all distinct assigned pages from DB
        result = await db.execute(select(UserPageAssignment))
        rows = result.scalars().all()
        seen: set = set()
        out = []
        for r in rows:
            if r.page_id not in seen:
                seen.add(r.page_id)
                out.append({"id": r.page_id, "name": r.page_name or r.page_id, "platform": r.platform})
        return out

    if not user_id:
        return []
    result = await db.execute(
        select(UserPageAssignment).where(UserPageAssignment.user_id == user_id)
    )
    rows = result.scalars().all()
    return [
        {"id": r.page_id, "name": r.page_name or r.page_id, "platform": r.platform, "meta_app_db_id": r.meta_app_db_id}
        for r in rows
    ]


def _serialize_posting_clients(clients: list) -> list:
    return [
        {
            "id": c.id,
            "name": c.name,
            "color_tag": c.color_tag,
            "profiles": [
                {
                    "id": p.id,
                    "label": p.label,
                    "fb_page_id": p.fb_page_id,
                    "fb_page_name": p.fb_page_name or p.fb_page_id,
                    "ig_account_id": p.ig_account_id,
                    "ig_username": p.ig_username,
                }
                for p in (c.posting_profiles or [])
            ],
        }
        for c in clients
    ]


@app.get("/api/posting/clients")
async def api_posting_clients(request: Request, db: AsyncSession = Depends(get_db)):
    """Clients with their posting profiles, scoped to the current user."""
    session = get_session(request)
    user_id = session.get("user_id")
    role = session.get("user_role", "user")

    if role == "admin":
        result = await db.execute(
            select(Client)
            .options(selectinload(Client.posting_profiles))
            .where(Client.is_archived == False)
            .order_by(Client.sort_order, Client.name)
        )
        return _serialize_posting_clients(result.scalars().all())

    if not user_id:
        return []

    result = await db.execute(
        select(Client)
        .join(UserClientAssignment, UserClientAssignment.client_id == Client.id)
        .options(selectinload(Client.posting_profiles))
        .where(UserClientAssignment.user_id == user_id, Client.is_archived == False)
        .order_by(Client.sort_order, Client.name)
    )
    clients = result.scalars().all()
    return _serialize_posting_clients([c for c in clients if c.posting_profiles])


class PostingProfileRequest(BaseModel):
    label: str = "Main"
    fb_page_id: str
    fb_page_name: str = ""
    ig_account_id: str = ""
    ig_username: str = ""


@app.post("/api/posting/clients/{client_id}/profiles")
async def api_add_posting_profile(
    client_id: int,
    req: PostingProfileRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Admin: assign a Facebook Page (+ optional Instagram) to a client for posting."""
    session = get_session(request)
    if session.get("user_role") != "admin":
        raise HTTPException(403, "Admin only")
    client = await db.get(Client, client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    profile = ClientPostingProfile(
        client_id=client_id,
        label=req.label or "Main",
        fb_page_id=req.fb_page_id,
        fb_page_name=req.fb_page_name or None,
        ig_account_id=req.ig_account_id or None,
        ig_username=req.ig_username or None,
    )
    db.add(profile)
    await db.flush()
    return {
        "id": profile.id,
        "label": profile.label,
        "fb_page_id": profile.fb_page_id,
        "fb_page_name": profile.fb_page_name,
        "ig_account_id": profile.ig_account_id,
        "ig_username": profile.ig_username,
    }


@app.delete("/api/posting/clients/profiles/{profile_id}")
async def api_delete_posting_profile(
    profile_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Admin: remove a posting profile."""
    session = get_session(request)
    if session.get("user_role") != "admin":
        raise HTTPException(403, "Admin only")
    profile = await db.get(ClientPostingProfile, profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")
    await db.delete(profile)
    return {"success": True}


# ── Business Portfolios (user-owned page groupings) ─────────────────────────

class BusinessPortfolioRequest(BaseModel):
    name: str
    pages: list[dict] = []   # [{platform, id, name}]


def _serialize_portfolio(p) -> dict:
    return {"id": p.id, "name": p.name, "pages": p.pages or []}


def _require_user_id(request: Request) -> int:
    uid = get_session(request).get("user_id")
    if not uid:
        raise HTTPException(401, "Sign in to manage portfolios")
    return uid


@app.get("/api/posting/portfolios")
async def api_list_portfolios(request: Request, db: AsyncSession = Depends(get_db)):
    """List the current user's business portfolios."""
    uid = get_session(request).get("user_id")
    if not uid:
        return []
    result = await db.execute(
        select(BusinessPortfolio).where(BusinessPortfolio.user_id == uid).order_by(BusinessPortfolio.name)
    )
    return [_serialize_portfolio(p) for p in result.scalars().all()]


@app.post("/api/posting/portfolios", status_code=201)
async def api_create_portfolio(
    req: BusinessPortfolioRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    uid = _require_user_id(request)
    name = (req.name or "").strip()
    if not name:
        raise HTTPException(400, "Portfolio name is required")
    p = BusinessPortfolio(user_id=uid, name=name, pages=req.pages or [])
    db.add(p)
    await db.flush()
    return _serialize_portfolio(p)


@app.put("/api/posting/portfolios/{portfolio_id}")
async def api_update_portfolio(
    portfolio_id: int, req: BusinessPortfolioRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    uid = _require_user_id(request)
    p = await db.get(BusinessPortfolio, portfolio_id)
    if not p or p.user_id != uid:
        raise HTTPException(404, "Portfolio not found")
    if req.name is not None and req.name.strip():
        p.name = req.name.strip()
    if req.pages is not None:
        p.pages = req.pages
    await db.flush()
    return _serialize_portfolio(p)


@app.delete("/api/posting/portfolios/{portfolio_id}")
async def api_delete_portfolio(
    portfolio_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    uid = _require_user_id(request)
    p = await db.get(BusinessPortfolio, portfolio_id)
    if not p or p.user_id != uid:
        raise HTTPException(404, "Portfolio not found")
    await db.delete(p)
    return {"success": True}


@app.get("/api/posting/my-queue")
async def api_my_queue(
    request: Request,
    db: AsyncSession = Depends(get_db),
    ig_account_id: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    statuses: str = "pending,failed",
):
    """Scheduled Instagram posts owned by the current posting account, with filters."""
    sess = get_session(request)
    posting_user_id = sess.get("posting_user_id")
    if not posting_user_id:
        # The session may have lost its posting_user_id (Meta connected in a
        # popup/other tab, portfolio user, expired cookie). Scheduled posts are
        # stored with the SAME fallback the bulk endpoint uses — the most recent
        # active posting account — so mirror it here, otherwise a correctly
        # scheduled post would never appear in My Queue.
        res = await db.execute(
            select(ConnectedPostingAccount.facebook_user_id)
            .where(ConnectedPostingAccount.is_active == True)
            .order_by(ConnectedPostingAccount.id.desc())
        )
        posting_user_id = res.scalars().first()
    if not posting_user_id and not ig_account_id:
        return {"posts": [], "total": 0}
    status_list = [s.strip() for s in statuses.split(",") if s.strip()]
    q = select(ScheduledPost).where(
        ScheduledPost.platform == "instagram",
        ScheduledPost.status.in_(status_list),
    )
    if ig_account_id:
        q = q.where(ScheduledPost.instagram_id == ig_account_id)
    if search:
        q = q.where(ScheduledPost.caption.ilike(f"%{search}%"))
    if date_from:
        try:
            dt = datetime.fromisoformat(date_from)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            q = q.where(ScheduledPost.scheduled_time >= dt)
        except Exception:
            pass
    if date_to:
        try:
            dt = datetime.fromisoformat(date_to)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            q = q.where(ScheduledPost.scheduled_time <= dt)
        except Exception:
            pass
    q = q.order_by(ScheduledPost.scheduled_time)
    result = await db.execute(q)
    rows = result.scalars().all()
    # Ownership scoping happens in Python: job_data is a generic JSON column, so
    # the PostgreSQL-only `.astext` operator can't be used portably (it raises an
    # AttributeError on SQLite). When an IG account is selected, instagram_id
    # already scopes to an account the user's token can reach, so we accept the
    # user's own rows plus legacy rows that never recorded a posting_user_id.
    if not posting_user_id:
        # If we still can't resolve an owner, only show rows that match the
        # explicit IG account filter (already narrow enough to be user-scoped).
        posts = list(rows) if ig_account_id else []
    else:
        posts = []
        for p in rows:
            owner = (p.job_data or {}).get("posting_user_id")
            if ig_account_id:
                # An IG account filter already scopes to an account the user's
                # token can reach, so accept the user's own rows plus legacy
                # rows that never recorded a posting_user_id.
                if owner and owner != posting_user_id:
                    continue
            else:
                # "All accounts" view is not account-scoped, so require strict
                # ownership — never surface another operator's (or unattributed
                # legacy) posts here. Legacy null-owner posts still show when
                # their specific account is selected (the branch above).
                if owner != posting_user_id:
                    continue
            posts.append(p)
    out = []
    for p in posts:
        jd = p.job_data or {}
        media = jd.get("media", [])
        thumb = None
        if media:
            m0 = media[0]
            _mime = m0.get("mime_type") or ""
            # Only offer a thumbnail for image media (videos fall back to the
            # 🎬 placeholder). The endpoint resolves disk/Drive sources itself.
            if (not _mime or _mime.startswith("image/")) and (
                m0.get("local_file_id") or m0.get("cache_file_id") or m0.get("drive_file_id")
            ):
                thumb = f"/api/posting/my-queue/{p.id}/thumb"
        out.append({
            "id": p.id,
            "status": p.status,
            "instagram_id": p.instagram_id,
            "caption": p.caption or "",
            "hashtags": jd.get("hashtags", []),
            "media_type": p.media_type or "IMAGE",
            "scheduled_time": p.scheduled_time.isoformat() if p.scheduled_time else None,
            "thumbnail": thumb,
            "media_count": len(media),
            "error_message": p.error_message,
            "attempts": p.attempts or 0,
        })
    return {"posts": out, "total": len(out)}


@app.get("/api/posting/queue-stats")
async def api_queue_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Per-user counts of their Instagram scheduled posts: how many are still
    on the queue, how many published successfully, and how many failed.

    Ownership is scoped to the current posting account exactly like
    /api/posting/my-queue (the 'All accounts' branch — strict ownership, no
    legacy null-owner leakage), so the numbers reflect only the posts this
    user scheduled.
    """
    sess = get_session(request)
    posting_user_id = sess.get("posting_user_id")
    if not posting_user_id:
        res = await db.execute(
            select(ConnectedPostingAccount.facebook_user_id)
            .where(ConnectedPostingAccount.is_active == True)
            .order_by(ConnectedPostingAccount.id.desc())
        )
        posting_user_id = res.scalars().first()
    stats = {"scheduled": 0, "posted": 0, "failed": 0}
    if not posting_user_id:
        return stats
    result = await db.execute(
        select(ScheduledPost.status, ScheduledPost.job_data).where(
            ScheduledPost.platform == "instagram",
            ScheduledPost.status.in_(("pending", "processing", "published", "failed")),
        )
    )
    for status, jd in result.all():
        owner = (jd or {}).get("posting_user_id")
        if owner != posting_user_id:
            continue
        if status in ("pending", "processing"):
            stats["scheduled"] += 1
        elif status == "published":
            stats["posted"] += 1
        elif status == "failed":
            stats["failed"] += 1
    return stats


async def _resolve_posting_uid(request: Request, db: AsyncSession) -> Optional[str]:
    """The current posting account uid — session first, else most-recent active
    account (the same fallback the bulk scheduler records on each post)."""
    uid = get_session(request).get("posting_user_id")
    if uid:
        return uid
    res = await db.execute(
        select(ConnectedPostingAccount.facebook_user_id)
        .where(ConnectedPostingAccount.is_active == True)
        .order_by(ConnectedPostingAccount.id.desc())
    )
    return res.scalars().first()


def _owns_scheduled_post(post: "ScheduledPost", posting_user_id: Optional[str]) -> bool:
    """True if the current posting account may manage this scheduled post.
    Accepts the user's own rows plus legacy rows that never recorded an owner."""
    owner = (post.job_data or {}).get("posting_user_id")
    if owner is None:
        return True
    return bool(posting_user_id) and owner == posting_user_id


@app.patch("/api/posting/my-queue/{post_id}")
async def api_my_queue_update(
    post_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Edit caption, hashtags, or scheduled_time of a user-owned pending IG post."""
    posting_user_id = await _resolve_posting_uid(request, db)
    body = await request.json()
    post = await db.get(ScheduledPost, post_id)
    if not post:
        raise HTTPException(404, "Post not found")
    jd = post.job_data or {}
    if not _owns_scheduled_post(post, posting_user_id):
        raise HTTPException(403, "You don't own this post")
    if post.status not in ("pending", "failed"):
        raise HTTPException(409, "Cannot edit a post that is currently publishing or already finished")
    if "caption" in body or "hashtags" in body:
        caption_text = body.get("caption", post.caption or "")
        new_tags = body.get("hashtags", jd.get("hashtags", []))
        post.caption = _compose_caption(caption_text, new_tags)
        new_jd = dict(jd)
        new_jd["hashtags"] = new_tags
        post.job_data = new_jd
        flag_modified(post, "job_data")
    if "scheduled_time" in body:
        try:
            st = body["scheduled_time"]
            if st:
                dt = datetime.fromisoformat(str(st).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                post.scheduled_time = dt
            else:
                post.scheduled_time = None
        except Exception as exc:
            raise HTTPException(400, f"Invalid scheduled_time: {exc}")
    await db.commit()
    return {"success": True, "id": post.id}


@app.get("/api/posting/my-queue/{post_id}/thumb")
async def api_my_queue_thumb(post_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Serve the first media item of a scheduled post as an inline image.

    Handles every storage case so the My Queue list/grid/preview shows a real
    picture: device uploads and Drive-cached files stream from disk, while
    Drive-only media (not yet pre-cached) is downloaded with the post's Google
    token and converted to JPEG on the fly. Non-image media returns 404 so the
    UI falls back to its 🎬/🖼️ placeholder.
    """
    posting_user_id = await _resolve_posting_uid(request, db)
    post = await db.get(ScheduledPost, post_id)
    if not post or not _owns_scheduled_post(post, posting_user_id):
        raise HTTPException(404, "Not found")
    jd = post.job_data or {}
    media = jd.get("media") or []
    if not media:
        raise HTTPException(404, "No media")
    m0 = media[0]
    mime = m0.get("mime_type") or ""
    if mime and not mime.startswith("image/"):
        raise HTTPException(404, "Not an image")
    # 1) Disk-backed (device upload or pre-cached Drive file).
    fid = m0.get("local_file_id") or m0.get("cache_file_id")
    if fid and "/" not in fid and "\\" not in fid and not fid.startswith("."):
        path = _UPLOAD_DIR / fid
        if path.is_file():
            async with aiofiles.open(path, "rb") as fh:
                data = await fh.read()
            out, out_mime, _ = await asyncio.to_thread(
                _ensure_jpeg_sync, data, mime or "image/jpeg", m0.get("filename") or "image")
            return Response(content=out, media_type=out_mime,
                headers={"Cache-Control": "private, max-age=600"})
    # 2) Drive-only: download with the post's Google account and convert.
    drive_id = m0.get("drive_file_id")
    if not drive_id:
        raise HTTPException(404, "Media not available")
    try:
        google_token = await _google_token_for_uid(jd.get("google_user_id"), db)
    except Exception:
        raise HTTPException(502, "Could not access source media")
    dl = await google_api.download_drive_file(drive_id, google_token)
    if not dl.get("success"):
        raise HTTPException(502, "Source media unavailable")
    out, out_mime, _ = await asyncio.to_thread(
        _ensure_jpeg_sync, dl["bytes"], mime or "image/jpeg", m0.get("filename") or "image")
    return Response(content=out, media_type=out_mime,
        headers={"Cache-Control": "private, max-age=600"})


@app.get("/api/posting/calendar")
async def api_posting_calendar(
    page_id: str,
    year: int,
    month: int,
    request: Request,
    platform: str = "facebook",
    db: AsyncSession = Depends(get_db),
):
    """Calendar data for a page/month: scheduled posts from DB + published posts from Meta API.

    Works for both Facebook Pages (reads /{page}/feed) and Instagram Business
    accounts (reads /{ig}/media). Every entry is tagged with its platform so
    the UI can show the right icon.
    """
    import calendar as _cal
    from datetime import timezone as _tz

    _, last_day = _cal.monthrange(year, month)
    month_start = datetime(year, month, 1, tzinfo=_tz.utc)
    month_end = datetime(year, month, last_day, 23, 59, 59, tzinfo=_tz.utc)
    is_instagram = platform == "instagram"

    sched_result = await db.execute(
        select(ScheduledPost).where(
            ((ScheduledPost.page_id == page_id) | (ScheduledPost.instagram_id == page_id)),
            ScheduledPost.status == "pending",
            ScheduledPost.scheduled_time >= month_start,
            ScheduledPost.scheduled_time <= month_end,
        )
    )
    scheduled = sched_result.scalars().all()

    published: list = []
    page_token = ""  # set inside the try; checked again before the FB scheduled-posts fetch
    try:
        token = await get_posting_token(request, db)
        if is_instagram:
            # IG media is read with the access token of the Page that owns the
            # account, so resolve that page token first.
            page_token = token
            try:
                cache_key = get_session(request).get("posting_user_id") or hashlib.sha256(token.encode()).hexdigest()[:16]
                pages_res = await _get_pages_cached(token, cache_key)
                if pages_res.get("success"):
                    raw = pages_res["data"]
                    for pg in (raw["data"] if isinstance(raw, dict) else raw):
                        iba = pg.get("instagram_business_account") or {}
                        if iba.get("id") == page_id:
                            page_token = pg.get("access_token", token)
                            break
            except Exception:
                pass
            async with httpx.AsyncClient(timeout=20) as client:
                media_r = await client.get(
                    f"{settings.meta_graph_base_url}/{page_id}/media",
                    params={
                        "fields": "id,caption,media_type,media_url,thumbnail_url,permalink,timestamp",
                        "limit": 100,
                        "since": int(month_start.timestamp()),
                        "until": int(month_end.timestamp()),
                        "access_token": page_token,
                    },
                )
            if media_r.status_code == 200:
                published = media_r.json().get("data", [])
        else:
            async with httpx.AsyncClient(timeout=15) as client:
                page_r = await client.get(
                    f"{settings.meta_graph_base_url}/{page_id}",
                    params={"fields": "access_token", "access_token": token},
                )
            page_token = page_r.json().get("access_token", token) if page_r.status_code == 200 else token
            async with httpx.AsyncClient(timeout=20) as client:
                feed_r = await client.get(
                    f"{settings.meta_graph_base_url}/{page_id}/feed",
                    params={
                        "fields": "id,message,created_time,story,full_picture,permalink_url",
                        "since": int(month_start.timestamp()),
                        "until": int(month_end.timestamp()),
                        "limit": 100,
                        "access_token": page_token,
                    },
                )
            if feed_r.status_code == 200:
                published = feed_r.json().get("data", [])
    except HTTPException:
        pass

    days: dict = {}
    for p in scheduled:
        if p.scheduled_time:
            day = str(p.scheduled_time.day)
            days.setdefault(day, {"scheduled": [], "published": []})
            # Resolve a thumbnail URL for the first media item so the
            # calendar chip and preview modal can show the image.
            jd = p.job_data or {}
            sched_media = (jd.get("media") or [])
            sched_img = None
            if sched_media:
                m0 = sched_media[0]
                fid = m0.get("local_file_id") or m0.get("cache_file_id")
                if fid:
                    sched_img = f"/api/uploads/{fid}"
            days[day]["scheduled"].append({
                "id": p.id,
                "caption": (p.caption or "")[:140],
                "time": p.scheduled_time.isoformat(),
                "platform": p.platform,
                "media_type": p.media_type,
                "image": sched_img,
            })
    for p in published:
        # Normalise FB-feed vs IG-media shapes into one entry.
        if is_instagram:
            ct = p.get("timestamp", "")
            entry = {
                "id": p.get("id"),
                "message": (p.get("caption") or "")[:140],
                "created_time": ct,
                "image": p.get("thumbnail_url") or p.get("media_url"),
                "permalink": p.get("permalink"),
                "platform": "instagram",
            }
        else:
            ct = p.get("created_time", "")
            entry = {
                "id": p.get("id"),
                "message": (p.get("message") or p.get("story", ""))[:140],
                "created_time": ct,
                "image": p.get("full_picture"),
                "permalink": p.get("permalink_url"),
                "platform": "facebook",
            }
        if ct:
            try:
                dt = datetime.fromisoformat(ct.replace("Z", "+00:00"))
                if dt < month_start or dt > month_end:
                    continue
                day = str(dt.day)
                days.setdefault(day, {"scheduled": [], "published": []})
                days[day]["published"].append(entry)
            except Exception:
                pass

    # For Facebook pages, also fetch Meta-native scheduled posts (they don't
    # appear in /feed until they publish, so they'd otherwise be invisible).
    if not is_instagram and page_token:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                sched_fb_r = await client.get(
                    f"{settings.meta_graph_base_url}/{page_id}/scheduled_posts",
                    params={
                        "fields": "id,message,scheduled_publish_time,full_picture",
                        "limit": 100,
                        "access_token": page_token,
                    },
                )
            if sched_fb_r.status_code == 200:
                for sp in sched_fb_r.json().get("data", []):
                    spt = sp.get("scheduled_publish_time")
                    if not spt:
                        continue
                    try:
                        dt = datetime.fromisoformat(spt.replace("Z", "+00:00"))
                        if dt < month_start or dt > month_end:
                            continue
                        day = str(dt.day)
                        days.setdefault(day, {"scheduled": [], "published": []})
                        days[day]["scheduled"].append({
                            "id": sp.get("id"),
                            "caption": (sp.get("message") or "")[:140],
                            "time": dt.isoformat(),
                            "platform": "facebook",
                            "media_type": "IMAGE",
                            "image": sp.get("full_picture"),
                        })
                    except Exception:
                        pass
        except Exception:
            pass

    return {"year": year, "month": month, "days": days}


@app.get("/api/posting/feed")
async def api_posting_feed(
    page_id: str,
    limit: int = 20,
    platform: str = "facebook",
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """Published posts feed for a Facebook Page or Instagram account.

    Returns a normalised list of ``{message, created_time, full_picture,
    permalink_url, platform}`` entries so the frontend can render FB and IG
    feeds with the same card markup.
    """
    token = await get_posting_token(request, db)

    if platform == "instagram":
        # IG media is read with the owning Page's token — resolve it first.
        page_token = token
        try:
            cache_key = get_session(request).get("posting_user_id") or hashlib.sha256(token.encode()).hexdigest()[:16]
            pages_res = await _get_pages_cached(token, cache_key)
            if pages_res.get("success"):
                raw = pages_res["data"]
                for pg in (raw["data"] if isinstance(raw, dict) else raw):
                    iba = pg.get("instagram_business_account") or {}
                    if iba.get("id") == page_id:
                        page_token = pg.get("access_token", token)
                        break
        except Exception:
            pass
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(
                f"{settings.meta_graph_base_url}/{page_id}/media",
                params={
                    "fields": "id,caption,media_type,media_url,thumbnail_url,permalink,timestamp",
                    "limit": min(limit, 50),
                    "access_token": page_token,
                },
            )
        if r.status_code != 200:
            err = r.json().get("error", {}).get("message", "Failed to load Instagram feed")
            raise HTTPException(502, err)
        return [
            {
                "id": p.get("id"),
                "message": p.get("caption") or "",
                "created_time": p.get("timestamp", ""),
                "full_picture": p.get("thumbnail_url") or p.get("media_url"),
                "permalink_url": p.get("permalink"),
                "platform": "instagram",
            }
            for p in r.json().get("data", [])
        ]

    async with httpx.AsyncClient(timeout=15) as client:
        page_r = await client.get(
            f"{settings.meta_graph_base_url}/{page_id}",
            params={"fields": "access_token", "access_token": token},
        )
    page_token = page_r.json().get("access_token", token) if page_r.status_code == 200 else token
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            f"{settings.meta_graph_base_url}/{page_id}/feed",
            params={
                "fields": "id,message,created_time,story,full_picture,permalink_url",
                "limit": min(limit, 50),
                "access_token": page_token,
            },
        )
    if r.status_code != 200:
        err = r.json().get("error", {}).get("message", "Failed to load feed")
        raise HTTPException(502, err)
    return [{**p, "platform": "facebook"} for p in r.json().get("data", [])]


# ── Scheduled posts ────────────────────────────────────────────────────────────

@app.get("/api/scheduled-posts")
async def api_scheduled_posts(request: Request, client_id: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    query = select(ScheduledPost).where(ScheduledPost.status == "pending")
    if client_id:
        query = query.where(ScheduledPost.client_id == client_id)
    query = query.order_by(ScheduledPost.scheduled_time)
    result = await db.execute(query)
    posts = result.scalars().all()
    return [
        {
            "id": p.id, "platform": p.platform, "page_id": p.page_id,
            "caption": p.caption, "media_type": p.media_type,
            "scheduled_time": p.scheduled_time.isoformat() if p.scheduled_time else None,
            "timezone": p.timezone, "status": p.status,
        }
        for p in posts
    ]


@app.delete("/api/posting/facebook-scheduled/{meta_post_id:path}")
async def api_cancel_meta_fb_scheduled(
    meta_post_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Cancel a Meta-native Facebook scheduled post (not tracked in our DB).

    Posts scheduled natively via Meta Business Suite appear on the calendar
    with string IDs like "123456789_987654321". They can't be cancelled via
    our DB endpoint (which expects integer IDs), so this routes directly to
    the Meta Graph API delete call.
    """
    token = await get_posting_token(request, db)
    page_id = meta_post_id.split("_")[0]
    try:
        page_token = await _get_page_token(token, page_id)
    except Exception:
        page_token = token
    res = await meta_api.delete_scheduled_post(page_token, meta_post_id)
    if not res.get("success"):
        raise HTTPException(502, f"Meta refused the cancel: {res.get('error', 'unknown error')}")
    return {"success": True}


@app.delete("/api/posting/published/{post_id}")
async def api_delete_published_post(
    post_id: str,
    request: Request,
    platform: str = "facebook",
    db: AsyncSession = Depends(get_db),
):
    """Delete a published Facebook page post from Meta.

    Instagram is rejected up front: the IG Graph API has no delete operation
    for published media — it can only be removed in the Instagram app itself.
    """
    if platform == "instagram":
        raise HTTPException(
            400,
            "Instagram doesn't allow apps to delete published posts — open the post "
            "on Instagram and delete it there.",
        )
    token = await get_posting_token(request, db)
    # FB post ids are "<page_id>_<post_id>" — deleting requires the page token.
    page_id = post_id.split("_")[0]
    page_token = await _get_page_token(token, page_id)
    res = await meta_api.delete_scheduled_post(page_token, post_id)
    if not res.get("success"):
        raise HTTPException(502, f"Meta refused the delete: {res.get('error', 'unknown error')}")
    return {"success": True}


@app.delete("/api/scheduled-posts/{post_id}")
async def api_cancel_scheduled_post(post_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScheduledPost).where(ScheduledPost.id == post_id))
    post = result.scalar_one_or_none()
    if not post:
        raise HTTPException(404, "Scheduled post not found")
    if post.meta_post_id and post.status != "published":
        token = await get_meta_token(request, db)
        await meta_api.delete_scheduled_post(token, post.meta_post_id)
    # Atomic guard: only cancel posts the worker hasn't claimed. Without the
    # status filter a cancel during a multi-minute video publish was silently
    # overwritten by the worker's final commit — the "cancelled" post published.
    res = await db.execute(
        update(ScheduledPost)
        .where(ScheduledPost.id == post_id, ScheduledPost.status.in_(("pending", "failed")))
        .values(status="cancelled", next_retry_at=None)
    )
    await db.commit()
    if res.rowcount != 1:
        raise HTTPException(
            409,
            "This post is publishing right now (or already finished) and can no longer be cancelled.",
        )
    _sess_c = get_session(request)
    await log_posting_event(db, "cancel", f"Scheduled post #{post_id} cancelled",
        level="info", platform=post.platform or "",
        page_id=post.page_id or post.instagram_id or "",
        username=_sess_c.get("posting_username") or _sess_c.get("username") or "",
        user_id=_sess_c.get("user_id"), post_id=post_id)
    return {"success": True}


@app.get("/api/admin/scheduled-posts/summary")
async def api_admin_scheduled_summary(request: Request, db: AsyncSession = Depends(get_db)):
    """Count app-tracked scheduled posts by status, plus a list of the active
    (cancellable) ones — admin only. Used by the 'start fresh' cleanup tool."""
    await require_admin(request, db)
    counts_res = await db.execute(
        select(ScheduledPost.status, func.count())
        .group_by(ScheduledPost.status)
    )
    counts = {row[0]: row[1] for row in counts_res.all()}
    active_res = await db.execute(
        select(ScheduledPost)
        .where(ScheduledPost.status.in_(("pending", "failed")))
        .order_by(ScheduledPost.scheduled_time)
    )
    active = [
        {
            "id": p.id,
            "platform": p.platform,
            "status": p.status,
            "scheduled_time": p.scheduled_time.isoformat() if p.scheduled_time else None,
            "caption": (p.caption or "")[:80],
        }
        for p in active_res.scalars().all()
    ]
    return {"counts": counts, "active": active, "active_count": len(active)}


@app.post("/api/admin/scheduled-posts/cancel-all")
async def api_admin_cancel_all_scheduled(request: Request, db: AsyncSession = Depends(get_db)):
    """Cancel every app-tracked pending/failed scheduled post — admin only.

    A 'start fresh' tool to clear out the self-scheduled (Instagram / Drive-job)
    queue. Uses the same atomic guard as the single cancel: only rows still in
    ``pending``/``failed`` are flipped to ``cancelled``, so a post the worker is
    publishing right now (``processing``) is never touched. Already-published
    posts are never affected — this only stops things from firing in the future.
    """
    await require_admin(request, db)
    res = await db.execute(
        update(ScheduledPost)
        .where(ScheduledPost.status.in_(("pending", "failed")))
        .values(status="cancelled", next_retry_at=None)
    )
    await db.commit()
    cancelled = res.rowcount or 0
    _sess_c = get_session(request)
    await log_posting_event(
        db, "cancel", f"Bulk-cancelled {cancelled} pending scheduled post(s) (start fresh)",
        level="info",
        username=_sess_c.get("posting_username") or _sess_c.get("username") or "",
        user_id=_sess_c.get("user_id"))
    return {"success": True, "cancelled": cancelled}


@app.get("/api/posting/token-health")
async def api_posting_token_health(request: Request, db: AsyncSession = Depends(get_db)):
    """Expiry status of every active posting account token, worst first."""
    result = await db.execute(
        select(ConnectedPostingAccount).where(ConnectedPostingAccount.is_active == True)
    )
    now = datetime.now(timezone.utc)
    out = []
    for acc in result.scalars().all():
        days_left = None
        status = "unknown"
        if acc.token_expiry:
            expiry = acc.token_expiry if acc.token_expiry.tzinfo else acc.token_expiry.replace(tzinfo=timezone.utc)
            days_left = (expiry - now).days
            status = "expired" if days_left < 0 else "warning" if days_left <= 7 else "ok"
        out.append({
            "id": acc.id,
            "name": acc.user_name or acc.facebook_user_id,
            "days_left": days_left,
            "status": status,
        })
    rank = {"expired": 0, "warning": 1, "unknown": 2, "ok": 3}
    out.sort(key=lambda a: rank.get(a["status"], 3))
    return {"accounts": out}


@app.get("/api/posting/notifications")
async def api_posting_notifications(request: Request, db: AsyncSession = Depends(get_db)):
    """Failed scheduled posts from the last 14 days for the CURRENT posting
    account only — you don't get notified about posts placed by someone
    else's account. Each entry says whether its posting account is still
    connected, so the UI can route to reconnect instead of a doomed retry."""
    session = get_session(request)
    my_uid = session.get("posting_user_id")
    since = datetime.now(timezone.utc) - timedelta(days=14)
    result = await db.execute(
        select(ScheduledPost)
        .where(
            ScheduledPost.status == "failed",
            ScheduledPost.scheduled_time >= since,
        )
        .order_by(ScheduledPost.scheduled_time.desc())
        .limit(200)
    )
    posts = result.scalars().all()

    # Active posting accounts, for connectivity + display names.
    acc_result = await db.execute(
        select(ConnectedPostingAccount).where(ConnectedPostingAccount.is_active == True)
    )
    active = {a.facebook_user_id: (a.user_name or a.facebook_user_id) for a in acc_result.scalars().all()}

    failed = []
    for p in posts:
        owner_uid = (p.job_data or {}).get("posting_user_id")
        # Scope: this user's account placed it — or it's a legacy row with no
        # owner recorded (show those to everyone rather than no one).
        if owner_uid and my_uid and owner_uid != my_uid:
            continue
        # Generate a thumbnail URL for image posts (same logic as api_my_queue).
        jd = p.job_data or {}
        media = jd.get("media", [])
        thumb = None
        if media:
            m0 = media[0]
            _mime = m0.get("mime_type") or ""
            if (not _mime or _mime.startswith("image/")) and (
                m0.get("local_file_id") or m0.get("cache_file_id") or m0.get("drive_file_id")
            ):
                thumb = f"/api/posting/my-queue/{p.id}/thumb"
        failed.append({
            "id": p.id,
            "platform": p.platform,
            "page_id": p.page_id,
            "instagram_id": p.instagram_id,
            "caption": (p.caption or "")[:200],
            "media_type": p.media_type,
            "thumbnail": thumb,
            "scheduled_time": p.scheduled_time.isoformat() if p.scheduled_time else None,
            "error": (p.error_message or "")[:300],
            "attempts": p.attempts,
            "account_uid": owner_uid,
            "account_name": active.get(owner_uid) if owner_uid else None,
            "account_connected": (owner_uid in active) if owner_uid else bool(active),
        })
        if len(failed) >= 50:
            break
    return {"failed": failed}


@app.post("/api/scheduled-posts/{post_id}/retry")
async def api_retry_scheduled_post(post_id: int, db: AsyncSession = Depends(get_db)):
    """Re-queue a failed scheduled post for immediate publish."""
    result = await db.execute(select(ScheduledPost).where(ScheduledPost.id == post_id))
    post = result.scalar_one_or_none()
    if not post:
        raise HTTPException(404, "Scheduled post not found")
    if post.status not in ("failed", "cancelled"):
        raise HTTPException(400, f"Post is {post.status} — only failed or cancelled posts can be retried")
    # If the account that placed this post is disconnected, refuse: retrying
    # would silently publish via a DIFFERENT account (the worker's fallback).
    owner_uid = (post.job_data or {}).get("posting_user_id")
    if owner_uid:
        acc_result = await db.execute(
            select(ConnectedPostingAccount).where(
                ConnectedPostingAccount.facebook_user_id == owner_uid,
                ConnectedPostingAccount.is_active == True,
            )
        )
        if not acc_result.scalar_one_or_none():
            raise HTTPException(
                409,
                "The Facebook account that placed this post is logged out — "
                "reconnect that account first, then retry.",
            )
    post.status = "pending"
    post.attempts = 0
    post.error_message = None
    post.claimed_by = None
    post.claimed_at = None
    post.next_retry_at = None
    # Publish on the next worker pass instead of waiting for the original
    # (now past) scheduled time.
    if post.scheduled_time and post.scheduled_time.replace(tzinfo=post.scheduled_time.tzinfo or timezone.utc) > datetime.now(timezone.utc):
        pass  # still in the future — keep the original slot
    else:
        post.scheduled_time = datetime.now(timezone.utc)
    await db.commit()
    return {"success": True, "message": "Post re-queued — it will publish within a minute."}


# ── System health & checkpoint ─────────────────────────────────────────────────

@app.get("/api/system/health")
async def api_system_health(request: Request, db: AsyncSession = Depends(get_db)):
    """Return overall system health: pending posts, API status, token status."""
    now = datetime.now(timezone.utc)

    # Pending scheduled posts count
    pending_result = await db.execute(
        select(func.count()).select_from(ScheduledPost).where(
            ScheduledPost.status == "pending",
            ScheduledPost.job_data.isnot(None),
        )
    )
    pending_count: int = pending_result.scalar() or 0

    # Processing posts (claimed by a worker right now)
    processing_result = await db.execute(
        select(func.count()).select_from(ScheduledPost).where(
            ScheduledPost.status == "processing",
        )
    )
    processing_count: int = processing_result.scalar() or 0

    # Failed posts in last 24h
    failed_result = await db.execute(
        select(func.count()).select_from(ScheduledPost).where(
            ScheduledPost.status == "failed",
            ScheduledPost.scheduled_time >= now - timedelta(hours=24),
        )
    )
    failed_24h: int = failed_result.scalar() or 0

    # Next due post
    next_result = await db.execute(
        select(ScheduledPost.scheduled_time).where(
            ScheduledPost.status == "pending",
            ScheduledPost.job_data.isnot(None),
        ).order_by(ScheduledPost.scheduled_time).limit(1)
    )
    next_due = next_result.scalar_one_or_none()

    # Token health summary
    token_result = await db.execute(
        select(ConnectedPostingAccount).where(ConnectedPostingAccount.is_active == True)
    )
    posting_accounts = token_result.scalars().all()
    expired_tokens = []
    warning_tokens = []
    for acc in posting_accounts:
        if acc.token_expiry:
            expiry = acc.token_expiry if acc.token_expiry.tzinfo else acc.token_expiry.replace(tzinfo=timezone.utc)
            days = (expiry - now).days
            if days < 0:
                expired_tokens.append(acc.user_name or acc.facebook_user_id)
            elif days <= 7:
                warning_tokens.append(acc.user_name or acc.facebook_user_id)

    # Overdue: pending posts whose due time passed >15 min ago and that are not
    # waiting on a retry back-off — these should have published already.
    overdue_result = await db.execute(
        select(func.count()).select_from(ScheduledPost).where(
            ScheduledPost.status == "pending",
            ScheduledPost.job_data.isnot(None),
            ScheduledPost.scheduled_time < now - timedelta(minutes=15),
            or_(
                ScheduledPost.next_retry_at.is_(None),
                ScheduledPost.next_retry_at < now - timedelta(minutes=15),
            ),
        )
    )
    overdue_count: int = overdue_result.scalar() or 0

    # Stuck: claimed by a worker >15 min ago and never finished (worker died).
    stuck_result = await db.execute(
        select(func.count()).select_from(ScheduledPost).where(
            ScheduledPost.status == "processing",
            ScheduledPost.claimed_at < now - timedelta(minutes=15),
        )
    )
    stuck_count: int = stuck_result.scalar() or 0

    issues = []
    if expired_tokens:
        issues.append(f"Expired tokens: {', '.join(expired_tokens)} — reconnect to publish scheduled posts")
    if warning_tokens:
        issues.append(f"Tokens expiring soon: {', '.join(warning_tokens)}")
    if failed_24h > 0:
        issues.append(f"{failed_24h} post(s) failed in the last 24 hours — check Notifications")
    if overdue_count > 0:
        issues.append(
            f"{overdue_count} scheduled post(s) are overdue — the scheduler may have been "
            "offline; they will publish on the next pass. If this persists, check the server."
        )
    if stuck_count > 0:
        issues.append(
            f"{stuck_count} post(s) stuck mid-publish — they will be retried automatically "
            "after the server restarts."
        )
    using_sqlite = settings.DATABASE_URL.startswith("sqlite")
    has_checkpoint_file = bool((settings.CHECKPOINT_FILE or "").strip())
    has_custom_uploads = settings.UPLOADS_DIR not in ("uploads", "./uploads", "uploads/")

    if pending_count > 0 and using_sqlite and not has_checkpoint_file:
        issues.append(
            "⚠️ DURABILITY RISK: Scheduled posts are stored in a temporary SQLite database "
            "that is wiped on every server redeploy. "
            "Fix option A (easiest): set CHECKPOINT_FILE=/data/checkpoint.json and "
            "UPLOADS_DIR=/data/uploads on a persistent disk — posts will survive redeploys. "
            "Fix option B (recommended): set DATABASE_URL to a PostgreSQL connection string "
            "(free tier available on Supabase or Render)."
        )
    elif pending_count > 0 and using_sqlite and has_checkpoint_file:
        issues.append(
            "Using SQLite with file checkpoint. Posts survive redeploys as long as "
            f"CHECKPOINT_FILE ({settings.CHECKPOINT_FILE}) is on a persistent disk. "
            "For full durability, migrate to PostgreSQL."
        )

    return {
        "pending_scheduled": pending_count,
        "processing_now": processing_count,
        "failed_last_24h": failed_24h,
        "overdue": overdue_count,
        "stuck_processing": stuck_count,
        "next_due_at": next_due.isoformat() if next_due else None,
        "issues": issues,
        "status": "degraded" if (expired_tokens or failed_24h > 0 or overdue_count or stuck_count) else "ok",
        "durability": {
            "database": "postgresql" if not using_sqlite else "sqlite",
            "checkpoint_file": settings.CHECKPOINT_FILE or None,
            "uploads_dir": settings.UPLOADS_DIR,
            "persistent_uploads": has_custom_uploads,
            "drive_cache_mb": round(
                sum(
                    f.stat().st_size
                    for f in _UPLOAD_DIR.glob("drivecache_*")
                    if not f.name.endswith(".part")
                ) / 1024 / 1024,
                1,
            ),
            "drive_cache_limit_mb": _DRIVE_CACHE_TOTAL_MAX_BYTES // (1024 * 1024),
        },
    }


@app.get("/api/system/scheduled-checkpoint")
async def api_scheduled_checkpoint(request: Request, db: AsyncSession = Depends(get_db)):
    """Return the most recent pending-posts checkpoint (admin only)."""
    session = get_session(request)
    if session.get("user_role") != "admin":
        raise HTTPException(403, "Admin only")
    from database import AppSetting
    row = await db.get(AppSetting, _CHECKPOINT_KEY)
    if not row:
        return {"checkpoint": None}
    try:
        return {"checkpoint": json.loads(row.value)}
    except Exception:
        return {"checkpoint": row.value}


# ── API usage stats ────────────────────────────────────────────────────────────

@app.get("/api/api-usage")
async def api_usage(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    uid = session.get("meta_user_id", "")
    count = api_tracker.get_call_count(uid)
    remaining = max(0, 200 - count)
    paused = api_tracker.is_account_paused(uid)
    return {
        "calls_used": count,
        "calls_limit": 200,
        "calls_remaining": remaining,
        "is_paused": paused,
    }


@app.get("/api/ai-usage")
async def api_ai_usage(request: Request, db: AsyncSession = Depends(get_db)):
    """Return AI token usage: session totals (in-memory) + all-time DB total."""
    from claude_agent import _ai_session_tokens
    from sqlalchemy import func as sqlfunc

    session = get_session(request)
    uid = session.get("meta_user_id", "anon")

    sess = _ai_session_tokens.get(uid, {})

    # All-time total from DB (sum of tokens_used on assistant messages)
    result = await db.execute(
        select(sqlfunc.sum(Message.tokens_used)).where(Message.role == "assistant")
    )
    alltime_total: int = result.scalar() or 0

    return {
        "session_input":   sess.get("input", 0),
        "session_output":  sess.get("output", 0),
        "session_total":   sess.get("input", 0) + sess.get("output", 0),
        "session_calls":   sess.get("calls", 0),
        "provider":        sess.get("provider", agent._provider),
        "model":           sess.get("model", agent.model),
        "alltime_total":   alltime_total,
    }


@app.get("/api/ai-usage/log")
async def api_ai_usage_log(request: Request, lines: int = 100):
    """Return the last N lines of the AI diagnostic log as plain text."""
    from pathlib import Path as _Path
    session = get_session(request)
    if not session.get("user_id") and not session.get("meta_user_id"):
        raise HTTPException(401, "Not authenticated")
    log_file = _Path("logs/ai_usage.log")
    if not log_file.exists():
        return {"log": "", "count": 0}
    all_lines = log_file.read_text(encoding="utf-8").splitlines()
    tail = all_lines[-lines:] if len(all_lines) > lines else all_lines
    return {"log": "\n".join(tail), "count": len(tail), "total": len(all_lines)}


# ── AI provider switcher ───────────────────────────────────────────────────────

class SwitchProviderRequest(BaseModel):
    provider: str           # "claude", "openai", or "groq"
    model: Optional[str] = None  # specific model version (optional)

@app.post("/api/ai-provider/switch")
async def switch_ai_provider(req: SwitchProviderRequest, request: Request):
    valid = {"claude", "openai", "groq"}
    if req.provider not in valid:
        raise HTTPException(400, f"provider must be one of {valid}")

    key_available = {
        "claude": bool(settings.ANTHROPIC_API_KEY),
        "openai": bool(settings.OPENAI_API_KEY),
        "groq":   bool(settings.GROQ_API_KEY),
    }.get(req.provider, False)
    if not key_available:
        raise HTTPException(400, f"No API key configured for {req.provider} — add the key in Settings first")

    env_path = Path(".env")
    lines: list[str] = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    def _set_env(key: str, val: str) -> None:
        for i, line in enumerate(lines):
            if line.startswith(f"{key}=") or line.startswith(f"{key} ="):
                lines[i] = f"{key}={val}"; return
        lines.append(f"{key}={val}")

    _set_env("AI_PROVIDER", req.provider)

    # Persist and hot-apply model if supplied
    if req.model:
        model_key = {"claude": "CLAUDE_MODEL", "openai": "OPENAI_MODEL", "groq": "GROQ_MODEL"}[req.provider]
        _set_env(model_key, req.model)
        if req.provider == "claude":
            settings.CLAUDE_MODEL = req.model
        elif req.provider == "openai":
            settings.OPENAI_MODEL = req.model
        elif req.provider == "groq":
            settings.GROQ_MODEL = req.model

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    settings.AI_PROVIDER = req.provider
    agent._init_client()
    logger.info("Switched AI provider to %s model=%s", req.provider, agent.model)
    return {"success": True, "provider": req.provider, "model": agent.model}

@app.get("/api/update/check")
async def update_check(response: Response):
    """Compare local version.txt with the latest on GitHub main."""
    # Never let browsers or proxies cache this — always fresh
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"

    local_version = "unknown"
    version_file = Path("version.txt")
    if version_file.exists():
        local_version = version_file.read_text(encoding="utf-8").strip()

    latest_version = None
    fetch_error = None
    import time as _time
    cache_bust = int(_time.time())
    urls_tried = [
        f"https://raw.githubusercontent.com/uplinxmarketing/final-app/main/version.txt?t={cache_bust}",
        "https://api.github.com/repos/uplinxmarketing/final-app/contents/version.txt",
    ]
    for url in urls_tried:
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                headers = {"Cache-Control": "no-cache"}
                if "api.github.com" in url:
                    headers["Accept"] = "application/vnd.github.raw+json"
                r = await client.get(url, headers=headers)
            logger.info("Update check %s -> status %d body=%r", url, r.status_code, r.text[:80])
            if r.status_code == 200:
                text = r.text.strip()
                if text.startswith("{"):
                    import base64, json as _json
                    content = _json.loads(text).get("content", "")
                    text = base64.b64decode(content).decode().strip()
                latest_version = text
                fetch_error = None
                break
            else:
                fetch_error = f"HTTP {r.status_code} from {url}"
        except Exception as exc:
            fetch_error = str(exc)
            logger.warning("Update check fetch failed (%s): %s", url, exc)

    has_update = bool(latest_version and latest_version != local_version)
    logger.info("Update check result: local=%r github=%r has_update=%s", local_version, latest_version, has_update)
    return {
        "current_version": local_version,
        "latest_version": latest_version or "unavailable",
        "has_update": has_update,
        "fetch_error": fetch_error,
    }


@app.post("/api/update/apply")
async def update_apply():
    """Download latest ZIP from GitHub, apply files, preserve .env and database."""
    import shutil
    import tempfile
    import zipfile

    zip_url = "https://github.com/uplinxmarketing/final-app/archive/refs/heads/main.zip"
    preserve = {".env", "uplinx.db", "user_settings.json", "venv", "uploads",
                "logs", "skills", "_update_dir", "_update_tmp.zip"}

    try:
        # 1. Download
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            r = await client.get(zip_url)
        r.raise_for_status()

        # 2. Extract to temp dir
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "update.zip"
            zip_path.write_bytes(r.content)

            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(tmp)

            # GitHub zips contain a single top-level folder like "final-app-main"
            extracted = [p for p in Path(tmp).iterdir() if p.is_dir()]
            if not extracted:
                raise RuntimeError("ZIP contained no top-level folder")
            src = extracted[0]

            # 3. Copy files, skipping preserved ones
            app_root = Path(".")
            for item in src.iterdir():
                if item.name in preserve:
                    continue
                dest = app_root / item.name
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)

        return {
            "success": True,
            "message": "Update applied. Please restart the app — close this window and run start.bat again.",
        }
    except Exception as exc:
        logger.error("Update failed: %s", exc, exc_info=True)
        raise HTTPException(500, f"Update failed: {exc}")


@app.get("/api/ai-provider/current")
async def current_ai_provider(request: Request):
    available = {
        "claude": bool(settings.ANTHROPIC_API_KEY),
        "openai": bool(settings.OPENAI_API_KEY),
        "groq":   bool(settings.GROQ_API_KEY),
    }
    return {
        "provider": agent._provider,   # "none" when no keys configured
        "model": agent.model,
        "available": available,
        "models": {
            "claude": ["claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
            "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1"],
            "groq": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"],
        },
    }
