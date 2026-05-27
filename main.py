"""
Uplinx Meta Manager — FastAPI application.
All routes, OAuth flows, session management, and API endpoints.
"""
import asyncio
import json
import logging
import hashlib
import secrets
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import httpx

from fastapi import FastAPI, Request, Response, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select, delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
from database import (
    init_db, get_db,
    ConnectedMetaAccount, ConnectedGoogleAccount, ConnectedPostingAccount,
    Client, ClientAdAccount, ClientInstagramAccount,
    Conversation, Message, ActiveContext,
    Skill, QuickCommand, ScheduledPost, ImageCache
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
from file_processor import process_uploaded_file, cleanup_old_uploads
from skills_manager import (
    initialize_default_skills, initialize_default_quick_commands,
    get_all_skills, create_skill, update_skill,
    toggle_skill, delete_skill, get_quick_commands, create_quick_command
)
from claude_agent import ClaudeAgent, invalidate_account_cache, invalidate_system_prompt, _system_prompt_cache
from rate_limiter import api_tracker

logger = setup_logging()
encryption = FernetEncryption()
agent = ClaudeAgent()

# ── Lifespan ──────────────────────────────────────────────────────────────────

_bg_tasks: list[asyncio.Task] = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    async for db in get_db():
        await initialize_default_skills(db)
        await initialize_default_quick_commands(db)
        break
    _bg_tasks.append(asyncio.create_task(_cleanup_uploads_loop()))
    _bg_tasks.append(asyncio.create_task(_token_refresh_loop()))
    logger.info("Uplinx Meta Manager started")
    yield
    for task in _bg_tasks:
        task.cancel()
    logger.info("Uplinx Meta Manager stopped")

async def _cleanup_uploads_loop() -> None:
    while True:
        await asyncio.sleep(3600)
        try:
            count = await cleanup_old_uploads(settings.AUTO_CLEAR_UPLOADS_HOURS)
            if count:
                logger.info("Auto-cleaned %d upload(s)", count)
        except Exception as exc:
            logger.warning("Upload cleanup error: %s", exc)

async def _token_refresh_loop() -> None:
    """Check for Meta tokens expiring within 7 days and attempt refresh."""
    while True:
        await asyncio.sleep(3600)
        try:
            async for db in get_db():
                threshold = datetime.utcnow() + timedelta(days=7)
                result = await db.execute(
                    select(ConnectedMetaAccount).where(
                        ConnectedMetaAccount.is_active == True,
                        ConnectedMetaAccount.token_expiry <= threshold,
                    )
                )
                accounts = result.scalars().all()
                for acc in accounts:
                    token = encryption.decrypt(acc.encrypted_long_token)
                    refresh = await meta_api.exchange_for_long_lived_token(
                        token, settings.META_APP_ID, settings.META_APP_SECRET
                    )
                    if refresh.get("success") and refresh.get("data", {}).get("access_token"):
                        new_token = refresh["data"]["access_token"]
                        acc.encrypted_long_token = encryption.encrypt(new_token)
                        expiry_days = refresh["data"].get("expires_in", 5184000) // 86400
                        acc.token_expiry = datetime.utcnow() + timedelta(days=expiry_days)
                        await db.commit()
                        logger.info("Refreshed token for %s", acc.facebook_user_id)
        except Exception as exc:
            logger.warning("Token refresh loop error: %s", exc)

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Uplinx Meta Manager", version="1.0.0", lifespan=lifespan)

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
PUBLIC_PATHS = {"/health", "/", "/auth/meta", "/auth/meta/callback",
                "/auth/meta/posting", "/auth/meta/posting/callback",
                "/auth/google", "/auth/google/callback", "/setup",
                "/api/accounts/meta/token", "/api/accounts/posting/token",
                "/login", "/api/login", "/api/logout"}


def _login_token() -> str:
    return hashlib.sha256(
        f"{settings.LOGIN_PASSWORD}:{settings.SECRET_KEY}".encode()
    ).hexdigest()

@app.middleware("http")
async def session_middleware(request: Request, call_next):
    if (request.url.path in PUBLIC_PATHS
            or request.url.path.startswith("/static")
            or request.url.path.startswith("/frontend")
            or request.url.path.startswith("/api/setup")):
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
    if not settings.LOGIN_PASSWORD:
        return await call_next(request)
    path = request.url.path
    if (path in {"/login", "/api/login", "/api/logout", "/health"}
            or path.startswith("/frontend/")
            or path.startswith("/static/")):
        return await call_next(request)
    token = request.cookies.get(LOGIN_COOKIE)
    expected = _login_token()
    if not token or not secrets.compare_digest(token, expected):
        if path.startswith("/api/"):
            return JSONResponse({"error": "Login required"}, status_code=403)
        return RedirectResponse("/login")
    return await call_next(request)


def get_session(request: Request) -> dict:
    return getattr(request.state, "session", {})


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
    if acc.token_expiry and acc.token_expiry < datetime.utcnow():
        raise HTTPException(401, "Meta token expired — please reconnect")
    acc.last_used_at = datetime.utcnow()
    await db.commit()
    return encryption.decrypt(acc.encrypted_long_token)


async def get_google_token(request: Request, db: AsyncSession) -> str:
    """Decrypt and return Google access token, refreshing if expired."""
    session = get_session(request)
    uid = session.get("google_user_id")
    if not uid:
        raise HTTPException(401, "Google account not connected")
    from database import ConnectedGoogleAccount
    result = await db.execute(
        select(ConnectedGoogleAccount).where(
            ConnectedGoogleAccount.google_user_id == uid,
            ConnectedGoogleAccount.is_active == True,
        )
    )
    acc = result.scalar_one_or_none()
    if not acc:
        raise HTTPException(401, "Google account not found")
    if acc.token_expiry and acc.token_expiry < datetime.utcnow():
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
    """Decrypt and return the active Posting Meta access token."""
    session = get_session(request)
    uid = session.get("posting_user_id")
    if not uid:
        raise HTTPException(401, "Posting account not connected")
    result = await db.execute(
        select(ConnectedPostingAccount).where(
            ConnectedPostingAccount.facebook_user_id == uid,
            ConnectedPostingAccount.is_active == True,
        )
    )
    acc = result.scalar_one_or_none()
    if not acc:
        raise HTTPException(401, "Posting account not found")
    if acc.token_expiry and acc.token_expiry < datetime.utcnow():
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

@app.post("/api/setup/save")
async def setup_save(req: SetupSaveRequest):
    """Write provided keys into the .env file and reload settings."""
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
async def clear_api_key(provider: str):
    """Remove a single AI provider key from .env and live settings."""
    env_key_map = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "groq": "GROQ_API_KEY"}
    env_key = env_key_map.get(provider)
    if not env_key:
        raise HTTPException(400, f"Unknown provider: {provider}")
    env_path = Path(".env")
    if env_path.exists():
        lines = [l for l in env_path.read_text(encoding="utf-8").splitlines()
                 if not (l.startswith(f"{env_key}=") or l.startswith(f"{env_key} ="))]
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
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
    body = await request.json()
    _save_user_settings(body)
    # Custom instructions are part of the system prompt — bust cache
    _system_prompt_cache.clear()
    return {"success": True}


@app.get("/api/setup/status")
async def setup_status():
    return {
        "complete": _is_setup_complete(),
        "ai_provider": settings.AI_PROVIDER,
        "has_meta": bool(settings.META_APP_ID),
        "has_posting_app": bool(settings.META_POSTING_APP_ID),
        "has_anthropic": bool(settings.ANTHROPIC_API_KEY),
        "has_openai": bool(settings.OPENAI_API_KEY),
        "has_groq": bool(settings.GROQ_API_KEY),
        "has_google": bool(settings.GOOGLE_CLIENT_ID),
    }

# ── Health & frontend ──────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


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


@app.get("/", response_class=HTMLResponse)
async def frontend(request: Request):
    html_path = Path("frontend/index.html")
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Uplinx Meta Manager</h1><p>Frontend not found.</p>")

# ── Meta OAuth ────────────────────────────────────────────────────────────────

META_SCOPES = ",".join([
    "ads_management", "ads_read", "pages_show_list",
    "pages_read_engagement", "pages_manage_ads", "pages_manage_posts",
    "read_insights", "instagram_basic", "instagram_content_publish",
    "instagram_manage_insights", "instagram_manage_contents",
    "publish_video", "business_management", "attribution_read",
])

@app.get("/auth/meta")
async def auth_meta(request: Request, response: Response):
    state = generate_oauth_state()
    response.set_cookie("oauth_state", state, max_age=600, httponly=True, samesite="lax")
    params = urllib.parse.urlencode({
        "client_id": settings.META_APP_ID,
        "redirect_uri": settings.META_REDIRECT_URI,
        "scope": META_SCOPES,
        "response_type": "code",
        "state": state,
    })
    return RedirectResponse(f"https://www.facebook.com/dialog/oauth?{params}", headers=response.headers)

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

    # Exchange code → short-lived token
    short = await meta_api.exchange_code_for_token(
        code, settings.META_APP_ID, settings.META_APP_SECRET, settings.META_REDIRECT_URI
    )
    if not short.get("success"):
        return RedirectResponse(f"/?error={urllib.parse.quote(short.get('error', 'token_exchange_failed'))}")

    short_token = short["data"].get("access_token", "")

    # Exchange → long-lived token
    long = await meta_api.exchange_for_long_lived_token(
        short_token, settings.META_APP_ID, settings.META_APP_SECRET
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
    if acc:
        acc.encrypted_short_token = encryption.encrypt(short_token)
        acc.encrypted_long_token = encryption.encrypt(long_token)
        acc.token_expiry = now + timedelta(seconds=expires_in)
        acc.user_name = name
        acc.user_email = email
        acc.is_active = True
        acc.last_used_at = now
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
        )
        db.add(acc)
    await db.commit()

    # Create signed session
    session_token = create_session_token({"meta_user_id": uid})
    redirect = RedirectResponse("/?connected=meta")
    redirect.set_cookie(
        SESSION_COOKIE, session_token,
        max_age=28800, httponly=True, samesite="lax"
    )
    redirect.delete_cookie("oauth_state")
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
    state = generate_oauth_state()
    response.set_cookie("oauth_state_google", state, max_age=600, httponly=True, samesite="lax")
    params = urllib.parse.urlencode({
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
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

    tokens = await google_api.exchange_code_for_tokens(
        code, settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET, settings.GOOGLE_REDIRECT_URI
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
    existing_session = verify_session_token(existing_token) if existing_token else {}
    existing_session["google_user_id"] = uid
    session_token = create_session_token(existing_session)
    redirect = RedirectResponse("/?connected=google")
    redirect.set_cookie(SESSION_COOKIE, session_token, max_age=28800, httponly=True, samesite="lax")
    redirect.delete_cookie("oauth_state_google")
    return redirect

@app.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"success": True}

# ── Shared request models ──────────────────────────────────────────────────────

class DirectTokenRequest(BaseModel):
    access_token: str

# ── Posting Account API routes ─────────────────────────────────────────────────

@app.get("/api/accounts/posting")
async def api_posting_accounts(request: Request, db: AsyncSession = Depends(get_db)):
    """List connected Posting app Meta accounts (no tokens exposed)."""
    session = get_session(request)
    result = await db.execute(
        select(ConnectedPostingAccount).where(ConnectedPostingAccount.is_active == True)
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
            "is_current": a.facebook_user_id == session.get("posting_user_id"),
        }
        for a in accounts
    ]


@app.delete("/api/accounts/posting/{account_id}")
async def api_disconnect_posting(account_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ConnectedPostingAccount).where(ConnectedPostingAccount.id == account_id))
    acc = result.scalar_one_or_none()
    if not acc:
        raise HTTPException(404, "Account not found")
    acc.is_active = False
    await db.commit()
    return {"success": True}


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

    if acc:
        acc.encrypted_short_token = encrypted
        acc.encrypted_long_token = encrypted
        acc.user_name = user_name
        acc.user_email = user_email
        acc.token_expiry = None
        acc.is_active = True
        acc.last_used_at = datetime.utcnow()
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


# ── Posting (Posts Manager) OAuth ─────────────────────────────────────────────

META_POSTING_SCOPES = ",".join([
    "pages_show_list", "pages_read_engagement", "pages_manage_posts",
    "instagram_basic", "instagram_content_publish",
    "instagram_manage_insights", "instagram_manage_contents",
    "publish_video",
])

@app.get("/auth/meta/posting")
async def auth_meta_posting(request: Request, response: Response):
    if not settings.META_POSTING_APP_ID:
        return RedirectResponse("/?error=posting_app_not_configured")
    state = generate_oauth_state()
    response.set_cookie("oauth_state_posting", state, max_age=600, httponly=True, samesite="lax")
    params = urllib.parse.urlencode({
        "client_id": settings.META_POSTING_APP_ID,
        "redirect_uri": settings.meta_posting_redirect_uri,
        "scope": META_POSTING_SCOPES,
        "response_type": "code",
        "state": state,
    })
    return RedirectResponse(f"https://www.facebook.com/dialog/oauth?{params}", headers=response.headers)


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

    short = await meta_api.exchange_code_for_token(
        code, settings.META_POSTING_APP_ID, settings.META_POSTING_APP_SECRET,
        settings.meta_posting_redirect_uri
    )
    if not short.get("success"):
        return RedirectResponse(f"/?error={urllib.parse.quote(short.get('error', 'token_exchange_failed'))}")

    short_token = short["data"].get("access_token", "")

    long = await meta_api.exchange_for_long_lived_token(
        short_token, settings.META_POSTING_APP_ID, settings.META_POSTING_APP_SECRET
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
    if acc:
        acc.encrypted_short_token = encryption.encrypt(short_token)
        acc.encrypted_long_token = encryption.encrypt(long_token)
        acc.token_expiry = now + timedelta(seconds=expires_in)
        acc.user_name = name
        acc.user_email = email
        acc.is_active = True
        acc.last_used_at = now
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
        )
        db.add(acc)
    await db.commit()

    # Merge into existing session so both ads + posting IDs coexist
    existing = get_session(request)
    session_data = {**dict(existing), "posting_user_id": uid}
    session_token = create_session_token(session_data)
    redirect = RedirectResponse("/?connected=posting")
    redirect.set_cookie(
        SESSION_COOKIE, session_token,
        max_age=28800, httponly=True, samesite="lax"
    )
    redirect.delete_cookie("oauth_state_posting")
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
        raise HTTPException(400, "No AI provider configured — add an API key in Settings first")

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

@app.post("/api/upload")
@limiter.limit("30/minute")
async def api_upload(request: Request, file: UploadFile = File(...)):
    session = get_session(request)
    session_key = session.get("meta_user_id", "anon")

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
    session_key = session.get("meta_user_id", "anon")
    return _session_uploads.get(session_key, [])


@app.delete("/api/uploads/{file_id}")
async def api_delete_upload(file_id: str, request: Request):
    session = get_session(request)
    session_key = session.get("meta_user_id", "anon")
    uploads = _session_uploads.get(session_key, [])
    path = None
    for u in uploads:
        if u["file_id"] == file_id:
            path = u["path"]
            break
    if path:
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

@app.get("/api/posting/pages")
async def api_posting_pages(request: Request, db: AsyncSession = Depends(get_db)):
    """Get FB pages accessible via the Posting app token."""
    token = await get_posting_token(request, db)
    result = await meta_api.get_pages(token)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    return result["data"]


@app.get("/api/posting/instagram")
async def api_posting_instagram(request: Request, db: AsyncSession = Depends(get_db)):
    """Get Instagram Business accounts accessible via the Posting app token."""
    token = await get_posting_token(request, db)
    result = await meta_api.get_pages(token)
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Meta API error"))
    pages = result["data"]
    ig_accounts = []
    async with httpx.AsyncClient(timeout=15) as client:
        for page in pages:
            r = await client.get(
                f"{settings.meta_graph_base_url}/{page['id']}",
                params={"fields": "instagram_business_account{id,name,username}", "access_token": token}
            )
            if r.status_code == 200:
                d = r.json()
                iba = d.get("instagram_business_account")
                if iba:
                    ig_accounts.append({
                        "id": iba["id"],
                        "name": iba.get("name", ""),
                        "username": iba.get("username", ""),
                        "page_id": page["id"],
                        "page_name": page.get("name", ""),
                    })
    return ig_accounts


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

    # Exchange user token for page-specific access token
    async with httpx.AsyncClient(timeout=15) as client:
        page_r = await client.get(
            f"{settings.meta_graph_base_url}/{req.page_id}",
            params={"fields": "access_token", "access_token": token},
        )
    if page_r.status_code != 200:
        raise HTTPException(502, "Could not retrieve page token — check page permissions")
    page_token = page_r.json().get("access_token", token)

    # Convert ISO datetime string → Unix timestamp for scheduled posts
    scheduled_ts: Optional[int] = None
    if req.scheduled_time:
        try:
            from datetime import timezone as _tz
            dt = datetime.fromisoformat(req.scheduled_time.replace("Z", "+00:00"))
            scheduled_ts = int(dt.timestamp())
        except Exception:
            raise HTTPException(400, "Invalid scheduled_time — use ISO 8601 format")

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
            r = await client.post(f"{base}/{req.page_id}/photos", data=payload)
        else:
            # Text / link post
            payload = {
                "message": req.caption,
                "access_token": page_token,
            }
            if scheduled_ts:
                payload["published"] = "false"
                payload["scheduled_publish_time"] = str(scheduled_ts)
            r = await client.post(f"{base}/{req.page_id}/feed", data=payload)

    if r.status_code not in (200, 201):
        err = r.json().get("error", {}).get("message", "Failed to publish to Facebook")
        raise HTTPException(502, err)
    data = r.json()
    return {"success": True, "post_id": data.get("id") or data.get("post_id")}


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

    if req.media_type == "REELS":
        container_data["media_type"] = "REELS"
        container_data["video_url"] = req.media_url
    elif req.media_type == "STORIES":
        container_data["media_type"] = "STORIES"
        container_data["image_url"] = req.media_url
    else:
        # Standard image post
        if req.media_url:
            container_data["image_url"] = req.media_url

    # Step 1 — create media container
    async with httpx.AsyncClient(timeout=30) as client:
        cr = await client.post(f"{base}/{req.instagram_id}/media", data=container_data)
    if cr.status_code not in (200, 201):
        err = cr.json().get("error", {}).get("message", "Failed to create Instagram media container")
        raise HTTPException(502, err)
    creation_id = cr.json().get("id")
    if not creation_id:
        raise HTTPException(502, "No creation_id returned from Instagram container step")

    # Step 2 — publish the container
    async with httpx.AsyncClient(timeout=30) as client:
        pr = await client.post(
            f"{base}/{req.instagram_id}/media_publish",
            data={"creation_id": creation_id, "access_token": token},
        )
    if pr.status_code not in (200, 201):
        err = pr.json().get("error", {}).get("message", "Failed to publish Instagram media")
        raise HTTPException(502, err)
    return {"success": True, "media_id": pr.json().get("id")}


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


@app.delete("/api/scheduled-posts/{post_id}")
async def api_cancel_scheduled_post(post_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScheduledPost).where(ScheduledPost.id == post_id))
    post = result.scalar_one_or_none()
    if not post:
        raise HTTPException(404, "Scheduled post not found")
    if post.meta_post_id:
        token = await get_meta_token(request, db)
        await meta_api.delete_scheduled_post(token, post.meta_post_id)
    post.status = "cancelled"
    await db.commit()
    return {"success": True}


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
        f"https://raw.githubusercontent.com/uplinxmarketing/ad-upload/main/version.txt?t={cache_bust}",
        "https://api.github.com/repos/uplinxmarketing/ad-upload/contents/version.txt",
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

    zip_url = "https://github.com/uplinxmarketing/ad-upload/archive/refs/heads/main.zip"
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

            # GitHub zips contain a single top-level folder like "ad-upload-main"
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
