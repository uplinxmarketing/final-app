"""
claude_agent.py — Claude AI agent integration for Uplinx Meta Manager.

Provides a streaming, tool-using Claude agent that orchestrates Meta advertising
operations via the MCP server tools.  Responses are streamed to the client as
SSE (Server-Sent Events).
"""

from __future__ import annotations

import asyncio
import json
import logging
import datetime
from typing import AsyncGenerator, Optional, Any

import time
from pathlib import Path
import anthropic
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

# ── Diagnostic log ─────────────────────────────────────────────────────────────
_LOG_DIR  = Path("logs")
_LOG_FILE = _LOG_DIR / "ai_usage.log"
_MAX_LOG_LINES = 500  # rotate after this many entries (keep last 500)


def _write_log_entry(entry: dict) -> None:
    """Append one JSONL line to the diagnostic log (non-blocking best-effort)."""
    try:
        _LOG_DIR.mkdir(exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False)
        # Rotate: keep last _MAX_LOG_LINES lines
        if _LOG_FILE.exists():
            existing = _LOG_FILE.read_text(encoding="utf-8").splitlines()
            if len(existing) >= _MAX_LOG_LINES:
                existing = existing[-(  _MAX_LOG_LINES - 1):]
                _LOG_FILE.write_text("\n".join(existing) + "\n" + line + "\n", encoding="utf-8")
                return
        with _LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass  # never crash the agent over logging

logger = logging.getLogger("uplinx")

# In-memory cache for Meta account/page lists keyed by meta_user_id.
# Avoids hitting the Graph API on every single chat message.
_account_cache: dict[str, dict] = {}
_ACCOUNT_CACHE_TTL = 600  # 10 minutes

# Cache for the fully-built system prompt, keyed by conversation_id.
# Rebuilt only when context or skills change; safe to keep for the length
# of a session because Anthropic's server-side prompt cache also lasts 5 min.
_system_prompt_cache: dict[int, str] = {}


def invalidate_system_prompt(conversation_id: int) -> None:
    """Call whenever the conversation context or skills change."""
    _system_prompt_cache.pop(conversation_id, None)


async def _get_cached_meta_accounts(uid: str, token: str) -> dict:
    """Return cached ad accounts + pages, refreshing only when stale."""
    import meta_api as _meta_api
    now = time.monotonic()
    entry = _account_cache.get(uid)
    if entry and now - entry["ts"] < _ACCOUNT_CACHE_TTL:
        return entry["data"]
    ad_result = await _meta_api.get_ad_accounts(token)
    page_result = await _meta_api.get_pages(token)
    data = {
        "ad_accounts": ad_result["data"].get("data", []) if ad_result.get("success") else [],
        "pages": page_result["data"].get("data", []) if page_result.get("success") else [],
    }
    _account_cache[uid] = {"data": data, "ts": now}
    return data


def invalidate_account_cache(uid: str) -> None:
    """Call this after the user explicitly refreshes assets."""
    _account_cache.pop(uid, None)


import re as _re
_META_WORD_RE = _re.compile(
    r'\b(ads?|campaign|adset|ad\s+set|ad\s+account|creative|pixel|facebook|instagram|'
    r'meta\s+ads?|impression|cpm|cpc|ctr|roas|budget|audience|targeting|placement|'
    r'schedule|reel|upload|analytics|report|spend|conversion|lead|traffic|awareness|'
    r'objective|pause\s+ad|activate\s+ad|create\s+ad|list\s+ad|ad\s+upload|'
    r'google\s+drive|drive\.google|drive\s+link|drive\s+folder|'
    r'google\s+doc|google\s+sheet|spreadsheet|docs\.google|sheets\.google|'
    r'drive\.google\.com|gdoc|gsheet)\b',
    _re.IGNORECASE,
)


def _is_meta_request(message: str) -> bool:
    """Return True when the message is likely asking for a Meta Ads action."""
    return bool(_META_WORD_RE.search(message))


# Tool groups used to send only the relevant subset of tools per message.
# Sending all ~24 tool schemas costs ~3 700 input tokens *per agentic turn*, and
# Groq/OpenAI have no prompt caching, so trimming this is the single biggest
# token saving for tool-using chats.
_TOOL_GROUPS = {
    "discovery": ["list_ad_accounts", "list_pages", "list_pixels"],
    "drive": [
        "read_google_doc", "read_google_sheet", "read_google_drive_folder",
        "read_pdf", "read_local_folder", "match_post_story_pairs",
        "upload_ads_from_drive", "search_drive", "prepare_upload_preview",
        "list_business_portfolios",
    ],
    "campaigns": [
        "create_campaign", "get_campaigns", "pause_campaign",
        "activate_campaign", "delete_campaign", "create_ad_set",
    ],
    "ads": ["upload_single_ad", "upload_multiple_ads"],
    "analytics": ["get_performance_report", "get_campaign_performance"],
    "posting": [
        "schedule_post", "schedule_reel", "get_scheduled_posts",
        "cancel_scheduled_post", "search_drive", "prepare_upload_preview",
        "list_business_portfolios",
    ],
}

_GROUP_PATTERNS = {
    "drive": _re.compile(r"\b(drive|google\s+doc|google\s+sheet|docs\.google|sheets\.google|spreadsheet|pdf|folder|file|document)\b", _re.IGNORECASE),
    "campaigns": _re.compile(r"\b(campaign|ad\s*set|adset|objective|budget|pause|activate|delete|create|targeting)\b", _re.IGNORECASE),
    "ads": _re.compile(r"\b(upload|creative|ad\s+image|new\s+ad|ads?\b)\b", _re.IGNORECASE),
    "analytics": _re.compile(r"\b(report|performance|analytics|spend|roas|cpm|cpc|ctr|impression|conversion|metrics?)\b", _re.IGNORECASE),
    "posting": _re.compile(r"\b(schedule|post|reel|publish|caption|portfolio|preview|instagram\s+post|facebook\s+post)\b", _re.IGNORECASE),
}


def _select_tool_names(message: str) -> set[str]:
    """Return the subset of tool names relevant to *message*.

    Discovery tools (list_*) are always included since the model often needs
    to resolve account/page IDs. Other groups are added only when the message
    matches their keyword pattern. If nothing matches we return an empty set so
    the caller can fall back to the full tool list.
    """
    selected: set[str] = set()
    for group, pattern in _GROUP_PATTERNS.items():
        if pattern.search(message):
            selected.update(_TOOL_GROUPS[group])
    if selected:
        selected.update(_TOOL_GROUPS["discovery"])
    return selected

# Lean prompt used when no accounts are connected (~30 tokens).
_LEAN_SYSTEM_PROMPT = (
    "You are Uplinx AI, a helpful assistant. "
    "Reply to every message clearly and concisely. "
    "Connect a Meta or Google account to unlock ad management and Drive tools."
)

# Full prompt used when Meta or Google IS connected.
BASE_SYSTEM_PROMPT = """You are Uplinx AI — a helpful assistant and expert Meta Ads manager.

You have tools available for these categories:
- **Meta Ads** (when Meta is connected): campaigns, ad sets, creatives, post scheduling, analytics
- **Google Drive** (when Google Drive is connected): upload_ads_from_drive, read_google_doc, read_google_sheet
- **File reading**: read_pdf, read_local_folder, match_post_story_pairs

IMPORTANT — GOOGLE DRIVE TOOLS:
When the user provides a Google Drive URL, Google Doc link, or Google Sheet link, you MUST \
call the appropriate tool (upload_ads_from_drive, read_google_doc, or read_google_sheet). \
Do NOT say you cannot access external files — you have tools specifically for this. \
Never respond with "I don't have access to Google Drive" when a Drive URL is provided.
When the user names a folder, file or document WITHOUT a link ("the June folder", "my captions \
sheet"), use search_drive to find it yourself instead of asking for the URL. \
When the user asks you to set up, prepare or load posts from Drive, call prepare_upload_preview \
— it fills the interactive upload preview in their chat (images, captions and schedule dates \
matched) so they only review and press Publish. Read the captions doc first if you need to \
verify how captions or dates correspond to the images.

Only call tools when the user explicitly asks for an action; reply directly for questions.
Use the Active Context IDs below — never invent account data.

CRITICAL — HOW TO USE TOOLS:
When you decide to use a tool you MUST invoke it through the tool-calling interface. \
NEVER write a tool name with arguments as plain text in your reply, and never say \
"I will call X" or "please wait while I search" — text that merely describes a tool \
call performs NOTHING. If the user asks you to act (find files, prepare posts, select \
a portfolio), call the tools immediately in the same turn, then report the results. \
When the user names a Business Portfolio as the destination, call list_business_portfolios \
(or pass portfolio_name to prepare_upload_preview) to resolve it — do not ask for page ids.

EFFICIENCY — avoid wasted tool calls:
If a tool requires information you don't have (e.g. a specific Drive folder URL, an ad set ID), \
ask the user for it in plain text FIRST. Do NOT call a tool with missing or guessed arguments. \
If a tool call returns an error, do NOT immediately retry the same call — explain the problem \
and ask the user for what's needed.

CRITICAL SAFETY RULE — DESTRUCTIVE ACTIONS:
You must NEVER delete, remove, archive, or otherwise destroy anything (campaigns, ad sets, \
ads, creatives, posts, accounts, or any other resource) without first getting EXPLICIT \
approval from the user in their own message. Before any such action you must:
  1. Clearly state exactly what will be deleted/removed (name and ID).
  2. Ask the user to confirm in plain words.
  3. Only after the user explicitly says yes (e.g. "yes, delete it") may you call the \
destructive tool, and only then set user_approved=true.
Never assume approval. Never set user_approved=true on your own. A vague or ambiguous \
request is NOT approval — ask again. The system will block any destructive tool call that \
is not explicitly approved by the user.

Be concise."""

# Substrings that mark a tool as destructive. Any tool whose name contains one of
# these is hard-blocked unless the call carries an explicit user_approved=true flag.
# Matching by substring means future delete/remove tools are covered automatically.
_DESTRUCTIVE_TOOL_MARKERS = ("delete", "remove", "archive", "destroy", "purge")


def _is_destructive_tool(tool_name: str) -> bool:
    name = (tool_name or "").lower()
    return any(marker in name for marker in _DESTRUCTIVE_TOOL_MARKERS)


# Maximum number of agentic turns before aborting to prevent runaway loops
_MAX_AGENTIC_TURNS = 20
# Per-tool call timeout in seconds
_TOOL_TIMEOUT_SECONDS = 30

# In-memory AI token usage, keyed by meta_user_id (resets on server restart).
# Structure: {uid: {"input": int, "output": int, "calls": int, "provider": str, "model": str}}
_ai_session_tokens: dict[str, dict] = {}


class ClaudeAgent:
    """Streaming AI agent supporting Claude, OpenAI, and Groq providers."""

    def __init__(self) -> None:
        from config import settings
        self.settings = settings
        self._init_client()

    def _init_client(self) -> None:
        """Initialise the correct client based on AI_PROVIDER setting.

        If the configured provider has no API key, auto-selects the first
        provider that does have a key rather than initialising with an empty key.
        """
        from config import settings
        self.settings = settings
        self._init_error = None
        requested = settings.AI_PROVIDER.lower()

        key_map = {
            "claude": bool(settings.ANTHROPIC_API_KEY),
            "openai": bool(settings.OPENAI_API_KEY),
            "groq":   bool(settings.GROQ_API_KEY),
        }

        # Pick provider: use requested if it has a key, else first available, else none
        if key_map.get(requested):
            provider = requested
        else:
            provider = next((p for p in ["groq", "openai", "claude"] if key_map[p]), None)

        if provider is None:
            # No API keys configured — stay idle until a key is added
            self._provider = "none"
            self.model = ""
            self.max_tokens = 1024
            return

        if provider in ("openai", "groq"):
            # Both OpenAI and Groq use the OpenAI-compatible client. If the
            # package is unavailable, degrade gracefully with a clear reason
            # rather than crashing the whole app / leaving the agent broken.
            try:
                from openai import AsyncOpenAI
            except ImportError as exc:
                logger.error("openai package not installed — cannot use %s provider: %s", provider, exc)
                self._provider = "none"
                self._init_error = "The 'openai' package is required for OpenAI/Groq. Install it (pip install openai)."
                self.model = ""
                self.max_tokens = 4096
                return
            if provider == "openai":
                self._provider = "openai"
                self._openai_client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
                self.model = settings.OPENAI_MODEL or "gpt-4o"
            else:
                self._provider = "groq"
                self._openai_client = AsyncOpenAI(
                    api_key=settings.GROQ_API_KEY,
                    base_url="https://api.groq.com/openai/v1",
                )
                self.model = settings.GROQ_MODEL or "llama-3.3-70b-versatile"
        else:
            self._provider = "claude"
            self.client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
            self.model = settings.CLAUDE_MODEL or "claude-opus-4-7"

        self.max_tokens = 1024  # default; bumped to 4096 when task complexity demands it

    async def complete_text(self, system: str, user: str, max_tokens: int = 1200) -> str:
        """One-shot, non-streaming completion with whatever provider is configured.

        Used for small utility tasks (e.g. matching captions to images) that
        don't need the full conversational tool loop.
        """
        if self._provider == "none":
            raise RuntimeError(self._init_error or "No AI provider configured")
        if self._provider == "claude":
            resp = await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        resp = await self._openai_client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""

    @property
    def supports_vision(self) -> bool:
        return self._provider == "claude"

    async def complete_vision(self, system: str, content: list, max_tokens: int = 1500) -> str:
        """One-shot completion with mixed text/image content blocks (Claude only)."""
        if self._provider != "claude":
            raise RuntimeError("Vision completions require the Claude provider")
        resp = await self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": content}],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    async def get_conversation_messages(
        self,
        conversation_id: int,
        db: AsyncSession,
        limit: int = 20,
    ) -> list[dict]:
        """
        Load the last *limit* messages from the DB for a conversation.

        Messages are returned in chronological order (oldest first) so they
        can be passed directly to the Claude messages API.
        """
        from database import Message

        stmt = (
            select(Message)
            .where(Message.conversation_id == conversation_id)
            .order_by(Message.id.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        rows = list(reversed(result.scalars().all()))

        messages: list[dict] = []
        for row in rows:
            # Only include role + content. tool_calls from DB is metadata-only
            # (stored without id/type/function structure and without the
            # corresponding tool-result messages), so including it would
            # cause a 400 from OpenAI/Groq on the next request.
            msg: dict = {"role": row.role, "content": row.content or ""}
            messages.append(msg)

        return messages

    async def save_message(
        self,
        conversation_id: int,
        role: str,
        content: str,
        tool_calls: Optional[list],
        tokens_used: int,
        db: AsyncSession,
    ) -> None:
        """Persist a message to the database."""
        from database import Message

        msg = Message(
            conversation_id=conversation_id,
            role=role,
            content=content,
            tool_calls=tool_calls,
            tokens_used=tokens_used,
        )
        db.add(msg)
        await db.flush()
        await db.commit()   # release SQLite write lock immediately
        logger.debug(
            "Saved message role=%s conversation_id=%d tokens=%d",
            role,
            conversation_id,
            tokens_used,
        )

    # ------------------------------------------------------------------
    # System prompt construction
    # ------------------------------------------------------------------

    async def build_system_prompt(
        self,
        conversation_id: int,
        client_id: Optional[int],
        db: AsyncSession,
        session_data: Optional[dict] = None,
    ) -> str:
        """Return the system prompt, using an in-memory cache to avoid
        rebuilding it on every turn (context/skills rarely change mid-chat).
        Call invalidate_system_prompt(conv_id) whenever context or skills change.
        """
        if conversation_id in _system_prompt_cache:
            return _system_prompt_cache[conversation_id]
        prompt = await self._build_system_prompt_uncached(
            conversation_id, client_id, db, session_data
        )
        _system_prompt_cache[conversation_id] = prompt
        return prompt

    async def _build_system_prompt_uncached(
        self,
        conversation_id: int,
        client_id: Optional[int],
        db: AsyncSession,
        session_data: Optional[dict] = None,
    ) -> str:
        """Build the full system prompt with pre-loaded account context.

        Loads ad accounts, pages, and pixels directly into the prompt so the
        AI already knows the user's full setup without making tool calls —
        equivalent to handing Claude a .env file with all account IDs.
        """
        from database import ActiveContext, Client, ClientAdAccount, ConnectedMetaAccount
        from skills_manager import load_skills_for_conversation, build_skills_system_prompt
        import meta_api
        from security import FernetEncryption

        meta_uid = (session_data or {}).get("meta_user_id", "")
        google_uid = (session_data or {}).get("google_user_id", "")
        posting_uid = (session_data or {}).get("posting_user_id", "")

        # Fast-path: no Meta, Google, or Posting account → use the lean prompt and return immediately.
        if not meta_uid and not google_uid and not posting_uid:
            return _LEAN_SYSTEM_PROMPT

        parts: list[str] = [BASE_SYSTEM_PROMPT]

        # ── 0. Custom instructions (user-defined, highest priority) ───────────
        try:
            import json as _json
            _us_file = Path("user_settings.json")
            if _us_file.exists():
                _us = _json.loads(_us_file.read_text(encoding="utf-8"))
                _custom = (_us.get("custom_instructions") or "").strip()
                if _custom:
                    parts.append(
                        "\n## Custom Instructions (follow these above all else)\n"
                        + _custom
                    )
        except Exception:
            pass

        # ── 1. Active conversation context ────────────────────────────────
        ctx_result = await db.execute(
            select(ActiveContext).where(ActiveContext.conversation_id == conversation_id)
        )
        ctx: Optional[ActiveContext] = ctx_result.scalar_one_or_none()

        active_lines: list[str] = []
        if client_id is not None:
            client_row = await db.get(Client, client_id)
            if client_row:
                active_lines.append(f"- Client: {client_row.name}" +
                    (f" ({client_row.industry})" if client_row.industry else ""))
                if client_row.website:
                    active_lines.append(f"- Website: {client_row.website}")

        if ctx is not None:
            if ctx.selected_ad_account_id:
                active_lines.append(f"- **Selected Ad Account ID: {ctx.selected_ad_account_id}**")
            if ctx.selected_page_id:
                active_lines.append(f"- **Selected Facebook Page ID: {ctx.selected_page_id}**")
            if ctx.selected_pixel_id:
                active_lines.append(f"- **Selected Pixel ID: {ctx.selected_pixel_id}**")
            if ctx.selected_instagram_id:
                active_lines.append(f"- **Selected Instagram Account ID: {ctx.selected_instagram_id}**")
            if ctx.selected_timezone and ctx.selected_timezone != "UTC":
                active_lines.append(f"- Timezone: {ctx.selected_timezone}")

        if active_lines:
            parts.append("\n## Active Context\n" + "\n".join(active_lines))

        # ── 2. Available accounts (only when no full context set yet) ─────────
        context_complete = (
            ctx is not None
            and ctx.selected_ad_account_id
            and ctx.selected_page_id
        )
        try:
            if not context_complete:
                enc = FernetEncryption()
                acc_result = await db.execute(
                    select(ConnectedMetaAccount).where(
                        ConnectedMetaAccount.facebook_user_id == meta_uid,
                        ConnectedMetaAccount.is_active == True,
                    )
                )
                meta_acc = acc_result.scalar_one_or_none()
                if meta_acc:
                    token = enc.decrypt(meta_acc.encrypted_long_token)
                    cached = await _get_cached_meta_accounts(meta_uid, token)
                    account_lines: list[str] = [
                        f"Connected as: {meta_acc.user_name or meta_uid}"
                    ]
                    for a in cached["ad_accounts"][:10]:
                        account_lines.append(
                            f"  - {a.get('name', '?')} | ID: {a.get('id','?')} | {a.get('currency','?')}"
                        )
                    for p in cached["pages"][:10]:
                        account_lines.append(f"  - Page: {p.get('name','?')} | ID: {p.get('id','?')}")
                    parts.append("\n## Available Accounts\n" + "\n".join(account_lines))
        except Exception as exc:
            logger.debug("Could not pre-load account list into prompt: %s", exc)

        # ── 3. Client ad account defaults ─────────────────────────────────
        if client_id is not None:
            try:
                aa_result = await db.execute(
                    select(ClientAdAccount).where(ClientAdAccount.client_id == client_id)
                )
                client_accounts = aa_result.scalars().all()
                if client_accounts:
                    aa_lines = ["\n## Client Ad Account Defaults"]
                    for aa in client_accounts:
                        aa_lines.append(f"- {aa.nickname} | Meta ID: {aa.meta_account_id}" +
                            (f" | Page: {aa.default_page_id}" if aa.default_page_id else "") +
                            (f" | Pixel: {aa.default_pixel_id}" if aa.default_pixel_id else ""))
                    parts.append("\n".join(aa_lines))
            except Exception as exc:
                logger.debug("Could not load client ad accounts: %s", exc)

        # ── 3b. Google Drive connection status ───────────────────────────────
        if google_uid:
            parts.append(
                "\n## Google Drive\n"
                "Google Drive IS connected. You have access to these tools:\n"
                "- read_google_drive_folder: list files in a Drive folder by URL\n"
                "- upload_ads_from_drive: upload ads directly from a Drive folder URL\n"
                "- read_google_doc: read the full text of a Google Doc\n"
                "- read_google_sheet: read data from a Google Sheet\n"
                "When a user provides any drive.google.com or docs.google.com URL, call the appropriate tool immediately."
            )

        # ── 3c. Posting account ──────────────────────────────────────────────
        if posting_uid:
            try:
                from database import ConnectedPostingAccount as _CPA
                posting_res = await db.execute(
                    select(_CPA).where(
                        _CPA.facebook_user_id == posting_uid,
                        _CPA.is_active == True,
                    )
                )
                posting_acc = posting_res.scalar_one_or_none()
                posting_lines = ["\n## Posting Account"]
                if posting_acc:
                    posting_lines.append(f"Connected posting account: {posting_acc.user_name or posting_uid}")
                posting_lines.append(
                    "This session is for content posting (Facebook Pages & Instagram), NOT ad campaigns. "
                    "Do NOT ask for an ad account ID — it is not needed here. "
                    "Help the user draft captions, schedule posts, create content, and manage their pages."
                )
                # List the actual Pages & Instagram accounts this account manages so
                # the AI can reference them by name/ID instead of asking the user.
                if posting_acc:
                    try:
                        enc = FernetEncryption()
                        ptoken = enc.decrypt(posting_acc.encrypted_long_token)
                        pages_result = await meta_api.get_pages(ptoken)
                        if pages_result.get("success"):
                            raw_pages = pages_result["data"]
                            page_list = raw_pages["data"] if isinstance(raw_pages, dict) else raw_pages
                            page_lines = []
                            for p in page_list[:15]:
                                page_lines.append(f"  - Facebook Page: {p.get('name','?')} | ID: {p.get('id','?')}")
                            if page_lines:
                                posting_lines.append("Available pages this account manages:")
                                posting_lines.extend(page_lines)
                                posting_lines.append(
                                    "You CAN reference and use these pages directly — they are authorized for this account."
                                )
                    except Exception as exc:
                        logger.debug("Could not pre-load posting pages: %s", exc)
                if ctx and ctx.selected_page_id:
                    posting_lines.append(f"Currently selected page/account ID: {ctx.selected_page_id}")
                parts.append("\n".join(posting_lines))
            except Exception as exc:
                logger.debug("Could not load posting account info: %s", exc)

        # ── 4. Skills ──────────────────────────────────────────────────────
        try:
            skills = await load_skills_for_conversation(conversation_id, client_id, db)
            skills_section = await build_skills_system_prompt(skills)
            if skills_section:
                parts.append("\n" + skills_section)
        except Exception as exc:
            logger.warning("Could not load skills for system prompt: %s", exc)

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Streaming response
    # ------------------------------------------------------------------

    async def stream_response(
        self,
        conversation_id: int,
        user_message: str,
        session_data: dict,
        db: AsyncSession,
    ) -> AsyncGenerator[str, None]:
        """
        Main streaming entry-point.  Yields SSE-formatted strings.

        Flow:
        1. Save user message to DB.
        2. Load conversation history (last 20 messages).
        3. Build system prompt.
        4. Stream Claude response with tool-use support.
        5. On tool_use blocks: execute tools (parallel when possible).
        6. Continue the conversation with tool results until Claude stops.
        7. Save assistant response to DB.
        8. Yield ``data: [DONE]\\n\\n``.

        SSE event types: ``text``, ``tool_start``, ``tool_result``, ``error``, ``done``.
        """
        client_id: Optional[int] = session_data.get("client_id")

        def _sse(payload: dict) -> str:
            return f"data: {json.dumps(payload)}\n\n"

        # 1. Save user message
        try:
            await self.save_message(
                conversation_id=conversation_id,
                role="user",
                content=user_message,
                tool_calls=None,
                tokens_used=0,
                db=db,
            )
        except Exception as exc:
            logger.error("Failed to save user message: %s", exc)
            yield _sse({"type": "error", "message": f"Database error: {exc}"})
            return

        # 2. Load history (keep last 6 turns to reduce token usage)
        try:
            history = await self.get_conversation_messages(
                conversation_id, db, limit=6
            )
        except Exception as exc:
            logger.error("Failed to load conversation history: %s", exc)
            yield _sse({"type": "error", "message": f"Database error: {exc}"})
            return

        # 3. Build system prompt
        try:
            system_prompt = await self.build_system_prompt(
                conversation_id, client_id, db, session_data=session_data
            )
        except Exception as exc:
            logger.warning("Could not build full system prompt, using base: %s", exc)
            system_prompt = BASE_SYSTEM_PROMPT

        # Build the messages list for the API call.
        # The history already includes the user message we just saved, but
        # get_conversation_messages returns what was in the DB *before* this
        # call (the flush may not have committed yet in the same session).
        # To be safe we append the new user message explicitly if not present.
        messages: list[dict] = list(history)
        if not messages or messages[-1].get("content") != user_message:
            messages.append({"role": "user", "content": user_message})

        # Only expose tools when an account is linked AND the message looks like
        # an actionable request.  For general chat we skip tools entirely — they
        # add ~1 500 input tokens every time and trigger the AI to run lookups
        # instead of just replying.
        meta_connected = bool(session_data.get("meta_user_id"))
        google_connected = bool(session_data.get("google_user_id"))
        use_tools = (meta_connected or google_connected) and _is_meta_request(user_message)
        if use_tools:
            all_defs = self.get_tool_definitions()
            wanted = _select_tool_names(user_message)
            # Send only the relevant subset; fall back to all if nothing matched.
            tool_definitions = (
                [d for d in all_defs if d["name"] in wanted] if wanted else all_defs
            )
        else:
            tool_definitions = []

        # Use a larger output budget for task-like requests; keep it tight for chat.
        effective_max_tokens = 4096 if use_tools else self.max_tokens

        full_response_text = ""
        total_input_tokens = 0
        total_output_tokens = 0
        total_tokens = 0  # kept for DB compat (input + output)
        all_tool_calls: list[dict] = []

        # Convert Claude tool definitions → OpenAI function format (used for openai/groq)
        def _to_openai_tools(defs: list[dict]) -> list[dict]:
            result = []
            for d in defs:
                result.append({
                    "type": "function",
                    "function": {
                        "name": d["name"],
                        "description": d.get("description", ""),
                        "parameters": d.get("input_schema", {"type": "object", "properties": {}}),
                    },
                })
            return result

        # 4–6. Agentic loop — keep calling the AI until it stops or we hit the turn limit.
        for turn in range(_MAX_AGENTIC_TURNS):
            try:
                accumulated_text = ""
                pending_tool_uses: list[dict] = []  # {id, name, input}

                if self._provider == "claude":
                    # ── Claude (Anthropic) streaming ──────────────────────────
                    # System prompt cached so subsequent turns in the same
                    # conversation pay ~10% of the normal input token price.
                    cached_system = [{"type": "text", "text": system_prompt,
                                      "cache_control": {"type": "ephemeral"}}]
                    claude_kwargs: dict = dict(
                        model=self.model,
                        max_tokens=effective_max_tokens,
                        system=cached_system,
                        messages=messages,
                        extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
                    )
                    if tool_definitions:
                        claude_kwargs["tools"] = tool_definitions
                    async with self.client.messages.stream(**claude_kwargs) as stream:
                        current_tool_id: Optional[str] = None
                        current_tool_name: Optional[str] = None
                        current_tool_input_parts: list[str] = []

                        async for event in stream:
                            event_type = event.type

                            if event_type == "content_block_start":
                                block = event.content_block
                                if block.type == "tool_use":
                                    current_tool_id = block.id
                                    current_tool_name = block.name
                                    current_tool_input_parts = []
                                    yield _sse({"type": "tool_start", "name": block.name})

                            elif event_type == "content_block_delta":
                                delta = event.delta
                                if delta.type == "text_delta":
                                    accumulated_text += delta.text
                                    yield _sse({"type": "text", "text": delta.text})
                                elif delta.type == "input_json_delta":
                                    if current_tool_input_parts is not None:
                                        current_tool_input_parts.append(delta.partial_json)

                            elif event_type == "content_block_stop":
                                if current_tool_id is not None:
                                    raw_input = "".join(current_tool_input_parts)
                                    try:
                                        tool_input = json.loads(raw_input) if raw_input else {}
                                    except json.JSONDecodeError:
                                        tool_input = {}
                                    pending_tool_uses.append({
                                        "id": current_tool_id,
                                        "name": current_tool_name,
                                        "input": tool_input,
                                    })
                                    current_tool_id = None
                                    current_tool_name = None
                                    current_tool_input_parts = []

                            elif event_type == "message_delta":
                                if hasattr(event, "usage") and event.usage:
                                    total_tokens += getattr(event.usage, "output_tokens", 0)

                    final_message = await stream.get_final_message()
                    stop_reason: str = final_message.stop_reason or "end_turn"
                    if final_message.usage:
                        turn_in  = final_message.usage.input_tokens
                        turn_out = final_message.usage.output_tokens
                        total_input_tokens  += turn_in
                        total_output_tokens += turn_out
                        total_tokens = total_input_tokens + total_output_tokens
                        yield _sse({"type": "usage", "input_tokens": turn_in,
                                    "output_tokens": turn_out, "provider": "claude",
                                    "model": self.model})

                else:
                    # ── OpenAI / Groq streaming ──────────────────────────────
                    # Build OpenAI-format messages (system first, then history)
                    # Must preserve tool_calls / tool_call_id fields so multi-turn
                    # tool-use works correctly on the second+ loop iteration.
                    oai_messages: list[dict] = [{"role": "system", "content": system_prompt}]
                    for m in messages:
                        role = m.get("role", "user")
                        content = m.get("content")
                        if isinstance(content, list):
                            content = " ".join(
                                b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
                            )
                        msg: dict = {"role": role}
                        if content is not None:
                            msg["content"] = content
                        if "tool_calls" in m:
                            msg["tool_calls"] = m["tool_calls"]
                        if "tool_call_id" in m:
                            msg["tool_call_id"] = m["tool_call_id"]
                        oai_messages.append(msg)

                    oai_tools = _to_openai_tools(tool_definitions)

                    # Collect streaming chunks
                    tool_calls_raw: dict[int, dict] = {}  # index → {id, name, arguments}
                    stop_reason = "end_turn"  # default; updated by finish_reason
                    turn_in_oai = 0
                    turn_out_oai = 0
                    create_kwargs: dict = dict(
                        model=self.model,
                        max_tokens=effective_max_tokens,
                        messages=oai_messages,
                        stream=True,
                        stream_options={"include_usage": True},
                    )
                    if oai_tools:
                        create_kwargs["tools"] = oai_tools
                        create_kwargs["tool_choice"] = "auto"
                    async for chunk in await self._openai_client.chat.completions.create(
                        **create_kwargs
                    ):
                        choice = chunk.choices[0] if chunk.choices else None
                        if choice is None:
                            continue
                        delta = choice.delta

                        if delta.content:
                            accumulated_text += delta.content
                            yield _sse({"type": "text", "text": delta.content})

                        if delta.tool_calls:
                            for tc in delta.tool_calls:
                                idx = tc.index
                                if idx not in tool_calls_raw:
                                    tool_calls_raw[idx] = {"id": "", "name": "", "arguments": ""}
                                if tc.id:
                                    tool_calls_raw[idx]["id"] = tc.id
                                if tc.function:
                                    if tc.function.name:
                                        if not tool_calls_raw[idx]["name"]:
                                            tool_calls_raw[idx]["name"] = tc.function.name
                                            yield _sse({"type": "tool_start", "name": tc.function.name})
                                    if tc.function.arguments:
                                        tool_calls_raw[idx]["arguments"] += tc.function.arguments

                        if choice.finish_reason:
                            if choice.finish_reason == "tool_calls":
                                stop_reason = "tool_use"
                            elif choice.finish_reason in ("stop", "length", "end_turn"):
                                stop_reason = "end_turn"

                        # Usage arrives on the final chunk (no choices)
                        if hasattr(chunk, "usage") and chunk.usage:
                            turn_in_oai  = getattr(chunk.usage, "prompt_tokens", 0) or 0
                            turn_out_oai = getattr(chunk.usage, "completion_tokens", 0) or 0

                    if turn_in_oai or turn_out_oai:
                        total_input_tokens  += turn_in_oai
                        total_output_tokens += turn_out_oai
                        total_tokens = total_input_tokens + total_output_tokens
                        yield _sse({"type": "usage", "input_tokens": turn_in_oai,
                                    "output_tokens": turn_out_oai,
                                    "provider": self._provider, "model": self.model})

                    # Parse accumulated tool calls into pending_tool_uses
                    for idx in sorted(tool_calls_raw):
                        tc = tool_calls_raw[idx]
                        if not tc["name"]:
                            continue  # skip empty/malformed entries
                        try:
                            tool_input = json.loads(tc["arguments"]) if tc["arguments"] else {}
                        except json.JSONDecodeError:
                            tool_input = {}
                        pending_tool_uses.append({
                            "id": tc["id"] or f"call_{idx}",
                            "name": tc["name"],
                            "input": tool_input,
                        })
                    # If tool calls present but stop_reason wasn't set by finish_reason
                    if pending_tool_uses and stop_reason == "end_turn":
                        stop_reason = "tool_use"

            except anthropic.APIConnectionError as exc:
                logger.error("Anthropic connection error: %s", exc)
                _write_log_entry({"ts": datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z",
                    "conv_id": conversation_id, "error": "connection_error", "detail": str(exc),
                    "provider": self._provider, "model": self.model})
                yield _sse({"type": "error", "message": "Connection to Claude failed. Please retry."})
                return
            except anthropic.RateLimitError as exc:
                logger.error("Anthropic rate limit: %s", exc)
                _write_log_entry({"ts": datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z",
                    "conv_id": conversation_id, "error": "rate_limit", "detail": str(exc),
                    "provider": self._provider, "model": self.model})
                yield _sse({"type": "error", "message": "Rate limit reached. Please wait a moment and retry."})
                return
            except anthropic.APIStatusError as exc:
                logger.error("Anthropic API error %d: %s", exc.status_code, exc.message)
                _write_log_entry({"ts": datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z",
                    "conv_id": conversation_id, "error": f"api_status_{exc.status_code}",
                    "detail": exc.message, "provider": self._provider, "model": self.model})
                yield _sse({"type": "error", "message": f"Claude API error ({exc.status_code}): {exc.message}"})
                return
            except Exception as exc:
                # Catch OpenAI/Groq SDK errors and any other unexpected errors
                err_str = str(exc)
                logger.error("Error in stream_response: %s", err_str, exc_info=True)
                _write_log_entry({"ts": datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z",
                    "conv_id": conversation_id, "error": "unexpected", "detail": err_str[:300],
                    "provider": self._provider, "model": self.model})
                # Friendly message for common API errors
                if "400" in err_str or "invalid_request" in err_str.lower():
                    yield _sse({"type": "error", "message": f"API request error: {err_str}"})
                elif "401" in err_str or "authentication" in err_str.lower():
                    yield _sse({"type": "error", "message": "Invalid API key — go to Settings → Open Setup Wizard and re-enter your API key for the selected provider."})
                elif "429" in err_str or "rate_limit" in err_str.lower():
                    yield _sse({"type": "error", "message": "Rate limit reached. Please wait and retry."})
                else:
                    yield _sse({"type": "error", "message": f"Unexpected error: {err_str}"})
                return

            full_response_text += accumulated_text

            # --- No tool calls — we're done ---
            if stop_reason == "end_turn" or not pending_tool_uses:
                break

            # --- Execute tool calls ---
            async def _run_tool(tu: dict) -> tuple[str, str, str]:
                try:
                    result_str = await asyncio.wait_for(
                        self.execute_tool(tu["name"], tu["input"], session_data, db),
                        timeout=_TOOL_TIMEOUT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    result_str = json.dumps({"error": f"Tool '{tu['name']}' timed out after {_TOOL_TIMEOUT_SECONDS}s"})
                except Exception as exc:
                    result_str = json.dumps({"error": str(exc)})
                return tu["id"], tu["name"], result_str

            tool_tasks = [_run_tool(tu) for tu in pending_tool_uses]
            tool_results: list[tuple[str, str, str]] = await asyncio.gather(*tool_tasks)

            # Yield tool_result events and update messages
            for tool_id, tool_name, result_str in tool_results:
                yield _sse({"type": "tool_result", "name": tool_name, "result": result_str[:500]})
                all_tool_calls.append({
                    "name": tool_name,
                    "input": next(tu["input"] for tu in pending_tool_uses if tu["id"] == tool_id),
                })

            if self._provider == "claude":
                # Claude expects tool_use blocks in assistant turn, then tool_result in user turn
                assistant_content: list[dict] = []
                if accumulated_text:
                    assistant_content.append({"type": "text", "text": accumulated_text})
                for tu in pending_tool_uses:
                    assistant_content.append({"type": "tool_use", "id": tu["id"], "name": tu["name"], "input": tu["input"]})
                messages.append({"role": "assistant", "content": assistant_content})

                tool_result_content: list[dict] = []
                for tool_id, tool_name, result_str in tool_results:
                    tool_result_content.append({"type": "tool_result", "tool_use_id": tool_id, "content": result_str})
                messages.append({"role": "user", "content": tool_result_content})
            else:
                # OpenAI expects assistant message with tool_calls, then role=tool messages
                oai_tool_calls_msg: list[dict] = []
                for tu in pending_tool_uses:
                    oai_tool_calls_msg.append({
                        "id": tu["id"],
                        "type": "function",
                        "function": {"name": tu["name"], "arguments": json.dumps(tu["input"])},
                    })
                messages.append({"role": "assistant", "content": accumulated_text or None, "tool_calls": oai_tool_calls_msg})
                for tool_id, tool_name, result_str in tool_results:
                    messages.append({"role": "tool", "tool_call_id": tool_id, "content": result_str})

            if stop_reason == "tool_use":
                continue
            break

        else:
            logger.warning(
                "Reached max agentic turns (%d) for conversation_id=%d",
                _MAX_AGENTIC_TURNS,
                conversation_id,
            )
            yield _sse(
                {
                    "type": "text",
                    "text": "\n\n[Max tool-use turns reached. Stopping.]",
                }
            )
            full_response_text += "\n\n[Max tool-use turns reached. Stopping.]"

        # Guard: if the AI produced no text at all (e.g. only ran tools with no follow-up),
        # emit a short fallback so the user isn't left with an empty chat bubble.
        if not full_response_text.strip():
            fallback = "I'm here! How can I help you?"
            full_response_text = fallback
            yield _sse({"type": "text", "text": fallback})

        # 7. Save assistant response to DB
        try:
            await self.save_message(
                conversation_id=conversation_id,
                role="assistant",
                content=full_response_text,
                tool_calls=all_tool_calls if all_tool_calls else None,
                tokens_used=total_tokens,
                db=db,
            )
        except Exception as exc:
            logger.error("Failed to save assistant message: %s", exc)

        # Update in-memory session token totals
        uid = session_data.get("meta_user_id", "anon")
        if uid not in _ai_session_tokens:
            _ai_session_tokens[uid] = {"input": 0, "output": 0, "calls": 0,
                                        "provider": self._provider, "model": self.model}
        _ai_session_tokens[uid]["input"]    += total_input_tokens
        _ai_session_tokens[uid]["output"]   += total_output_tokens
        _ai_session_tokens[uid]["calls"]    += 1
        _ai_session_tokens[uid]["provider"]  = self._provider
        _ai_session_tokens[uid]["model"]     = self.model

        # Write diagnostic log entry
        _write_log_entry({
            "ts":          datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "uid":         uid[:8] + "…" if len(uid) > 8 else uid,
            "conv_id":     conversation_id,
            "msg_preview": user_message[:120].replace("\n", " "),
            "provider":    self._provider,
            "model":       self.model,
            "in_tokens":   total_input_tokens,
            "out_tokens":  total_output_tokens,
            "total":       total_tokens,
            "tools_used":  [t["name"] for t in all_tool_calls] if all_tool_calls else [],
            "meta_req":    use_tools,
            "max_tok_cap": effective_max_tokens,
            "empty_reply": not full_response_text.strip() if not all_tool_calls else False,
        })

        # 8. Signal completion
        yield _sse({"type": "done"})
        yield "data: [DONE]\n\n"

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def execute_tool(
        self,
        tool_name: str,
        tool_input: dict,
        session_data: dict,
        db: AsyncSession,
    ) -> str:
        """
        Dispatch a tool call from Claude to the appropriate MCP server function.

        Returns a JSON string result to be fed back to Claude as a tool_result.
        Each call is wrapped in a try/except so an error never crashes the loop.
        """
        logger.info("Executing tool: %s  input_keys=%s", tool_name, list(tool_input.keys()))

        # ── Forced safety gate: destructive actions require explicit approval ──
        # This is a hard block independent of the system prompt. Even if the model
        # ignores its instructions, a delete/remove/archive call cannot proceed
        # unless the user explicitly approved it (user_approved=true in the call).
        if _is_destructive_tool(tool_name):
            approved = tool_input.get("user_approved")
            if approved is not True and str(approved).lower() not in ("true", "yes", "1"):
                logger.warning("Blocked destructive tool '%s' — no explicit user approval", tool_name)
                return json.dumps({
                    "error": "approval_required",
                    "tool": tool_name,
                    "message": (
                        "This is a destructive action and was BLOCKED. You must first tell "
                        "the user exactly what will be deleted (name and ID) and ask them to "
                        "confirm. Only after the user explicitly approves in their own message "
                        "may you retry this tool with user_approved=true. Do not approve it yourself."
                    ),
                })

        try:
            # Import lazily to avoid circular imports at module load time
            import mcp_server  # type: ignore[import]

            handler = getattr(mcp_server, tool_name, None)
            if handler is None:
                return json.dumps({"error": f"Unknown tool: {tool_name}"})

            # MCP tools use session_id (facebook_user_id) to look up tokens
            # themselves — do NOT pass db/session_data as kwargs.
            call_kwargs = dict(tool_input)
            # The approval flag is consumed by the safety gate above; MCP handlers
            # don't accept it, so strip it before dispatch.
            call_kwargs.pop("user_approved", None)
            if "session_id" not in call_kwargs:
                call_kwargs["session_id"] = session_data.get("meta_user_id", "")
            result = await handler(**call_kwargs)

            if isinstance(result, (dict, list)):
                return json.dumps(result)
            return str(result)

        except ImportError:
            # mcp_server not installed in this environment — return a stub
            logger.debug("mcp_server module not available; returning stub for %s", tool_name)
            return json.dumps(
                {
                    "tool": tool_name,
                    "status": "unavailable",
                    "message": "MCP server module not installed in this environment.",
                    "input": tool_input,
                }
            )
        except Exception as exc:
            logger.error("Tool '%s' raised an exception: %s", tool_name, exc, exc_info=True)
            return json.dumps({"error": str(exc), "tool": tool_name})

    # ------------------------------------------------------------------
    # Tool definitions (Claude API schema)
    # ------------------------------------------------------------------

    def get_tool_definitions(self) -> list[dict]:
        """
        Return the full list of tool definitions for the Claude messages API.

        Each entry follows the Anthropic tool schema::

            {
                "name": str,
                "description": str,
                "input_schema": {
                    "type": "object",
                    "properties": {...},
                    "required": [...]
                }
            }
        """
        return [
            # ----------------------------------------------------------
            # Meta account discovery
            # ----------------------------------------------------------
            {
                "name": "list_ad_accounts",
                "description": (
                    "List all Meta ad accounts accessible to the connected user. "
                    "Returns account IDs, names, currency, and status."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "meta_account_id": {
                            "type": "string",
                            "description": "Connected Meta user account ID. Omit to use active context.",
                        }
                    },
                    "required": [],
                },
            },
            {
                "name": "list_pages",
                "description": (
                    "List all Facebook Pages accessible to the connected user. "
                    "Returns page IDs, names, and categories."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "meta_account_id": {
                            "type": "string",
                            "description": "Connected Meta user account ID. Omit to use active context.",
                        }
                    },
                    "required": [],
                },
            },
            {
                "name": "list_pixels",
                "description": (
                    "List all Meta Pixels (datasets) for a given ad account."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ad_account_id": {
                            "type": "string",
                            "description": "Meta ad account ID (e.g. 'act_123456'). Omit to use active context.",
                        }
                    },
                    "required": [],
                },
            },
            # ----------------------------------------------------------
            # Campaigns
            # ----------------------------------------------------------
            {
                "name": "create_campaign",
                "description": (
                    "Create a new Meta ad campaign. Returns the new campaign ID."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ad_account_id": {
                            "type": "string",
                            "description": "Meta ad account ID (e.g. 'act_123456').",
                        },
                        "name": {
                            "type": "string",
                            "description": "Campaign name.",
                        },
                        "objective": {
                            "type": "string",
                            "description": "Campaign objective, e.g. OUTCOME_SALES, OUTCOME_TRAFFIC.",
                            "enum": [
                                "OUTCOME_SALES",
                                "OUTCOME_TRAFFIC",
                                "OUTCOME_LEADS",
                                "OUTCOME_ENGAGEMENT",
                                "OUTCOME_APP_PROMOTION",
                                "OUTCOME_AWARENESS",
                            ],
                        },
                        "status": {
                            "type": "string",
                            "description": "Initial campaign status. Default: ACTIVE.",
                            "enum": ["ACTIVE", "PAUSED"],
                        },
                        "daily_budget": {
                            "type": "number",
                            "description": "Daily budget in the account's currency (minor units, e.g. cents).",
                        },
                        "special_ad_categories": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Special ad categories, e.g. ['NONE'].",
                        },
                    },
                    "required": ["ad_account_id", "name", "objective"],
                },
            },
            {
                "name": "get_campaigns",
                "description": (
                    "Retrieve all campaigns for an ad account with their status, "
                    "budget, and spend."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ad_account_id": {
                            "type": "string",
                            "description": "Meta ad account ID.",
                        },
                        "status_filter": {
                            "type": "string",
                            "description": "Filter by status: ACTIVE, PAUSED, ARCHIVED, or ALL. Default: ALL.",
                        },
                    },
                    "required": ["ad_account_id"],
                },
            },
            {
                "name": "pause_campaign",
                "description": "Pause a running Meta campaign by ID.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "campaign_id": {
                            "type": "string",
                            "description": "Campaign ID to pause.",
                        }
                    },
                    "required": ["campaign_id"],
                },
            },
            {
                "name": "activate_campaign",
                "description": "Activate (unpause) a Meta campaign by ID.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "campaign_id": {
                            "type": "string",
                            "description": "Campaign ID to activate.",
                        }
                    },
                    "required": ["campaign_id"],
                },
            },
            {
                "name": "delete_campaign",
                "description": (
                    "Permanently delete a Meta campaign. DESTRUCTIVE ACTION: you must first "
                    "tell the user exactly which campaign (name and ID) will be deleted and "
                    "get their explicit confirmation in their own message. Only set "
                    "user_approved=true after the user has clearly said yes. The system blocks "
                    "this call unless user_approved=true."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "campaign_id": {
                            "type": "string",
                            "description": "Campaign ID to delete.",
                        },
                        "user_approved": {
                            "type": "boolean",
                            "description": (
                                "Must be true and is only allowed after the user has "
                                "explicitly approved this specific deletion in their own "
                                "message. Never set this on your own initiative."
                            ),
                        },
                    },
                    "required": ["campaign_id", "user_approved"],
                },
            },
            # ----------------------------------------------------------
            # Ad sets
            # ----------------------------------------------------------
            {
                "name": "create_ad_set",
                "description": (
                    "Create a new ad set within a campaign. "
                    "Defines targeting, budget, placements, and schedule."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "campaign_id": {
                            "type": "string",
                            "description": "Parent campaign ID.",
                        },
                        "ad_account_id": {
                            "type": "string",
                            "description": "Meta ad account ID.",
                        },
                        "name": {
                            "type": "string",
                            "description": "Ad set name.",
                        },
                        "daily_budget": {
                            "type": "number",
                            "description": "Daily budget in minor currency units.",
                        },
                        "targeting": {
                            "type": "object",
                            "description": (
                                "Targeting spec object. Common fields: "
                                "geo_locations, age_min, age_max, genders."
                            ),
                        },
                        "optimization_goal": {
                            "type": "string",
                            "description": "Optimization goal, e.g. OFFSITE_CONVERSIONS, LINK_CLICKS.",
                        },
                        "billing_event": {
                            "type": "string",
                            "description": "Billing event, e.g. IMPRESSIONS.",
                        },
                        "pixel_id": {
                            "type": "string",
                            "description": "Pixel ID for conversion tracking.",
                        },
                        "instagram_actor_id": {
                            "type": "string",
                            "description": "Instagram account ID for Instagram placements.",
                        },
                        "start_time": {
                            "type": "string",
                            "description": "ISO-8601 start datetime.",
                        },
                        "end_time": {
                            "type": "string",
                            "description": "ISO-8601 end datetime.",
                        },
                    },
                    "required": ["campaign_id", "ad_account_id", "name", "daily_budget"],
                },
            },
            # ----------------------------------------------------------
            # Ad creative & upload
            # ----------------------------------------------------------
            {
                "name": "upload_single_ad",
                "description": (
                    "Upload a single ad creative to Meta and create the ad. "
                    "Prefer upload_multiple_ads for batches."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ad_set_id": {
                            "type": "string",
                            "description": "Ad set ID to attach the ad to.",
                        },
                        "ad_account_id": {
                            "type": "string",
                            "description": "Meta ad account ID.",
                        },
                        "image_path": {
                            "type": "string",
                            "description": "Local path to the image file.",
                        },
                        "ad_name": {
                            "type": "string",
                            "description": "Display name for the ad.",
                        },
                        "headline": {
                            "type": "string",
                            "description": "Ad headline (max 40 chars).",
                        },
                        "body": {
                            "type": "string",
                            "description": "Ad body copy.",
                        },
                        "call_to_action": {
                            "type": "string",
                            "description": "CTA button type, e.g. SHOP_NOW, LEARN_MORE.",
                        },
                        "page_id": {
                            "type": "string",
                            "description": "Facebook Page ID.",
                        },
                        "instagram_actor_id": {
                            "type": "string",
                            "description": "Instagram account ID for Instagram placement.",
                        },
                        "link_url": {
                            "type": "string",
                            "description": "Destination URL.",
                        },
                        "placement": {
                            "type": "string",
                            "description": "Placement hint: 'feed' or 'story'.",
                            "enum": ["feed", "story"],
                        },
                    },
                    "required": [
                        "ad_set_id",
                        "ad_account_id",
                        "image_path",
                        "ad_name",
                        "page_id",
                    ],
                },
            },
            {
                "name": "upload_multiple_ads",
                "description": (
                    "Upload multiple ads in a batch. "
                    "Use this for any task involving more than one ad. "
                    "Accepts a list of ad specs and processes them efficiently."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ad_account_id": {
                            "type": "string",
                            "description": "Meta ad account ID.",
                        },
                        "ad_set_id": {
                            "type": "string",
                            "description": "Ad set ID to attach all ads to.",
                        },
                        "ads": {
                            "type": "array",
                            "description": "List of ad spec objects (same fields as upload_single_ad).",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "image_path": {"type": "string"},
                                    "ad_name": {"type": "string"},
                                    "headline": {"type": "string"},
                                    "body": {"type": "string"},
                                    "call_to_action": {"type": "string"},
                                    "link_url": {"type": "string"},
                                    "placement": {
                                        "type": "string",
                                        "enum": ["feed", "story"],
                                    },
                                },
                                "required": ["image_path", "ad_name"],
                            },
                        },
                        "page_id": {
                            "type": "string",
                            "description": "Facebook Page ID.",
                        },
                        "instagram_actor_id": {
                            "type": "string",
                            "description": "Instagram account ID.",
                        },
                    },
                    "required": ["ad_account_id", "ad_set_id", "ads", "page_id"],
                },
            },
            # ----------------------------------------------------------
            # Analytics
            # ----------------------------------------------------------
            {
                "name": "get_performance_report",
                "description": (
                    "Get aggregated performance metrics (spend, ROAS, CPM, CTR, CPC, "
                    "impressions, clicks, conversions) for all active campaigns in an "
                    "ad account over a date range."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ad_account_id": {
                            "type": "string",
                            "description": "Meta ad account ID.",
                        },
                        "date_preset": {
                            "type": "string",
                            "description": (
                                "Date range preset. Options: last_7d, last_14d, "
                                "last_30d, this_month, last_month."
                            ),
                        },
                        "since": {
                            "type": "string",
                            "description": "Custom start date in YYYY-MM-DD format.",
                        },
                        "until": {
                            "type": "string",
                            "description": "Custom end date in YYYY-MM-DD format.",
                        },
                        "breakdown": {
                            "type": "string",
                            "description": "Optional breakdown: age, gender, country, placement.",
                        },
                    },
                    "required": ["ad_account_id"],
                },
            },
            {
                "name": "get_campaign_performance",
                "description": (
                    "Get detailed performance metrics for a specific campaign, "
                    "broken down by ad set and individual ad."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "campaign_id": {
                            "type": "string",
                            "description": "Campaign ID to report on.",
                        },
                        "date_preset": {
                            "type": "string",
                            "description": "Date range preset (last_7d, last_14d, last_30d, etc.).",
                        },
                        "since": {
                            "type": "string",
                            "description": "Custom start date YYYY-MM-DD.",
                        },
                        "until": {
                            "type": "string",
                            "description": "Custom end date YYYY-MM-DD.",
                        },
                    },
                    "required": ["campaign_id"],
                },
            },
            # ----------------------------------------------------------
            # Post scheduling
            # ----------------------------------------------------------
            {
                "name": "schedule_post",
                "description": (
                    "Schedule an image post on Facebook or Instagram at a specific time."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "page_id": {
                            "type": "string",
                            "description": "Facebook Page ID to post from.",
                        },
                        "instagram_account_id": {
                            "type": "string",
                            "description": "Instagram account ID for Instagram posts.",
                        },
                        "image_path": {
                            "type": "string",
                            "description": "Local path to the image file.",
                        },
                        "caption": {
                            "type": "string",
                            "description": "Post caption / copy.",
                        },
                        "scheduled_time": {
                            "type": "string",
                            "description": "ISO-8601 datetime when to publish the post.",
                        },
                        "platform": {
                            "type": "string",
                            "description": "Target platform. Default: both.",
                            "enum": ["facebook", "instagram", "both"],
                        },
                        "timezone": {
                            "type": "string",
                            "description": "Timezone name for the scheduled time, e.g. 'Europe/Madrid'. Default: UTC.",
                        },
                    },
                    "required": ["image_path", "caption", "scheduled_time"],
                },
            },
            {
                "name": "schedule_reel",
                "description": (
                    "Schedule a Reel (short video) on Facebook or Instagram."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "page_id": {
                            "type": "string",
                            "description": "Facebook Page ID.",
                        },
                        "instagram_account_id": {
                            "type": "string",
                            "description": "Instagram account ID.",
                        },
                        "video_path": {
                            "type": "string",
                            "description": "Local path to the video file (mp4 or mov).",
                        },
                        "caption": {
                            "type": "string",
                            "description": "Reel caption.",
                        },
                        "scheduled_time": {
                            "type": "string",
                            "description": "ISO-8601 datetime when to publish.",
                        },
                        "platform": {
                            "type": "string",
                            "enum": ["facebook", "instagram", "both"],
                        },
                        "timezone": {
                            "type": "string",
                            "description": "Timezone name.",
                        },
                    },
                    "required": ["video_path", "caption", "scheduled_time"],
                },
            },
            {
                "name": "get_scheduled_posts",
                "description": (
                    "List all scheduled posts for a client, optionally filtered by "
                    "date range or platform."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "client_id": {
                            "type": "integer",
                            "description": "Client DB ID. Omit to use active context.",
                        },
                        "platform": {
                            "type": "string",
                            "description": "Filter by platform: facebook, instagram, or all.",
                        },
                        "since": {
                            "type": "string",
                            "description": "Start of date range (YYYY-MM-DD).",
                        },
                        "until": {
                            "type": "string",
                            "description": "End of date range (YYYY-MM-DD).",
                        },
                    },
                    "required": [],
                },
            },
            {
                "name": "cancel_scheduled_post",
                "description": "Cancel a scheduled post by its DB ID.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "post_id": {
                            "type": "integer",
                            "description": "DB ID of the scheduled post to cancel.",
                        }
                    },
                    "required": ["post_id"],
                },
            },
            # ----------------------------------------------------------
            # Document / file reading
            # ----------------------------------------------------------
            {
                "name": "read_google_doc",
                "description": (
                    "Read the full text content of a Google Doc by URL or document ID. "
                    "Use this to read copy documents, briefs, or strategy documents."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "doc_url_or_id": {
                            "type": "string",
                            "description": "Google Doc URL or document ID.",
                        }
                    },
                    "required": ["doc_url_or_id"],
                },
            },
            {
                "name": "read_google_sheet",
                "description": (
                    "Read data from a Google Sheet by URL or spreadsheet ID. "
                    "Returns rows as a list of lists."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sheet_url_or_id": {
                            "type": "string",
                            "description": "Google Sheets URL or spreadsheet ID.",
                        },
                        "sheet_name": {
                            "type": "string",
                            "description": "Sheet tab name. Defaults to the first sheet.",
                        },
                        "range": {
                            "type": "string",
                            "description": "A1 notation range, e.g. 'A1:Z100'. Omit for all data.",
                        },
                    },
                    "required": ["sheet_url_or_id"],
                },
            },
            {
                "name": "read_pdf",
                "description": (
                    "Extract and return the full text content of a PDF file. "
                    "Works with uploaded files or local paths."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Local file path to the PDF.",
                        }
                    },
                    "required": ["file_path"],
                },
            },
            {
                "name": "read_google_drive_folder",
                "description": (
                    "List files inside a Google Drive folder by URL. "
                    "Returns file names, types, and IDs. "
                    "Use this to inspect what images or documents are in a Drive folder "
                    "before calling upload_ads_from_drive."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "folder_url": {
                            "type": "string",
                            "description": "Google Drive folder URL (drive.google.com/drive/folders/...).",
                        }
                    },
                    "required": ["folder_url"],
                },
            },
            {
                "name": "search_drive",
                "description": (
                    "Search the user's Google Drive by name. Use this to FIND folders, "
                    "images/videos or caption documents when the user refers to them by "
                    "name instead of pasting a link (e.g. \"the June campaign folder\"). "
                    "Returns names and ready-to-use URLs for the other Drive tools."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Name (or part of it) to search for.",
                        },
                        "kind": {
                            "type": "string",
                            "enum": ["any", "folder", "media", "document"],
                            "description": "Restrict results to folders, media files or documents.",
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "prepare_upload_preview",
                "description": (
                    "Build an interactive upload preview card in the user's chat from "
                    "Google Drive content. Scans the given folders/files for images and "
                    "videos, parses the captions doc (including per-post schedule dates) "
                    "and fills the same preview the manual upload wizard shows, so the "
                    "user only has to review and press Publish. Use this whenever the "
                    "user asks you to set up, prepare, select or load posts from Drive. "
                    "Pass the destination page/instagram ids and names from your Active "
                    "Context when the user has named where to post."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "folder_urls": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Google Drive folder URLs holding the images/videos.",
                        },
                        "file_urls": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Individual Drive image/video file URLs to include.",
                        },
                        "captions_doc_url": {
                            "type": "string",
                            "description": "Google Doc/Sheet URL with captions (and optional schedule dates).",
                        },
                        "page_id": {"type": "string", "description": "Facebook page id to post to."},
                        "page_name": {"type": "string", "description": "Facebook page name."},
                        "instagram_id": {"type": "string", "description": "Instagram business account id to post to."},
                        "instagram_name": {"type": "string", "description": "Instagram account name."},
                        "portfolio_name": {
                            "type": "string",
                            "description": (
                                "Name of a saved Business Portfolio to post to — resolves to its "
                                "Facebook page + Instagram account automatically. Prefer this when "
                                "the user names a portfolio."
                            ),
                        },
                    },
                    "required": [],
                },
            },
            {
                "name": "list_business_portfolios",
                "description": (
                    "List the user's saved Business Portfolios (named groupings of a "
                    "Facebook page + Instagram account) with their page ids. Use this to "
                    "resolve a portfolio the user names into posting targets."
                ),
                "input_schema": {"type": "object", "properties": {}, "required": []},
            },
            {
                "name": "read_local_folder",
                "description": (
                    "Scan a local folder and list all image/video files inside it. "
                    "Use this before uploading ads from a folder."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "folder_path": {
                            "type": "string",
                            "description": "Absolute or relative path to the folder.",
                        },
                        "extensions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "File extensions to include, e.g. ['jpg', 'png']. "
                                "Defaults to all image and video types."
                            ),
                        },
                    },
                    "required": ["folder_path"],
                },
            },
            {
                "name": "match_post_story_pairs",
                "description": (
                    "Scan a folder and automatically match Post/Story image pairs by "
                    "filename. Files with 'Post' in the name are paired with files "
                    "containing 'Story' that share the same numeric prefix. "
                    "Returns matched pairs and unmatched files."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "folder_path": {
                            "type": "string",
                            "description": "Path to the folder containing the ad images.",
                        }
                    },
                    "required": ["folder_path"],
                },
            },
            # ----------------------------------------------------------
            # Google Drive upload
            # ----------------------------------------------------------
            {
                "name": "upload_ads_from_drive",
                "description": (
                    "Upload ads directly from Google Drive. "
                    "images_drive_url must be a Google Drive folder (containing Post/Story "
                    "image pairs) or a single image file URL. "
                    "text_drive_url must be a Google Doc, Google Sheet, or Drive text file "
                    "containing the ad copy. "
                    "Google Sheet format: columns Headline | Primary Text | Destination URL (optional) | CTA Type (optional). "
                    "Google Doc format: sections separated by '---', each with optional Headline:, Text:, URL: labels. "
                    "Images are paired automatically by filename (files containing 'Post'/'Story'). "
                    "Requires both Meta and Google accounts to be connected."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "images_drive_url": {
                            "type": "string",
                            "description": "Google Drive folder URL containing ad images, or a single image file URL.",
                        },
                        "text_drive_url": {
                            "type": "string",
                            "description": "Google Doc, Sheet, or Drive file URL with ad copy text.",
                        },
                        "ad_set_id": {
                            "type": "string",
                            "description": "Meta ad set ID to upload ads into.",
                        },
                        "page_id": {
                            "type": "string",
                            "description": "Facebook Page ID for the ad creatives.",
                        },
                        "destination_url": {
                            "type": "string",
                            "description": "Landing page URL used as the ad destination.",
                        },
                        "ad_account_id": {
                            "type": "string",
                            "description": "Meta ad account ID (e.g. 'act_123456'). Omit to use active context.",
                        },
                        "cta_type": {
                            "type": "string",
                            "description": "Call-to-action button type. Defaults to LEARN_MORE.",
                        },
                    },
                    "required": ["images_drive_url", "text_drive_url", "ad_set_id", "page_id", "destination_url"],
                },
            },
            {
                "name": "upload_video_ads_from_drive",
                "description": (
                    "Upload VIDEO ads directly from Google Drive. Streams each video straight "
                    "from Drive to Meta (no disk usage), waits for Meta to finish processing, "
                    "then builds a video creative + ad using the video's auto-generated thumbnail "
                    "as the cover image. "
                    "videos_drive_url must be a Google Drive folder of videos (.mp4/.mov/etc.) or "
                    "a single video file URL. "
                    "text_drive_url must be a Google Doc/Sheet with ad copy (same format as "
                    "upload_ads_from_drive). One ad is created per video, matched to copy in order. "
                    "Requires both Meta and Google accounts to be connected."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "videos_drive_url": {
                            "type": "string",
                            "description": "Google Drive folder URL containing videos, or a single video file URL.",
                        },
                        "text_drive_url": {
                            "type": "string",
                            "description": "Google Doc, Sheet, or Drive file URL with ad copy text.",
                        },
                        "ad_set_id": {
                            "type": "string",
                            "description": "Meta ad set ID to upload ads into.",
                        },
                        "page_id": {
                            "type": "string",
                            "description": "Facebook Page ID for the ad creatives.",
                        },
                        "destination_url": {
                            "type": "string",
                            "description": "Landing page URL used as the ad destination.",
                        },
                        "ad_account_id": {
                            "type": "string",
                            "description": "Meta ad account ID (e.g. 'act_123456'). Omit to use active context.",
                        },
                        "cta_type": {
                            "type": "string",
                            "description": "Call-to-action button type. Defaults to LEARN_MORE.",
                        },
                    },
                    "required": ["videos_drive_url", "text_drive_url", "ad_set_id", "page_id", "destination_url"],
                },
            },
        ]
