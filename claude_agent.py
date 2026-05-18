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
from typing import AsyncGenerator, Optional, Any

import time
from pathlib import Path
import anthropic
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

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

BASE_SYSTEM_PROMPT = """You are Uplinx — an expert Meta Ads manager and strategist \
built into a web app. You have deep knowledge of Facebook and Instagram advertising, \
campaign structure, creative best practices, audience targeting, budget optimisation, \
and performance analytics.

You are connected to the user's Meta account via the Graph API. All account IDs, \
tokens, pages, and pixels are already loaded — you NEVER need to ask for credentials.

## How to behave

**Be direct and action-oriented.**
- When the user gives an instruction, break it into steps and execute all of them.
- Ask only for information that is genuinely missing and cannot be inferred.
- Confirm before destructive actions (delete, pause all, bulk changes).

**Use context before calling tools.**
- The "Active Context" section below contains the selected Ad Account, Page, Pixel, \
Instagram account and timezone. Use those IDs directly.
- The "Available Accounts" section lists every ad account and page the user has access \
to. Use those for lookups — do NOT call list_ad_accounts or list_pages unless the user \
explicitly asks you to refresh the list.
- Only call a tool when you genuinely need live data (e.g. current campaign metrics, \
creating/editing objects, uploading ads).

**For ad uploads:**
- Always use upload_multiple_ads for multi-ad tasks.
- Match Post/Story image pairs by filename automatically.
- Apply naming conventions from active Skills if any are loaded.

**For analytics:**
- Always give actionable recommendations alongside raw numbers.
- Flag anomalies: high CPM, low ROAS, disapproved ads, budget pacing issues.

**When something fails:**
- Explain clearly what went wrong (API error message, missing permission, etc.).
- Suggest a concrete next step the user can take to resolve it.
- Never silently swallow errors."""

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
            self.max_tokens = 4096
            return

        if provider == "openai":
            from openai import AsyncOpenAI
            self._provider = "openai"
            self._openai_client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            self.model = settings.OPENAI_MODEL or "gpt-4o"
        elif provider == "groq":
            from openai import AsyncOpenAI
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

        self.max_tokens = 4096

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
        else:
            parts.append("\n## Active Context\nNo ad account selected yet. "
                         "The user should select one from the right panel, or you can list "
                         "available accounts from the Available Accounts section below.")

        # ── 2. Available accounts (cached, skipped when context is set) ───────
        # Only inject the full account list when no ad account is selected yet.
        # When the user has a context set, the AI already has the IDs it needs
        # above — fetching the full list every message wastes Meta API quota
        # and adds latency.  When we do fetch, results are cached for 10 min.
        context_complete = (
            ctx is not None
            and ctx.selected_ad_account_id
            and ctx.selected_page_id
        )
        try:
            uid = (session_data or {}).get("meta_user_id", "")
            if uid and not context_complete:
                enc = FernetEncryption()
                acc_result = await db.execute(
                    select(ConnectedMetaAccount).where(
                        ConnectedMetaAccount.facebook_user_id == uid,
                        ConnectedMetaAccount.is_active == True,
                    )
                )
                meta_acc = acc_result.scalar_one_or_none()
                if meta_acc:
                    token = enc.decrypt(meta_acc.encrypted_long_token)
                    cached = await _get_cached_meta_accounts(uid, token)
                    account_lines: list[str] = [
                        f"Connected as: {meta_acc.user_name or uid}"
                    ]
                    accounts = cached["ad_accounts"]
                    if accounts:
                        account_lines.append("\n**Ad Accounts:**")
                        for a in accounts[:30]:
                            account_lines.append(
                                f"  - {a.get('name', a.get('account_id', '?'))} "
                                f"| ID: {a.get('id','?')} "
                                f"| Currency: {a.get('currency','?')} "
                                f"| Timezone: {a.get('timezone_name','?')}"
                            )
                    pages = cached["pages"]
                    if pages:
                        account_lines.append("\n**Facebook Pages:**")
                        for p in pages[:20]:
                            account_lines.append(
                                f"  - {p.get('name','?')} | ID: {p.get('id','?')}"
                            )
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
                            (f" | Pixel: {aa.default_pixel_id}" if aa.default_pixel_id else "") +
                            (f" | TZ: {aa.default_timezone}" if aa.default_timezone else ""))
                    parts.append("\n".join(aa_lines))
            except Exception as exc:
                logger.debug("Could not load client ad accounts: %s", exc)

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

        # 2. Load history
        try:
            history = await self.get_conversation_messages(
                conversation_id, db, limit=10
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

        tool_definitions = self.get_tool_definitions()
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
                    async with self.client.messages.stream(
                        model=self.model,
                        max_tokens=self.max_tokens,
                        system=cached_system,
                        messages=messages,
                        tools=tool_definitions,
                        extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
                    ) as stream:
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
                    async for chunk in await self._openai_client.chat.completions.create(
                        model=self.model,
                        max_tokens=self.max_tokens,
                        messages=oai_messages,
                        tools=oai_tools if oai_tools else None,
                        tool_choice="auto" if oai_tools else None,
                        stream=True,
                        stream_options={"include_usage": True},
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
                yield _sse({"type": "error", "message": "Connection to Claude failed. Please retry."})
                return
            except anthropic.RateLimitError as exc:
                logger.error("Anthropic rate limit: %s", exc)
                yield _sse({"type": "error", "message": "Rate limit reached. Please wait a moment and retry."})
                return
            except anthropic.APIStatusError as exc:
                logger.error("Anthropic API error %d: %s", exc.status_code, exc.message)
                yield _sse({"type": "error", "message": f"Claude API error ({exc.status_code}): {exc.message}"})
                return
            except Exception as exc:
                # Catch OpenAI/Groq SDK errors and any other unexpected errors
                err_str = str(exc)
                logger.error("Error in stream_response: %s", err_str, exc_info=True)
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

        try:
            # Import lazily to avoid circular imports at module load time
            import mcp_server  # type: ignore[import]

            handler = getattr(mcp_server, tool_name, None)
            if handler is None:
                return json.dumps({"error": f"Unknown tool: {tool_name}"})

            # MCP tools use session_id (facebook_user_id) to look up tokens
            # themselves — do NOT pass db/session_data as kwargs.
            call_kwargs = dict(tool_input)
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
                    "Permanently delete a Meta campaign. "
                    "Always confirm with the user before calling this."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "campaign_id": {
                            "type": "string",
                            "description": "Campaign ID to delete.",
                        }
                    },
                    "required": ["campaign_id"],
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
        ]
