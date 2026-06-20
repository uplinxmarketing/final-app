"""
leadsales_gcal.py — Google Calendar (read-only) helper for the CRM module ONLY.

Uses a DEDICATED OAuth client (CRM_GOOGLE_CLIENT_ID / CRM_GOOGLE_CLIENT_SECRET)
so it is fully separate from the posting app's Google connection. If the
dedicated client is not configured it falls back to the shared GOOGLE_CLIENT_ID
so the feature still works, but the Settings screen reports which is in use.

Scope is restricted to calendar.events.readonly — the CRM can only READ your
upcoming events; it can never create, edit or delete anything in your Google
Calendar. (In-app events live in the separate ls_events table.)

Token exchange/refresh/userinfo reuse the shared, read-only-guarded helpers in
google_api.py; only the calendar event listing is added here.
"""
from __future__ import annotations

import logging
import os
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

import google_api

logger = logging.getLogger("uplinx.leadsales")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
CALENDAR_API = "https://www.googleapis.com/calendar/v3"

# Read-only calendar access + identity, nothing else.
CRM_GOOGLE_SCOPES = " ".join([
    "openid", "email",
    "https://www.googleapis.com/auth/calendar.events.readonly",
])


def oauth_config() -> dict:
    """Resolve which Google OAuth client the CRM should use.

    Returns dict: {client_id, client_secret, configured: bool, source: str}
    source ∈ {'dedicated', 'shared', ''}.
    """
    cid = (os.environ.get("CRM_GOOGLE_CLIENT_ID") or "").strip()
    csec = (os.environ.get("CRM_GOOGLE_CLIENT_SECRET") or "").strip()
    if cid and csec:
        return {"client_id": cid, "client_secret": csec, "configured": True, "source": "dedicated"}
    # Fallback so the feature still works if a dedicated client isn't set yet.
    cid = (os.environ.get("GOOGLE_CLIENT_ID") or "").strip()
    csec = (os.environ.get("GOOGLE_CLIENT_SECRET") or "").strip()
    if cid and csec:
        return {"client_id": cid, "client_secret": csec, "configured": True, "source": "shared"}
    return {"client_id": "", "client_secret": "", "configured": False, "source": ""}


def build_auth_url(redirect_uri: str, state: str) -> str:
    cfg = oauth_config()
    params = urllib.parse.urlencode({
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "scope": CRM_GOOGLE_SCOPES,
        "response_type": "code",
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
    })
    return f"{GOOGLE_AUTH_URL}?{params}"


async def exchange_code(code: str, redirect_uri: str) -> dict[str, Any]:
    cfg = oauth_config()
    return await google_api.exchange_code_for_tokens(
        code, cfg["client_id"], cfg["client_secret"], redirect_uri
    )


async def refresh_access_token(refresh_token: str) -> dict[str, Any]:
    cfg = oauth_config()
    return await google_api.refresh_access_token(
        refresh_token, cfg["client_id"], cfg["client_secret"]
    )


async def get_user_info(access_token: str) -> dict[str, Any]:
    return await google_api.get_user_info(access_token)


def _parse_event_time(node: dict | None) -> tuple[Optional[str], bool]:
    """Return (iso_string, all_day) from a Google event start/end node."""
    if not node:
        return None, False
    if node.get("dateTime"):
        return node["dateTime"], False
    if node.get("date"):
        # All-day event — represent at local midnight.
        return node["date"] + "T00:00:00", True
    return None, False


async def list_events(
    access_token: str,
    time_min: datetime,
    time_max: datetime,
    max_results: int = 50,
) -> list[dict]:
    """List upcoming primary-calendar events in the window. Read-only GET."""
    params = {
        "timeMin": time_min.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "timeMax": time_max.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "singleEvents": "true",
        "orderBy": "startTime",
        "maxResults": str(max_results),
    }
    url = f"{CALENDAR_API}/calendars/primary/events"
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(
            url, params=params, headers={"Authorization": f"Bearer {access_token}"}
        )
        resp.raise_for_status()
        data = resp.json()

    out: list[dict] = []
    for ev in data.get("items", []):
        if ev.get("status") == "cancelled":
            continue
        start_iso, all_day = _parse_event_time(ev.get("start"))
        end_iso, _ = _parse_event_time(ev.get("end"))
        if not start_iso:
            continue
        out.append({
            "source": "google",
            "id": ev.get("id", ""),
            "title": ev.get("summary") or "(no title)",
            "start_at": start_iso,
            "end_at": end_iso,
            "location": ev.get("location"),
            "description": ev.get("description"),
            "html_link": ev.get("htmlLink"),
            "all_day": all_day,
            "lead_id": None,
        })
    return out
