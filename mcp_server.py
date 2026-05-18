"""
MCP Server for Uplinx Meta Manager.
All Meta advertising tools exposed to the Claude AI agent.
"""
import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP

from config import settings
from database import AsyncSessionLocal, ConnectedMetaAccount, ActiveContext, ImageCache, ConnectedGoogleAccount
from security import FernetEncryption
import meta_api
import google_api
import file_processor

logger = logging.getLogger("uplinx")
mcp = FastMCP("uplinx-meta-manager")
encryption = FernetEncryption()


# ── Session helpers ────────────────────────────────────────────────────────────

async def get_meta_token_for_session(session_id: str) -> Optional[str]:
    """Look up and decrypt the Meta token for the given facebook_user_id."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(
            select(ConnectedMetaAccount).where(
                ConnectedMetaAccount.facebook_user_id == session_id,
                ConnectedMetaAccount.is_active == True,
            )
        )
        acc = result.scalar_one_or_none()
        if acc:
            return encryption.decrypt(acc.encrypted_long_token)
    return None


async def get_google_token_for_session(session_id: str) -> Optional[str]:
    """Look up and decrypt the Google token for the given google_user_id."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(
            select(ConnectedGoogleAccount).where(
                ConnectedGoogleAccount.google_user_id == session_id,
                ConnectedGoogleAccount.is_active == True,
            )
        )
        acc = result.scalar_one_or_none()
        if acc:
            return encryption.decrypt(acc.encrypted_access_token)
    return None


async def check_image_cache(sha256: str, ad_account_id: str) -> Optional[str]:
    """Return cached Meta image hash if it exists."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(
            select(ImageCache).where(
                ImageCache.file_sha256 == sha256,
                ImageCache.ad_account_id == ad_account_id,
            )
        )
        row = result.scalar_one_or_none()
        return row.meta_image_hash if row else None


async def store_image_cache(sha256: str, filename: str, meta_hash: str, ad_account_id: str) -> None:
    """Store image hash mapping in cache."""
    async with AsyncSessionLocal() as db:
        cache_entry = ImageCache(
            file_sha256=sha256,
            file_name=filename,
            meta_image_hash=meta_hash,
            ad_account_id=ad_account_id,
            uploaded_at=datetime.utcnow(),
        )
        db.add(cache_entry)
        await db.commit()


def _fmt(result: dict) -> str:
    """Format an API result dict as a readable string for Claude."""
    if result.get("success"):
        data = result.get("data", result.get("content", result.get("rows", "")))
        if isinstance(data, (dict, list)):
            return json.dumps(data, indent=2, default=str)
        return str(data)
    return f"Error: {result.get('error', 'Unknown error')}"


# ── Account discovery tools ────────────────────────────────────────────────────

@mcp.tool()
async def list_ad_accounts(session_id: str) -> str:
    """List all Meta ad accounts accessible to the connected user."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected for this session."
    result = await meta_api.get_ad_accounts(token)
    return _fmt(result)


@mcp.tool()
async def list_pages(session_id: str) -> str:
    """List all Facebook Pages the user manages."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    result = await meta_api.get_pages(token)
    return _fmt(result)


@mcp.tool()
async def list_instagram_accounts(session_id: str, page_id: str) -> str:
    """List Instagram accounts linked to a Facebook Page."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    result = await meta_api.get_instagram_accounts(token, page_id)
    return _fmt(result)


@mcp.tool()
async def list_pixels(session_id: str, ad_account_id: str) -> str:
    """List Meta Pixels for an ad account."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    result = await meta_api.get_pixels(token, ad_account_id)
    return _fmt(result)


@mcp.tool()
async def get_ad_accounts_with_all_assets(session_id: str) -> str:
    """Get all ad accounts with pages, pixels, and Instagram accounts in one call."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    accounts_r, pages_r = await asyncio.gather(
        meta_api.get_ad_accounts(token),
        meta_api.get_pages(token),
    )
    accounts = accounts_r.get("data", {}).get("data", []) if accounts_r.get("success") else []
    pages = pages_r.get("data", {}).get("data", []) if pages_r.get("success") else []

    # Fetch pixels + instagram in parallel for each account/page
    pixel_tasks = [meta_api.get_pixels(token, a["id"]) for a in accounts]
    ig_tasks = [meta_api.get_instagram_accounts(token, p["id"]) for p in pages]
    pixel_results, ig_results = await asyncio.gather(
        asyncio.gather(*pixel_tasks) if pixel_tasks else asyncio.sleep(0),
        asyncio.gather(*ig_tasks) if ig_tasks else asyncio.sleep(0),
    )

    for i, acc in enumerate(accounts):
        acc["pixels"] = pixel_results[i].get("data", {}).get("data", []) if pixel_tasks and pixel_results[i].get("success") else []
    for i, page in enumerate(pages):
        page["instagram_accounts"] = ig_results[i].get("data", {}).get("data", []) if ig_tasks and ig_results[i].get("success") else []

    return json.dumps({"ad_accounts": accounts, "pages": pages}, indent=2, default=str)


# ── Campaign tools ─────────────────────────────────────────────────────────────

@mcp.tool()
async def create_campaign(
    session_id: str,
    ad_account_id: str,
    name: str,
    objective: str,
    daily_budget_euros: float,
    status: str = "ACTIVE",
) -> str:
    """Create a new Meta ad campaign. Objective options: OUTCOME_SALES, OUTCOME_LEADS, OUTCOME_AWARENESS, OUTCOME_TRAFFIC, OUTCOME_ENGAGEMENT."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    daily_budget_cents = int(daily_budget_euros * 100)
    result = await meta_api.create_campaign(token, ad_account_id, name, objective, status)
    return _fmt(result)


@mcp.tool()
async def get_campaigns(session_id: str, ad_account_id: str) -> str:
    """List all campaigns for an ad account."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    result = await meta_api.get_campaigns(token, ad_account_id)
    return _fmt(result)


@mcp.tool()
async def pause_campaign(session_id: str, campaign_id: str) -> str:
    """Pause an active campaign."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    result = await meta_api.pause_campaign(token, campaign_id)
    return _fmt(result)


@mcp.tool()
async def activate_campaign(session_id: str, campaign_id: str) -> str:
    """Activate a paused campaign."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    result = await meta_api.activate_campaign(token, campaign_id)
    return _fmt(result)


@mcp.tool()
async def delete_campaign(session_id: str, campaign_id: str) -> str:
    """Delete a campaign permanently."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    result = await meta_api.delete_campaign(token, campaign_id)
    return _fmt(result)


# ── Ad set tools ───────────────────────────────────────────────────────────────

@mcp.tool()
async def create_ad_set(
    session_id: str,
    campaign_id: str,
    name: str,
    daily_budget_euros: float,
    countries: list[str],
    age_min: int,
    age_max: int,
    optimization_goal: str,
    pixel_id: Optional[str] = None,
    ad_account_id: Optional[str] = None,
) -> str:
    """Create an ad set within a campaign. countries: 2-letter codes e.g. ['ES','IT']. optimization_goal: OFFSITE_CONVERSIONS, LINK_CLICKS, IMPRESSIONS, REACH."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    if not ad_account_id:
        return "Error: ad_account_id is required."
    daily_budget_cents = int(daily_budget_euros * 100)
    result = await meta_api.create_ad_set(
        token, ad_account_id, campaign_id, name,
        daily_budget_cents, countries, age_min, age_max,
        pixel_id, optimization_goal,
    )
    return _fmt(result)


# ── Ad upload tools ────────────────────────────────────────────────────────────

@mcp.tool()
async def upload_single_ad(
    session_id: str,
    ad_set_id: str,
    ad_name: str,
    post_image_filename: str,
    story_image_filename: str,
    headline: str,
    primary_text: str,
    destination_url: str,
    page_id: str,
    cta_type: str = "LEARN_MORE",
    ad_account_id: Optional[str] = None,
) -> str:
    """Upload a single ad with Post (Feed) and Story images. Deduplicates images via SHA256 cache."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    if not ad_account_id:
        return "Error: ad_account_id is required."

    results = []
    for img_path, placement_label in [(post_image_filename, "Post"), (story_image_filename, "Story")]:
        p = Path(img_path)
        if not p.exists():
            results.append(f"Warning: {placement_label} image not found: {img_path}")
            continue

        sha256 = await file_processor.compute_sha256(img_path)
        cached_hash = await check_image_cache(sha256, ad_account_id)

        if cached_hash:
            image_hash = cached_hash
        else:
            upload_r = await meta_api.upload_image(token, ad_account_id, img_path)
            if not upload_r.get("success"):
                results.append(f"Error uploading {placement_label}: {upload_r.get('error')}")
                continue
            image_hash = upload_r["data"]
            await store_image_cache(sha256, p.name, image_hash, ad_account_id)

        creative_r = await meta_api.create_ad_creative(
            token, ad_account_id, page_id, image_hash,
            headline, primary_text, destination_url, cta_type,
        )
        if not creative_r.get("success"):
            results.append(f"Error creating {placement_label} creative: {creative_r.get('error')}")
            continue

        creative_id = creative_r["data"].get("id", "")
        ad_r = await meta_api.create_ad(
            token, ad_account_id, ad_set_id, creative_id,
            f"{ad_name} {placement_label}", "ACTIVE",
        )
        if ad_r.get("success"):
            results.append(f"{placement_label} ad created: {ad_r['data'].get('id')}")
        else:
            results.append(f"Error creating {placement_label} ad: {ad_r.get('error')}")

    return "\n".join(results)


@mcp.tool()
async def upload_multiple_ads(
    session_id: str,
    ad_set_id: str,
    ads_config: str,
    page_id: str,
    ad_account_id: Optional[str] = None,
) -> str:
    """Upload multiple ads. ads_config: JSON list of {ad_name, post_image, story_image, headline, primary_text, destination_url}."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    if not ad_account_id:
        return "Error: ad_account_id is required."

    try:
        configs = json.loads(ads_config)
    except json.JSONDecodeError:
        return "Error: ads_config must be valid JSON."

    results = []
    for cfg in configs:
        r = await upload_single_ad(
            session_id,
            ad_set_id,
            cfg.get("ad_name", "Ad"),
            cfg.get("post_image", ""),
            cfg.get("story_image", ""),
            cfg.get("headline", ""),
            cfg.get("primary_text", ""),
            cfg.get("destination_url", ""),
            page_id,
            cfg.get("cta_type", "LEARN_MORE"),
            ad_account_id,
        )
        results.append(r)

    return "\n\n".join(results)


@mcp.tool()
async def upload_ads_from_folder(
    session_id: str,
    ad_set_id: str,
    folder_path: str,
    copy_source: str,
    page_id: str,
    destination_url: str,
    ad_account_id: Optional[str] = None,
) -> str:
    """Scan folder for Post/Story pairs and upload all as ads. copy_source contains the ad copy text."""
    pairs_result = await file_processor.match_post_story_pairs(folder_path)
    if not pairs_result.get("success"):
        return f"Error scanning folder: {pairs_result.get('error')}"
    pairs = pairs_result.get("pairs", [])
    if not pairs:
        return "No Post/Story image pairs found in folder."

    results = [f"Found {len(pairs)} ad pairs. Uploading..."]
    for pair in pairs:
        r = await upload_single_ad(
            session_id,
            ad_set_id,
            pair.get("ad_name", f"Ad {pair.get('number', '')}"),
            pair.get("post_file", ""),
            pair.get("story_file", ""),
            f"Ad {pair.get('number', '')}",
            copy_source[:500],
            destination_url,
            page_id,
            "LEARN_MORE",
            ad_account_id,
        )
        results.append(r)

    return "\n\n".join(results)


# ── Analytics tools ────────────────────────────────────────────────────────────

@mcp.tool()
async def get_performance_report(
    session_id: str,
    ad_account_id: str,
    date_range: str = "last_7d",
    breakdown: str = "campaign",
) -> str:
    """Get performance report. date_range: last_7d, last_30d, this_month, or YYYY-MM-DD:YYYY-MM-DD."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."

    if ":" in date_range:
        since, until = date_range.split(":", 1)
        dr = {"since": since, "until": until}
    else:
        dr = {"date_preset": date_range}

    result = await meta_api.get_account_insights(token, ad_account_id, dr)
    return _fmt(result)


@mcp.tool()
async def get_campaign_performance(
    session_id: str,
    campaign_id: str,
    date_range: str = "last_7d",
) -> str:
    """Get detailed performance for a specific campaign."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    if ":" in date_range:
        since, until = date_range.split(":", 1)
        dr = {"since": since, "until": until}
    else:
        dr = {"date_preset": date_range}
    result = await meta_api.get_campaign_insights(token, campaign_id, dr)
    return _fmt(result)


@mcp.tool()
async def compare_campaigns(
    session_id: str,
    campaign_ids: str,
    date_range: str = "last_7d",
) -> str:
    """Compare performance across multiple campaigns side by side."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    try:
        ids = json.loads(campaign_ids)
    except json.JSONDecodeError:
        return "Error: campaign_ids must be a JSON list."
    if ":" in date_range:
        since, until = date_range.split(":", 1)
        dr = {"since": since, "until": until}
    else:
        dr = {"date_preset": date_range}
    tasks = [meta_api.get_campaign_insights(token, cid, dr) for cid in ids]
    results = await asyncio.gather(*tasks)
    output = []
    for cid, r in zip(ids, results):
        output.append(f"Campaign {cid}:\n{_fmt(r)}")
    return "\n\n".join(output)


# ── Scheduling tools ───────────────────────────────────────────────────────────

@mcp.tool()
async def schedule_post(
    session_id: str,
    platform: str,
    page_id: str,
    caption: str,
    media_filename: str,
    scheduled_datetime: str,
    timezone: str = "UTC",
) -> str:
    """Schedule a post on Facebook or Instagram. platform: 'facebook' or 'instagram'. scheduled_datetime: ISO 8601 e.g. 2024-12-25T10:00:00."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    try:
        from datetime import timezone as tz
        import calendar
        dt = datetime.fromisoformat(scheduled_datetime)
        scheduled_ts = int(calendar.timegm(dt.timetuple()))
    except ValueError:
        return f"Error: Invalid datetime format '{scheduled_datetime}'. Use ISO 8601."

    media_path: Optional[str] = media_filename if Path(media_filename).exists() else None

    if platform.lower() == "facebook":
        result = await meta_api.schedule_facebook_post(token, page_id, caption, media_path, scheduled_ts)
    elif platform.lower() == "instagram":
        if not media_path:
            return "Error: Instagram posts require a valid media file."
        result = await meta_api.schedule_instagram_post(token, page_id, caption, media_path, scheduled_ts)
    else:
        return f"Error: Unknown platform '{platform}'. Use 'facebook' or 'instagram'."
    return _fmt(result)


@mcp.tool()
async def schedule_reel(
    session_id: str,
    platform: str,
    page_id: str,
    caption: str,
    video_filename: str,
    scheduled_datetime: str,
    timezone: str = "UTC",
) -> str:
    """Schedule a Reel on Facebook or Instagram."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    try:
        import calendar
        dt = datetime.fromisoformat(scheduled_datetime)
        scheduled_ts = int(calendar.timegm(dt.timetuple()))
    except ValueError:
        return f"Error: Invalid datetime '{scheduled_datetime}'."
    if platform.lower() == "facebook":
        result = await meta_api.schedule_facebook_reel(token, page_id, video_filename, caption, scheduled_ts)
    else:
        result = await meta_api.schedule_instagram_reel(token, page_id, video_filename, caption, scheduled_ts)
    return _fmt(result)


@mcp.tool()
async def schedule_bulk_posts(session_id: str, posts_config: str) -> str:
    """Schedule multiple posts. posts_config: JSON list of post configs."""
    try:
        configs = json.loads(posts_config)
    except json.JSONDecodeError:
        return "Error: posts_config must be valid JSON."
    results = []
    for cfg in configs:
        r = await schedule_post(
            session_id,
            cfg.get("platform", "facebook"),
            cfg.get("page_id", ""),
            cfg.get("caption", ""),
            cfg.get("media_filename", ""),
            cfg.get("scheduled_datetime", ""),
            cfg.get("timezone", "UTC"),
        )
        results.append(r)
    return "\n\n".join(results)


@mcp.tool()
async def get_scheduled_posts(session_id: str, page_id: str) -> str:
    """List all scheduled posts for a Facebook Page."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    result = await meta_api.get_scheduled_posts(token, page_id)
    return _fmt(result)


@mcp.tool()
async def cancel_scheduled_post(session_id: str, post_id: str) -> str:
    """Cancel (delete) a scheduled post."""
    token = await get_meta_token_for_session(session_id)
    if not token:
        return "Error: Meta account not connected."
    result = await meta_api.delete_scheduled_post(token, post_id)
    return _fmt(result)


# ── File processing tools ──────────────────────────────────────────────────────

@mcp.tool()
async def read_google_doc(session_id: str, url_or_id: str) -> str:
    """Read content from a Google Doc by URL or document ID."""
    token = await get_google_token_for_session(session_id)
    if not token:
        return "Error: Google account not connected."

    doc_id = google_api.extract_doc_id_from_url(url_or_id) or url_or_id
    result = await google_api.read_google_doc(doc_id, token)
    if result.get("success"):
        return f"Title: {result.get('title', '')}\n\n{result.get('content', '')}"
    return f"Error: {result.get('error')}"


@mcp.tool()
async def read_google_sheet(session_id: str, url_or_id: str) -> str:
    """Read content from a Google Sheet."""
    token = await get_google_token_for_session(session_id)
    if not token:
        return "Error: Google account not connected."
    sheet_id = google_api.extract_sheet_id_from_url(url_or_id) or url_or_id
    result = await google_api.read_google_sheet(sheet_id, token)
    if result.get("success"):
        rows = result.get("rows", [])
        lines = ["\t".join(str(c) for c in row) for row in rows]
        return f"Title: {result.get('title', '')}\n\n" + "\n".join(lines)
    return f"Error: {result.get('error')}"


@mcp.tool()
async def read_pdf(session_id: str, file_path_or_url: str) -> str:
    """Extract text from a PDF file (local path or Google Drive URL)."""
    if file_path_or_url.startswith("http"):
        token = await get_google_token_for_session(session_id)
        if token:
            file_id = google_api.extract_file_id_from_url(file_path_or_url)
            if file_id:
                dl = await google_api.download_drive_file(file_id, token)
                if dl.get("success"):
                    tmp_path = f"uploads/temp_{file_id}.pdf"
                    Path(tmp_path).write_bytes(dl["bytes"])
                    result = await file_processor.extract_pdf_text(tmp_path)
                    Path(tmp_path).unlink(missing_ok=True)
                    if result.get("success"):
                        return result.get("text", "")
                    return f"Error: {result.get('error')}"
        return "Error: Could not download PDF from URL."

    result = await file_processor.extract_pdf_text(file_path_or_url)
    if result.get("success"):
        return result.get("text", "")
    return f"Error: {result.get('error')}"


@mcp.tool()
async def read_local_folder(
    session_id: str,
    folder_path: str,
    extensions: Optional[str] = None,
) -> str:
    """List files in a local folder. extensions: comma-separated list e.g. 'jpg,png,pdf'."""
    ext_list: Optional[list[str]] = None
    if extensions:
        ext_list = [e.strip().lstrip(".") for e in extensions.split(",")]
    result = await file_processor.scan_folder(folder_path, ext_list)
    if not result.get("success"):
        return f"Error: {result.get('error')}"
    files = result.get("files", [])
    if not files:
        return "No matching files found in folder."
    lines = [f"{f['name']} ({f['extension']}, {f['size']} bytes)" for f in files]
    return f"Found {len(files)} file(s) in {folder_path}:\n" + "\n".join(lines)


@mcp.tool()
async def match_post_story_pairs(session_id: str, folder_path: str) -> str:
    """Scan a folder and match Post/Story image pairs by filename convention."""
    result = await file_processor.match_post_story_pairs(folder_path)
    if not result.get("success"):
        return f"Error: {result.get('error')}"
    pairs = result.get("pairs", [])
    unmatched = result.get("unmatched", [])
    lines = [f"Matched {len(pairs)} pair(s):"]
    for p in pairs:
        lines.append(f"  {p.get('ad_name')}: Post={Path(p.get('post_file','')).name}, Story={Path(p.get('story_file','')).name}")
    if unmatched:
        lines.append(f"\nUnmatched files ({len(unmatched)}):")
        for u in unmatched:
            lines.append(f"  {Path(u).name}")
    return "\n".join(lines)


# ── Cross-account tool ─────────────────────────────────────────────────────────

@mcp.tool()
async def run_on_multiple_accounts(
    session_id: str,
    account_ids: str,
    task_description: str,
) -> str:
    """Run a task description across multiple ad accounts. account_ids: JSON list of account ID strings."""
    try:
        ids = json.loads(account_ids)
    except json.JSONDecodeError:
        return "Error: account_ids must be a JSON list."
    results = [f"Running task on {len(ids)} account(s): {task_description}\n"]
    for aid in ids:
        campaigns_r = await get_campaigns(session_id, aid)
        results.append(f"\nAccount {aid}:\n{campaigns_r}")
    return "\n".join(results)


if __name__ == "__main__":
    mcp.run()
