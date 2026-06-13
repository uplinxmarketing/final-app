import asyncio
import hashlib
import httpx
import json
import logging
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode

logger = logging.getLogger("uplinx")
BASE_URL = "https://graph.facebook.com/v21.0"

# Meta API error codes that indicate rate limiting
_RATE_LIMIT_CODES = {4, 17, 32, 341, 80000, 80001, 80002, 80003}

# Transient service errors — retry with short backoff (code 1 = unknown error,
# code 2 = "Please retry your request later")
_TRANSIENT_CODES = {1, 2}


# ---------------------------------------------------------------------------
# Private helper
# ---------------------------------------------------------------------------

async def _api_request(
    method: str,
    url: str,
    retries: int = 4,
    **kwargs: Any,
) -> dict[str, Any]:
    """Make an HTTP request with retry logic.

    - Uses httpx.AsyncClient with a 30-second timeout.
    - Retries up to `retries` times with exponential back-off (1s, 2s, 4s …).
    - On Meta rate-limit errors (codes 17, 32, 80000-80003) waits 60 s then
      retries (consuming one retry slot).
    - Logs each attempt at DEBUG level.
    - Returns ``{"success": True, "data": <response json>}`` on success or
      ``{"success": False, "error": "<message>"}`` on final failure.
    """
    last_error: str = "Unknown error"

    for attempt in range(retries):
        wait = 2 ** attempt  # 1, 2, 4 …
        logger.debug(
            "API %s %s – attempt %d/%d", method.upper(), url, attempt + 1, retries
        )
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.request(method, url, **kwargs)

            # Try to parse JSON regardless of status code so we can inspect
            # Meta error objects.
            try:
                body: Any = response.json()
            except Exception:
                body = response.text

            # Inspect for Meta error envelope
            if isinstance(body, dict) and "error" in body:
                err_obj = body["error"]
                code = err_obj.get("code", 0) if isinstance(err_obj, dict) else 0
                message = (
                    err_obj.get("message", str(err_obj))
                    if isinstance(err_obj, dict)
                    else str(err_obj)
                )

                if code in _RATE_LIMIT_CODES:
                    logger.warning(
                        "Meta rate-limit (code %s) on %s – waiting 60s …", code, url
                    )
                    await asyncio.sleep(60)
                    last_error = f"Rate limit (code {code}): {message}"
                    continue  # retry

                if code in _TRANSIENT_CODES:
                    logger.warning(
                        "Meta transient error (code %s) on %s – waiting 8s …", code, url
                    )
                    await asyncio.sleep(8)
                    last_error = f"Transient error (code {code}): {message}"
                    continue  # retry

                # Non-retriable API error
                return {"success": False, "error": f"Meta API error {code}: {message}"}

            if response.is_success:
                return {"success": True, "data": body}

            # HTTP error without a Meta error envelope
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"
            logger.warning("Request failed (%s), attempt %d/%d", last_error, attempt + 1, retries)

        except httpx.TimeoutException as exc:
            last_error = f"Timeout: {exc}"
            logger.warning("Timeout on %s, attempt %d/%d", url, attempt + 1, retries)
        except httpx.RequestError as exc:
            last_error = f"Request error: {exc}"
            logger.warning("Request error on %s, attempt %d/%d: %s", url, attempt + 1, retries, exc)

        if attempt < retries - 1:
            await asyncio.sleep(wait)

    return {"success": False, "error": last_error}


# ---------------------------------------------------------------------------
# Token Management
# ---------------------------------------------------------------------------

async def exchange_code_for_token(
    code: str,
    app_id: str,
    app_secret: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange an OAuth authorisation code for a short-lived access token."""
    url = f"{BASE_URL}/oauth/access_token"
    result = await _api_request(
        "POST",
        url,
        data={
            "client_id": app_id,
            "client_secret": app_secret,
            "redirect_uri": redirect_uri,
            "code": code,
        },
    )
    return result


async def exchange_for_long_lived_token(
    short_token: str,
    app_id: str,
    app_secret: str,
) -> dict[str, Any]:
    """Exchange a short-lived token for a long-lived user access token."""
    url = f"{BASE_URL}/oauth/access_token"
    result = await _api_request(
        "GET",
        url,
        params={
            "grant_type": "fb_exchange_token",
            "client_id": app_id,
            "client_secret": app_secret,
            "fb_exchange_token": short_token,
        },
    )
    return result


async def get_user_info(token: str) -> dict[str, Any]:
    """Return basic profile info for the token owner."""
    url = f"{BASE_URL}/me"
    return await _api_request(
        "GET",
        url,
        params={"fields": "id,name,email", "access_token": token},
    )


# ---------------------------------------------------------------------------
# Account & Asset Discovery
# ---------------------------------------------------------------------------

async def get_ad_accounts(token: str) -> dict[str, Any]:
    """List all ad accounts accessible by the token owner."""
    url = f"{BASE_URL}/me/adaccounts"
    return await _api_request(
        "GET",
        url,
        params={
            "fields": "id,name,account_id,currency,timezone_name",
            "access_token": token,
        },
    )


async def get_pages(token: str) -> dict[str, Any]:
    """List all Facebook Pages managed by the token owner (handles pagination)."""
    url = f"{BASE_URL}/me/accounts"
    all_pages: list[Any] = []
    params: dict[str, Any] = {
        "fields": "id,name,access_token,category,picture{url},instagram_business_account{id,name,username,profile_picture_url}",
        "access_token": token,
        "limit": "200",
    }

    while True:
        result = await _api_request("GET", url, params=params)
        if not result.get("success"):
            if not all_pages:
                return result
            break
        body = result["data"]
        all_pages.extend(body.get("data", []))
        next_url = body.get("paging", {}).get("next")
        if not next_url:
            break
        # The next cursor URL already contains all query params
        url = next_url
        params = {}

    return {"success": True, "data": {"data": all_pages}}


async def get_page_access_token(user_token: str, page_id: str) -> Optional[str]:
    """Fetch the page-scoped access token for a given page ID."""
    r = await _api_request(
        "GET",
        f"{BASE_URL}/{page_id}",
        params={"fields": "access_token", "access_token": user_token},
    )
    if r.get("success"):
        return r["data"].get("access_token")
    return None


async def get_instagram_accounts(
    token: str,
    page_id: str,
    page_token: Optional[str] = None,
) -> dict[str, Any]:
    """Return Instagram account(s) connected to a Facebook Page.

    ``page_token`` should be the page-scoped access token when available;
    falls back to ``token`` (user token) so existing callers still work.
    Always returns {"success": True, "data": {"data": [...]}} shape.
    """
    effective_token = page_token or token

    # Method 1 – instagram_business_account field (requires page token)
    r1 = await _api_request(
        "GET",
        f"{BASE_URL}/{page_id}",
        params={"fields": "instagram_business_account{id,username}", "access_token": effective_token},
    )
    if r1.get("success"):
        ig = r1["data"].get("instagram_business_account")
        if ig and ig.get("id"):
            return {"success": True, "data": {"data": [{"id": ig["id"], "username": ig.get("username", ig["id"])}]}}

    # Method 2 – retry with user token if page token didn't work
    if page_token and page_token != token:
        r1b = await _api_request(
            "GET",
            f"{BASE_URL}/{page_id}",
            params={"fields": "instagram_business_account{id,username}", "access_token": token},
        )
        if r1b.get("success"):
            ig = r1b["data"].get("instagram_business_account")
            if ig and ig.get("id"):
                return {"success": True, "data": {"data": [{"id": ig["id"], "username": ig.get("username", ig["id"])}]}}

    # Method 3 – legacy edge (requires instagram_basic permission)
    r2 = await _api_request(
        "GET",
        f"{BASE_URL}/{page_id}/instagram_accounts",
        params={"fields": "id,username", "access_token": effective_token},
    )
    if r2.get("success") and r2["data"].get("data"):
        return r2

    return {"success": True, "data": {"data": []}}


async def get_pixels(token: str, ad_account_id: str) -> dict[str, Any]:
    """List Meta pixels accessible for an ad account.

    Tries the direct adspixels edge first (pixels owned by or shared with the
    ad account), then falls back to any Business Manager the user manages so
    that BM-owned pixels are also returned.
    """
    url = f"{BASE_URL}/act_{ad_account_id}/adspixels"
    r1 = await _api_request(
        "GET",
        url,
        params={"fields": "id,name", "access_token": token, "limit": "200"},
    )
    if r1.get("success") and r1["data"].get("data"):
        return r1

    # Fallback: fetch pixels via all accessible Business Managers
    biz_result = await _api_request(
        "GET",
        f"{BASE_URL}/me/businesses",
        params={"fields": "id,name", "access_token": token, "limit": "50"},
    )
    all_pixels: list[Any] = []
    seen_ids: set[str] = set()

    # Include any pixels already found in r1
    if r1.get("success"):
        for px in r1["data"].get("data", []):
            if px.get("id") not in seen_ids:
                seen_ids.add(px["id"])
                all_pixels.append(px)

    if biz_result.get("success"):
        for biz in biz_result["data"].get("data", []):
            biz_id = biz.get("id")
            if not biz_id:
                continue
            for edge in ("owned_pixels", "client_pixels"):
                px_result = await _api_request(
                    "GET",
                    f"{BASE_URL}/{biz_id}/{edge}",
                    params={"fields": "id,name", "access_token": token, "limit": "200"},
                )
                if px_result.get("success"):
                    for px in px_result["data"].get("data", []):
                        if px.get("id") not in seen_ids:
                            seen_ids.add(px["id"])
                            all_pixels.append(px)

    if all_pixels:
        return {"success": True, "data": {"data": all_pixels}}

    # Return r1 even if empty so callers can handle no-pixels gracefully
    return r1 if r1.get("success") else {"success": True, "data": {"data": []}}


async def get_business_portfolios(token: str) -> dict[str, Any]:
    """List Business Portfolios (formerly Business Managers) for the user."""
    url = f"{BASE_URL}/me/businesses"
    return await _api_request(
        "GET",
        url,
        params={"fields": "id,name", "access_token": token},
    )


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------

async def create_campaign(
    token: str,
    ad_account_id: str,
    name: str,
    objective: str,
    status: str = "PAUSED",
    is_adset_budget_sharing: bool = False,
) -> dict[str, Any]:
    """Create a new campaign under an ad account."""
    url = f"{BASE_URL}/act_{ad_account_id}/campaigns"
    payload: dict[str, Any] = {
        "name": name,
        "objective": objective,
        "status": status,
        "special_ad_categories": [],
        "access_token": token,
    }
    if is_adset_budget_sharing:
        payload["is_skadnetwork_attribution"] = False
        payload["buying_type"] = "AUCTION"
    return await _api_request("POST", url, data=payload)


async def get_campaigns(token: str, ad_account_id: str) -> dict[str, Any]:
    """Return all campaigns belonging to an ad account."""
    url = f"{BASE_URL}/act_{ad_account_id}/campaigns"
    return await _api_request(
        "GET",
        url,
        params={
            "fields": "id,name,status,objective,daily_budget,lifetime_budget",
            "access_token": token,
        },
    )


async def update_campaign(
    token: str,
    campaign_id: str,
    updates: dict[str, Any],
) -> dict[str, Any]:
    """Apply arbitrary field updates to an existing campaign."""
    url = f"{BASE_URL}/{campaign_id}"
    payload = {"access_token": token, **updates}
    return await _api_request("POST", url, data=payload)


async def delete_campaign(token: str, campaign_id: str) -> dict[str, Any]:
    """Permanently delete a campaign."""
    url = f"{BASE_URL}/{campaign_id}"
    return await _api_request(
        "DELETE",
        url,
        params={"access_token": token},
    )


async def pause_campaign(token: str, campaign_id: str) -> dict[str, Any]:
    """Pause an active campaign."""
    return await update_campaign(token, campaign_id, {"status": "PAUSED"})


async def activate_campaign(token: str, campaign_id: str) -> dict[str, Any]:
    """Activate a paused campaign."""
    return await update_campaign(token, campaign_id, {"status": "ACTIVE"})


# ---------------------------------------------------------------------------
# Ad Sets
# ---------------------------------------------------------------------------

async def create_ad_set(
    token: str,
    ad_account_id: str,
    campaign_id: str,
    name: str,
    daily_budget: int,
    countries: list[str],
    age_min: int,
    age_max: int,
    pixel_id: Optional[str],
    optimization_goal: str,
    bid_strategy: str = "LOWEST_COST_WITHOUT_CAP",
    status: str = "PAUSED",
    targeting_automation: bool = False,
) -> dict[str, Any]:
    """Create an ad set within a campaign."""
    url = f"{BASE_URL}/act_{ad_account_id}/adsets"

    targeting: dict[str, Any] = {
        "geo_locations": {"countries": countries},
        "age_min": age_min,
        "age_max": age_max,
    }
    if targeting_automation:
        targeting["targeting_automation"] = {"advantage_audience": 1}

    payload: dict[str, Any] = {
        "name": name,
        "campaign_id": campaign_id,
        "daily_budget": daily_budget,
        "billing_event": "IMPRESSIONS",
        "optimization_goal": optimization_goal,
        "bid_strategy": bid_strategy,
        "targeting": json.dumps(targeting),
        "status": status,
        "access_token": token,
    }

    if pixel_id:
        payload["promoted_object"] = json.dumps({"pixel_id": pixel_id})

    return await _api_request("POST", url, data=payload)


async def get_ad_sets(token: str, campaign_id: str) -> dict[str, Any]:
    """Return all ad sets belonging to a campaign."""
    url = f"{BASE_URL}/{campaign_id}/adsets"
    return await _api_request(
        "GET",
        url,
        params={
            "fields": "id,name,status,daily_budget,targeting",
            "access_token": token,
        },
    )


async def update_ad_set(
    token: str,
    ad_set_id: str,
    updates: dict[str, Any],
) -> dict[str, Any]:
    """Apply arbitrary field updates to an existing ad set."""
    url = f"{BASE_URL}/{ad_set_id}"
    payload = {"access_token": token, **updates}
    return await _api_request("POST", url, data=payload)


async def pause_ad_set(token: str, ad_set_id: str) -> dict[str, Any]:
    """Pause an active ad set."""
    return await update_ad_set(token, ad_set_id, {"status": "PAUSED"})


async def activate_ad_set(token: str, ad_set_id: str) -> dict[str, Any]:
    """Activate a paused ad set."""
    return await update_ad_set(token, ad_set_id, {"status": "ACTIVE"})


# ---------------------------------------------------------------------------
# Images & Creatives
# ---------------------------------------------------------------------------

async def upload_image(
    token: str,
    ad_account_id: str,
    file_path: str,
) -> dict[str, Any]:
    """Upload a local image to an ad account and return its hash.

    On success ``data`` contains the raw API response which includes
    ``images.<filename>.hash``.
    """
    url = f"{BASE_URL}/act_{ad_account_id}/adimages"
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {file_path}"}

    file_bytes = path.read_bytes()
    result = await _api_request(
        "POST",
        url,
        data={"access_token": token},
        files={"filename": (path.name, file_bytes, "application/octet-stream")},
    )

    if not result["success"]:
        return result

    # Normalise: extract the hash from the nested response
    try:
        images: dict[str, Any] = result["data"].get("images", {})
        first_image = next(iter(images.values()))
        image_hash: str = first_image["hash"]
        return {"success": True, "data": {"hash": image_hash, "raw": result["data"]}}
    except (StopIteration, KeyError, TypeError) as exc:
        return {
            "success": False,
            "error": f"Could not extract image hash from response: {exc}",
        }


async def upload_image_bytes(
    token: str,
    ad_account_id: str,
    image_bytes: bytes,
    filename: str = "image.jpg",
) -> dict[str, Any]:
    """Upload in-memory image bytes to an ad account and return its hash.

    Identical to :func:`upload_image` but takes raw bytes (e.g. streamed from
    Google Drive) instead of a local file path — nothing touches disk.
    """
    url = f"{BASE_URL}/act_{ad_account_id}/adimages"
    result = await _api_request(
        "POST",
        url,
        data={"access_token": token},
        files={"filename": (filename, image_bytes, "application/octet-stream")},
    )
    if not result["success"]:
        return result
    try:
        images: dict[str, Any] = result["data"].get("images", {})
        first_image = next(iter(images.values()))
        return {"success": True, "data": {"hash": first_image["hash"], "raw": result["data"]}}
    except (StopIteration, KeyError, TypeError) as exc:
        return {"success": False, "error": f"Could not extract image hash: {exc}"}


# ---------------------------------------------------------------------------
# Video upload (ads) — graph-video host + status polling
# ---------------------------------------------------------------------------

VIDEO_BASE_URL = "https://graph-video.facebook.com/v21.0"


async def upload_video_bytes(
    token: str,
    ad_account_id: str,
    video_bytes: bytes,
    filename: str = "video.mp4",
    name: str = "",
) -> dict[str, Any]:
    """Upload in-memory video bytes to an ad account's video library.

    POSTs to ``graph-video.facebook.com/act_{account}/advideos`` and returns the
    new ``video_id``. The video is not yet processed — call
    :func:`poll_video_ready` before using it in a creative.
    """
    url = f"{VIDEO_BASE_URL}/act_{ad_account_id}/advideos"
    data = {"access_token": token}
    if name:
        data["name"] = name
    # graph-video uploads can be large; use a longer timeout than the default.
    result = await _api_request(
        "POST",
        url,
        retries=2,
        data=data,
        files={"source": (filename, video_bytes, "application/octet-stream")},
        timeout=300.0,
    )
    if not result["success"]:
        return result
    vid = result["data"].get("id") if isinstance(result["data"], dict) else None
    if not vid:
        return {"success": False, "error": "No video id returned from Meta"}
    return {"success": True, "data": {"video_id": vid, "raw": result["data"]}}


async def poll_video_ready(
    token: str,
    video_id: str,
    timeout_seconds: int = 600,
    interval_seconds: int = 5,
) -> dict[str, Any]:
    """Poll ``/{video_id}?fields=status`` until processing is ready or times out."""
    url = f"{BASE_URL}/{video_id}"
    waited = 0
    while waited < timeout_seconds:
        result = await _api_request(
            "GET", url, params={"fields": "status", "access_token": token}
        )
        if result["success"]:
            status = (result["data"] or {}).get("status", {})
            video_status = status.get("video_status")
            if video_status == "ready":
                return {"success": True, "data": {"video_id": video_id, "status": "ready"}}
            if video_status == "error":
                return {"success": False, "error": f"Video processing failed: {status}"}
        await asyncio.sleep(interval_seconds)
        waited += interval_seconds
    return {"success": False, "error": f"Video {video_id} not ready after {timeout_seconds}s"}


async def get_video_thumbnail(token: str, video_id: str) -> Optional[str]:
    """Return a thumbnail URL for a processed video (used as the creative cover)."""
    result = await _api_request(
        "GET",
        f"{BASE_URL}/{video_id}/thumbnails",
        params={"fields": "uri,is_preferred", "access_token": token},
    )
    if not result.get("success"):
        return None
    thumbs = (result["data"] or {}).get("data", []) if isinstance(result["data"], dict) else []
    if not thumbs:
        return None
    # Prefer Meta's preferred thumbnail, else the first.
    preferred = next((t for t in thumbs if t.get("is_preferred")), thumbs[0])
    return preferred.get("uri")


async def create_video_creative(
    token: str,
    ad_account_id: str,
    page_id: str,
    video_id: str,
    headline: str,
    message: str,
    link: str,
    cta_type: str = "LEARN_MORE",
    image_hash: str = "",
    image_url: str = "",
) -> dict[str, Any]:
    """Create a video ad creative.

    A cover image is required by Meta — pass either an ``image_hash`` (already
    uploaded) or an ``image_url`` (e.g. the video's auto-generated thumbnail).
    """
    url = f"{BASE_URL}/act_{ad_account_id}/adcreatives"
    video_data: dict[str, Any] = {
        "video_id": video_id,
        "message": message,
        "title": headline,
        "call_to_action": {"type": cta_type, "value": {"link": link}},
    }
    if image_hash:
        video_data["image_hash"] = image_hash
    elif image_url:
        video_data["image_url"] = image_url
    object_story_spec = {"page_id": page_id, "video_data": video_data}
    return await _api_request(
        "POST",
        url,
        data={"object_story_spec": json.dumps(object_story_spec), "access_token": token},
    )


# ---------------------------------------------------------------------------
# Page posting — upload bytes directly (Facebook)
# ---------------------------------------------------------------------------

async def publish_page_photo_bytes(
    page_token: str,
    page_id: str,
    image_bytes: bytes,
    caption: str = "",
    filename: str = "photo.jpg",
    published: bool = True,
    scheduled_publish_time: Optional[int] = None,
    no_story: bool = False,
) -> dict[str, Any]:
    """Publish (or schedule) a Facebook Page photo by uploading raw bytes.

    Uses the ``source`` multipart field so Meta receives the file directly —
    no public URL needed and nothing written to our disk.
    """
    url = f"{BASE_URL}/{page_id}/photos"
    data: dict[str, Any] = {"caption": caption, "access_token": page_token}
    if not published or scheduled_publish_time:
        data["published"] = "false"
    if scheduled_publish_time:
        data["scheduled_publish_time"] = str(scheduled_publish_time)
    if no_story:
        data["no_story"] = "true"
    return await _api_request(
        "POST",
        url,
        data=data,
        files={"source": (filename, image_bytes, "application/octet-stream")},
    )


async def publish_page_video_bytes(
    page_token: str,
    page_id: str,
    video_bytes: bytes,
    caption: str = "",
    title: str = "",
    filename: str = "video.mp4",
    published: bool = True,
    scheduled_publish_time: Optional[int] = None,
) -> dict[str, Any]:
    """Publish (or schedule) a Facebook Page video by uploading raw bytes.

    Posts to ``graph-video.facebook.com/{page_id}/videos`` using the ``source``
    multipart field, so Meta receives the file directly — no public URL and
    nothing written to our disk. Returns the new video/post ``id``.
    """
    url = f"{VIDEO_BASE_URL}/{page_id}/videos"
    data: dict[str, Any] = {"description": caption, "access_token": page_token}
    if title:
        data["title"] = title
    if not published or scheduled_publish_time:
        data["published"] = "false"
    if scheduled_publish_time:
        data["scheduled_publish_time"] = str(scheduled_publish_time)
    # Video uploads can be large; allow a generous timeout.
    return await _api_request(
        "POST",
        url,
        retries=2,
        data=data,
        files={"source": (filename, video_bytes, "application/octet-stream")},
        timeout=300.0,
    )


async def upload_unpublished_page_photo_bytes(
    page_token: str,
    page_id: str,
    image_bytes: bytes,
    filename: str = "photo.jpg",
) -> dict[str, Any]:
    """Upload an unpublished Page photo and return its ``id`` (for carousels).

    The returned media id is attached to a feed post via ``attached_media``.
    """
    url = f"{BASE_URL}/{page_id}/photos"
    result = await _api_request(
        "POST",
        url,
        data={"published": "false", "access_token": page_token},
        files={"source": (filename, image_bytes, "application/octet-stream")},
    )
    if not result["success"]:
        return result
    media_id = result["data"].get("id") if isinstance(result["data"], dict) else None
    if not media_id:
        return {"success": False, "error": "No media id returned"}
    return {"success": True, "data": {"media_id": media_id}}


async def publish_page_carousel(
    page_token: str,
    page_id: str,
    media_ids: list[str],
    caption: str = "",
    scheduled_publish_time: Optional[int] = None,
) -> dict[str, Any]:
    """Publish a multi-photo Page feed post from already-uploaded media ids."""
    url = f"{BASE_URL}/{page_id}/feed"
    data: dict[str, Any] = {"message": caption, "access_token": page_token}
    data["attached_media"] = json.dumps([{"media_fbid": mid} for mid in media_ids])
    if scheduled_publish_time:
        data["published"] = "false"
        data["scheduled_publish_time"] = str(scheduled_publish_time)
    return await _api_request("POST", url, data=data)


async def create_ad_creative(
    token: str,
    ad_account_id: str,
    page_id: str,
    image_hash: str,
    headline: str,
    message: str,
    link: str,
    cta_type: str = "LEARN_MORE",
) -> dict[str, Any]:
    """Create an ad creative using an already-uploaded image hash."""
    url = f"{BASE_URL}/act_{ad_account_id}/adcreatives"

    object_story_spec = {
        "page_id": page_id,
        "link_data": {
            "image_hash": image_hash,
            "message": message,
            "link": link,
            "name": headline,
            "call_to_action": {"type": cta_type, "value": {"link": link}},
        },
    }

    return await _api_request(
        "POST",
        url,
        data={
            "object_story_spec": json.dumps(object_story_spec),
            "access_token": token,
        },
    )


async def create_ad(
    token: str,
    ad_account_id: str,
    ad_set_id: str,
    creative_id: str,
    name: str,
    status: str = "ACTIVE",
) -> dict[str, Any]:
    """Create a single ad within an ad set."""
    url = f"{BASE_URL}/act_{ad_account_id}/ads"
    return await _api_request(
        "POST",
        url,
        data={
            "name": name,
            "adset_id": ad_set_id,
            "creative": json.dumps({"creative_id": creative_id}),
            "status": status,
            "access_token": token,
        },
    )


async def get_ads(token: str, ad_set_id: str) -> dict[str, Any]:
    """Return all ads within an ad set."""
    url = f"{BASE_URL}/{ad_set_id}/ads"
    return await _api_request(
        "GET",
        url,
        params={"fields": "id,name,status,creative", "access_token": token},
    )


async def batch_create_ads(
    token: str,
    ad_account_id: str,
    ads_config: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create many ads via the Meta Batch API (max 50 calls per request).

    Each item in ``ads_config`` must contain:
    ``ad_set_id``, ``creative_id``, ``name``, ``status``.
    """
    BATCH_SIZE = 50
    all_results: list[Any] = []

    for chunk_start in range(0, len(ads_config), BATCH_SIZE):
        chunk = ads_config[chunk_start : chunk_start + BATCH_SIZE]

        batch_ops: list[dict[str, Any]] = []
        for ad in chunk:
            body_params = {
                "name": ad["name"],
                "adset_id": ad["ad_set_id"],
                "creative": json.dumps({"creative_id": ad["creative_id"]}),
                "status": ad.get("status", "ACTIVE"),
                "access_token": token,
            }
            body_str = urlencode(body_params)
            batch_ops.append(
                {
                    "method": "POST",
                    "relative_url": f"act_{ad_account_id}/ads",
                    "body": body_str,
                }
            )

        result = await _api_request(
            "POST",
            BASE_URL,
            data={
                "access_token": token,
                "batch": json.dumps(batch_ops),
            },
        )

        if not result["success"]:
            return result

        # The batch endpoint returns a list of individual responses
        batch_responses: list[Any] = result["data"]
        for resp in batch_responses:
            if isinstance(resp, dict):
                try:
                    body_parsed = json.loads(resp.get("body", "{}"))
                except (json.JSONDecodeError, TypeError):
                    body_parsed = resp.get("body")
                all_results.append(
                    {
                        "success": resp.get("code", 500) < 300,
                        "code": resp.get("code"),
                        "data": body_parsed,
                    }
                )

    return {"success": True, "data": all_results}


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

def _build_insights_params(
    token: str,
    date_range: dict[str, str],
) -> dict[str, str]:
    fields = (
        "impressions,clicks,spend,reach,cpm,cpc,ctr,actions,action_values"
    )
    params: dict[str, str] = {"fields": fields, "access_token": token}

    if "date_preset" in date_range:
        params["date_preset"] = date_range["date_preset"]
    else:
        params["time_range"] = json.dumps(
            {"since": date_range["since"], "until": date_range["until"]}
        )
    return params


async def get_account_insights(
    token: str,
    ad_account_id: str,
    date_range: dict[str, str],
) -> dict[str, Any]:
    """Return aggregate performance metrics for an entire ad account."""
    url = f"{BASE_URL}/act_{ad_account_id}/insights"
    return await _api_request("GET", url, params=_build_insights_params(token, date_range))


async def get_campaign_insights(
    token: str,
    campaign_id: str,
    date_range: dict[str, str],
) -> dict[str, Any]:
    """Return performance metrics for a specific campaign."""
    url = f"{BASE_URL}/{campaign_id}/insights"
    return await _api_request("GET", url, params=_build_insights_params(token, date_range))


async def get_ad_insights(
    token: str,
    ad_id: str,
    date_range: dict[str, str],
) -> dict[str, Any]:
    """Return performance metrics for a specific ad."""
    url = f"{BASE_URL}/{ad_id}/insights"
    return await _api_request("GET", url, params=_build_insights_params(token, date_range))


# ---------------------------------------------------------------------------
# Posts & Scheduling
# ---------------------------------------------------------------------------

async def schedule_facebook_post(
    token: str,
    page_id: str,
    message: str,
    media_path: Optional[str],
    scheduled_time: int,
) -> dict[str, Any]:
    """Schedule a Facebook Page post (with or without an image).

    ``scheduled_time`` is a Unix timestamp (must be ≥10 min and ≤6 months in
    the future when calling the live API).
    """
    if media_path:
        path = Path(media_path)
        if not path.is_file():
            return {"success": False, "error": f"File not found: {media_path}"}

        file_bytes = path.read_bytes()
        url = f"{BASE_URL}/{page_id}/photos"
        return await _api_request(
            "POST",
            url,
            data={
                "caption": message,
                "published": "false",
                "scheduled_publish_time": str(scheduled_time),
                "access_token": token,
            },
            files={"source": (path.name, file_bytes, "application/octet-stream")},
        )
    else:
        url = f"{BASE_URL}/{page_id}/feed"
        return await _api_request(
            "POST",
            url,
            data={
                "message": message,
                "published": "false",
                "scheduled_publish_time": str(scheduled_time),
                "access_token": token,
            },
        )


_IG_NO_NATIVE_SCHEDULING = (
    "Instagram's API has no native scheduling — the 'published'/"
    "'scheduled_publish_time' parameters are not supported and the post would "
    "either be rejected or publish immediately. Schedule Instagram posts "
    "through the app's own queue instead (Posts tab → bulk composer with a "
    "scheduled time, which stores the post and publishes it when due)."
)


async def schedule_instagram_post(
    token: str,
    ig_account_id: str,
    caption: str,
    media_path: str,
    scheduled_time: int,
) -> dict[str, Any]:
    """Refused: Instagram cannot schedule natively — use the app's queue.

    This used to send ``published=false`` + ``scheduled_publish_time`` to
    ``/{ig}/media``, parameters the IG Content Publishing API does not
    support, then immediately called ``/media_publish`` — so the post either
    errored or published right away instead of at the scheduled time.
    """
    return {"success": False, "error": _IG_NO_NATIVE_SCHEDULING}


async def schedule_facebook_reel(
    token: str,
    page_id: str,
    video_path: str,
    description: str,
    scheduled_time: int,
) -> dict[str, Any]:
    """Upload and schedule a Facebook Reel."""
    path = Path(video_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {video_path}"}

    file_bytes = path.read_bytes()
    url = f"{BASE_URL}/{page_id}/video_reels"
    return await _api_request(
        "POST",
        url,
        data={
            "description": description,
            "published": "false",
            "scheduled_publish_time": str(scheduled_time),
            "access_token": token,
        },
        files={"source": (path.name, file_bytes, "video/mp4")},
    )


async def schedule_instagram_reel(
    token: str,
    ig_account_id: str,
    video_path: str,
    caption: str,
    scheduled_time: int,
) -> dict[str, Any]:
    """Refused: Instagram cannot schedule natively — use the app's queue."""
    return {"success": False, "error": _IG_NO_NATIVE_SCHEDULING}


async def schedule_instagram_story(
    token: str,
    ig_account_id: str,
    media_path: str,
    scheduled_time: int,
) -> dict[str, Any]:
    """Refused: Instagram cannot schedule natively — use the app's queue."""
    return {"success": False, "error": _IG_NO_NATIVE_SCHEDULING}


async def get_scheduled_posts(token: str, page_id: str) -> dict[str, Any]:
    """Return all scheduled (unpublished) posts for a Facebook Page."""
    url = f"{BASE_URL}/{page_id}/scheduled_posts"
    return await _api_request(
        "GET",
        url,
        params={
            "fields": "id,message,scheduled_publish_time,full_picture",
            "access_token": token,
        },
    )


async def delete_scheduled_post(token: str, post_id: str, retries: int = 4) -> dict[str, Any]:
    """Delete a scheduled post by its ID.

    ``retries`` is exposed so callers that verify the post's state afterwards
    (e.g. the cancel endpoint) can avoid the long transient-error back-off —
    Meta sometimes returns a code-1 "unknown error" on a delete that actually
    succeeded, and retrying it for ~30s just to fail is worse than checking.
    """
    url = f"{BASE_URL}/{post_id}"
    return await _api_request(
        "DELETE",
        url,
        retries=retries,
        params={"access_token": token},
    )
