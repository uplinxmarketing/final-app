"""
Google API integration for Uplinx Meta Manager.
Uses direct httpx calls to Google APIs — no google-api-python-client dependency.
"""
import asyncio
import hashlib
import httpx
import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger("uplinx")

GOOGLE_OAUTH_BASE = "https://oauth2.googleapis.com"
GOOGLE_DOCS_BASE = "https://docs.googleapis.com/v1"
GOOGLE_SHEETS_BASE = "https://sheets.googleapis.com/v4"
GOOGLE_DRIVE_BASE = "https://www.googleapis.com/drive/v3"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _bearer(access_token: str) -> dict[str, str]:
    """Return an ``Authorization: Bearer`` header dict.

    Args:
        access_token: A valid OAuth 2.0 access token.

    Returns:
        A single-entry dict suitable for passing as ``headers=`` to httpx.
    """
    return {"Authorization": f"Bearer {access_token}"}


def _extract_google_error(response: httpx.Response) -> str:
    """Extract a human-readable error message from a failed Google API response.

    Tries to parse the JSON body and pull ``error.message`` or
    ``error_description``.  Falls back to the raw response text.

    Args:
        response: The failed ``httpx.Response`` object.

    Returns:
        A non-empty string describing the error.
    """
    try:
        body = response.json()
        # Structured Google API error envelope
        err = body.get("error", {})
        if isinstance(err, dict):
            return err.get("message") or str(err)
        # OAuth token-endpoint style
        return body.get("error_description") or body.get("error") or response.text
    except Exception:
        return response.text or f"HTTP {response.status_code}"


def _extract_doc_content(content: list[dict[str, Any]]) -> str:
    """Recursively extract plain text from a Google Docs body content list.

    Handles paragraph ``textRun`` elements and recurses into table cells so
    that text embedded inside tables is also captured.

    Args:
        content: The ``body.content`` list from a Docs API document object, or
                 the ``content`` list from a table cell.

    Returns:
        Concatenated plain-text string with no additional formatting.
    """
    parts: list[str] = []

    for element in content:
        # --- Paragraph ---------------------------------------------------------
        if "paragraph" in element:
            for para_elem in element["paragraph"].get("elements", []):
                text_run = para_elem.get("textRun")
                if text_run:
                    parts.append(text_run.get("content", ""))

        # --- Table – recurse into each cell ------------------------------------
        elif "table" in element:
            for row in element["table"].get("tableRows", []):
                for cell in row.get("tableCells", []):
                    cell_text = _extract_doc_content(cell.get("content", []))
                    parts.append(cell_text)

        # Section breaks and other structural elements carry no text; skip them.

    return "".join(parts)


# ---------------------------------------------------------------------------
# OAuth / Token Management
# ---------------------------------------------------------------------------


async def exchange_code_for_tokens(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange an OAuth 2.0 authorisation code for access and refresh tokens.

    POST to ``https://oauth2.googleapis.com/token`` with
    ``grant_type=authorization_code``.

    Args:
        code: The one-time authorisation code received from the OAuth consent
              screen redirect.
        client_id: The application's OAuth 2.0 client ID.
        client_secret: The application's OAuth 2.0 client secret.
        redirect_uri: The redirect URI that was used in the initial
                      authorisation request (must match exactly).

    Returns:
        On success::

            {"success": True, "access_token": str, "refresh_token": str,
             "expires_in": int}

        On failure::

            {"success": False, "error": str}
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{GOOGLE_OAUTH_BASE}/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            return {
                "success": True,
                "access_token": data.get("access_token", ""),
                "refresh_token": data.get("refresh_token", ""),
                "expires_in": data.get("expires_in", 3600),
            }
    except httpx.HTTPStatusError as exc:
        error_msg = _extract_google_error(exc.response)
        logger.error(
            "exchange_code_for_tokens HTTP %s: %s",
            exc.response.status_code,
            error_msg,
        )
        return {"success": False, "error": error_msg}
    except Exception as exc:
        logger.error("exchange_code_for_tokens unexpected error: %s", exc)
        return {"success": False, "error": str(exc)}


async def refresh_access_token(
    refresh_token: str,
    client_id: str,
    client_secret: str,
) -> dict[str, Any]:
    """Obtain a new access token by exchanging a refresh token.

    POST to ``https://oauth2.googleapis.com/token`` with
    ``grant_type=refresh_token``.

    Args:
        refresh_token: A valid refresh token previously obtained during the
                       OAuth authorisation flow.
        client_id: The application's OAuth 2.0 client ID.
        client_secret: The application's OAuth 2.0 client secret.

    Returns:
        On success::

            {"success": True, "access_token": str, "expires_in": int}

        On failure::

            {"success": False, "error": str}
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{GOOGLE_OAUTH_BASE}/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            return {
                "success": True,
                "access_token": data.get("access_token", ""),
                "expires_in": data.get("expires_in", 3600),
            }
    except httpx.HTTPStatusError as exc:
        error_msg = _extract_google_error(exc.response)
        logger.error(
            "refresh_access_token HTTP %s: %s",
            exc.response.status_code,
            error_msg,
        )
        return {"success": False, "error": error_msg}
    except Exception as exc:
        logger.error("refresh_access_token unexpected error: %s", exc)
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# User Info
# ---------------------------------------------------------------------------


async def get_user_info(access_token: str) -> dict[str, Any]:
    """Retrieve the authenticated Google user's profile information.

    GET ``https://www.googleapis.com/oauth2/v2/userinfo`` with a Bearer token.

    Requires the ``profile`` and ``email`` OAuth scopes.

    Args:
        access_token: A valid OAuth 2.0 access token.

    Returns:
        On success::

            {"success": True, "id": str, "email": str, "name": str,
             "picture": str}

        On failure::

            {"success": False, "error": str}
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                GOOGLE_USERINFO_URL,
                headers=_bearer(access_token),
            )
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            return {
                "success": True,
                "id": data.get("id", ""),
                "email": data.get("email", ""),
                "name": data.get("name", ""),
                "picture": data.get("picture", ""),
            }
    except httpx.HTTPStatusError as exc:
        error_msg = _extract_google_error(exc.response)
        logger.error("get_user_info HTTP %s: %s", exc.response.status_code, error_msg)
        return {"success": False, "error": error_msg}
    except Exception as exc:
        logger.error("get_user_info unexpected error: %s", exc)
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Google Docs
# ---------------------------------------------------------------------------


async def read_google_doc(doc_id: str, access_token: str) -> dict[str, Any]:
    """Read a Google Doc and return its title and full plain-text content.

    GET ``https://docs.googleapis.com/v1/documents/{doc_id}``

    Traverses the document body, extracting text from every
    ``paragraph → elements → textRun.content`` path.  Table cells are also
    recursed so that text embedded inside tables is included.

    Args:
        doc_id: The Google Docs document ID extracted from the document URL.
        access_token: A valid OAuth 2.0 access token with
                      ``https://www.googleapis.com/auth/documents.readonly``
                      scope (or broader).

    Returns:
        On success::

            {"success": True, "title": str, "content": str, "error": ""}

        On failure::

            {"success": False, "title": "", "content": "", "error": str}
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GOOGLE_DOCS_BASE}/documents/{doc_id}",
                headers=_bearer(access_token),
            )
            response.raise_for_status()
            document: dict[str, Any] = response.json()

        title: str = document.get("title", "")
        body_content: list[dict[str, Any]] = document.get("body", {}).get("content", [])
        content: str = _extract_doc_content(body_content)

        return {"success": True, "title": title, "content": content, "error": ""}

    except httpx.HTTPStatusError as exc:
        error_msg = _extract_google_error(exc.response)
        logger.error(
            "read_google_doc HTTP %s for doc %s: %s",
            exc.response.status_code,
            doc_id,
            error_msg,
        )
        return {"success": False, "title": "", "content": "", "error": error_msg}
    except Exception as exc:
        logger.error("read_google_doc unexpected error for doc %s: %s", doc_id, exc)
        return {"success": False, "title": "", "content": "", "error": str(exc)}


# ---------------------------------------------------------------------------
# Google Sheets
# ---------------------------------------------------------------------------


async def read_google_sheet(
    sheet_id: str,
    access_token: str,
    range_name: str = "A1:ZZ10000",
) -> dict[str, Any]:
    """Read cell values from a Google Sheet.

    Performs two HTTP requests:

    1. ``GET /spreadsheets/{sheet_id}?fields=properties.title`` — fetch the
       spreadsheet title.
    2. ``GET /spreadsheets/{sheet_id}/values/{range_name}`` — fetch the cell
       values for the requested range.

    Args:
        sheet_id: The Google Sheets spreadsheet ID (from the URL).
        access_token: A valid OAuth 2.0 access token with
                      ``https://www.googleapis.com/auth/spreadsheets.readonly``
                      scope (or broader).
        range_name: A1 notation range to read.  Defaults to ``"A1:ZZ10000"``
                    which covers up to 702 columns and 10 000 rows.

    Returns:
        On success::

            {"success": True, "title": str, "rows": list[list[str]], "error": ""}

        On failure::

            {"success": False, "title": "", "rows": [], "error": str}
    """
    headers = _bearer(access_token)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1 — spreadsheet title
            meta_response = await client.get(
                f"{GOOGLE_SHEETS_BASE}/spreadsheets/{sheet_id}",
                headers=headers,
                params={"fields": "properties.title"},
            )
            meta_response.raise_for_status()
            title: str = (
                meta_response.json().get("properties", {}).get("title", "")
            )

            # Step 2 — cell values
            values_response = await client.get(
                f"{GOOGLE_SHEETS_BASE}/spreadsheets/{sheet_id}/values/{range_name}",
                headers=headers,
            )
            values_response.raise_for_status()
            raw_rows: list[list[Any]] = values_response.json().get("values", [])

        # Normalise every cell to str (the API may return int/float for numeric cells)
        rows: list[list[str]] = [[str(cell) for cell in row] for row in raw_rows]

        return {"success": True, "title": title, "rows": rows, "error": ""}

    except httpx.HTTPStatusError as exc:
        error_msg = _extract_google_error(exc.response)
        logger.error(
            "read_google_sheet HTTP %s for sheet %s: %s",
            exc.response.status_code,
            sheet_id,
            error_msg,
        )
        return {"success": False, "title": "", "rows": [], "error": error_msg}
    except Exception as exc:
        logger.error(
            "read_google_sheet unexpected error for sheet %s: %s", sheet_id, exc
        )
        return {"success": False, "title": "", "rows": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# Google Drive — metadata, download, export, list
# ---------------------------------------------------------------------------


async def get_file_metadata(file_id: str, access_token: str) -> dict[str, Any]:
    """Retrieve metadata for a Google Drive file.

    GET ``https://www.googleapis.com/drive/v3/files/{file_id}``
    with ``fields=id,name,mimeType,size,modifiedTime``.

    Args:
        file_id: The Google Drive file ID.
        access_token: A valid OAuth 2.0 access token with
                      ``https://www.googleapis.com/auth/drive.readonly``
                      scope (or broader).

    Returns:
        On success::

            {"success": True, "id": str, "name": str, "mimeType": str,
             "size": str, "modifiedTime": str}

        On failure::

            {"success": False, "error": str}
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GOOGLE_DRIVE_BASE}/files/{file_id}",
                headers=_bearer(access_token),
                params={"fields": "id,name,mimeType,size,modifiedTime"},
            )
            response.raise_for_status()
            data: dict[str, Any] = response.json()

        return {
            "success": True,
            "id": data.get("id", ""),
            "name": data.get("name", ""),
            "mimeType": data.get("mimeType", ""),
            "size": data.get("size", ""),
            "modifiedTime": data.get("modifiedTime", ""),
        }
    except httpx.HTTPStatusError as exc:
        error_msg = _extract_google_error(exc.response)
        logger.error(
            "get_file_metadata HTTP %s for file %s: %s",
            exc.response.status_code,
            file_id,
            error_msg,
        )
        return {"success": False, "error": error_msg}
    except Exception as exc:
        logger.error(
            "get_file_metadata unexpected error for file %s: %s", file_id, exc
        )
        return {"success": False, "error": str(exc)}


async def download_drive_file(file_id: str, access_token: str) -> dict[str, Any]:
    """Download the raw bytes of a (non-Workspace) file from Google Drive.

    GET ``https://www.googleapis.com/drive/v3/files/{file_id}?alt=media``

    This endpoint is only valid for binary/non-Workspace files (e.g. PDFs,
    images, plain-text uploads).  For Google Docs or Sheets use
    :func:`export_drive_file` instead.

    Args:
        file_id: The Google Drive file ID.
        access_token: A valid OAuth 2.0 access token with
                      ``https://www.googleapis.com/auth/drive.readonly``
                      scope (or broader).

    Returns:
        On success::

            {"success": True, "bytes": bytes, "error": ""}

        On failure::

            {"success": False, "bytes": b"", "error": str}
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GOOGLE_DRIVE_BASE}/files/{file_id}",
                headers=_bearer(access_token),
                params={"alt": "media"},
            )
            response.raise_for_status()
            return {"success": True, "bytes": response.content, "error": ""}

    except httpx.HTTPStatusError as exc:
        error_msg = _extract_google_error(exc.response)
        logger.error(
            "download_drive_file HTTP %s for file %s: %s",
            exc.response.status_code,
            file_id,
            error_msg,
        )
        return {"success": False, "bytes": b"", "error": error_msg}
    except Exception as exc:
        logger.error(
            "download_drive_file unexpected error for file %s: %s", file_id, exc
        )
        return {"success": False, "bytes": b"", "error": str(exc)}


async def export_drive_file(
    file_id: str, mime_type: str, access_token: str
) -> dict[str, Any]:
    """Export a Google Workspace file to a specified MIME type.

    GET ``https://www.googleapis.com/drive/v3/files/{file_id}/export``
    with ``mimeType={mime_type}``.

    Common export MIME types:

    * ``"text/plain"``        — Google Doc as plain text
    * ``"text/csv"``          — Google Sheet as CSV
    * ``"application/pdf"``   — any Workspace file as PDF

    Args:
        file_id: The Google Drive file ID of a Google Workspace document.
        mime_type: The target export MIME type string.
        access_token: A valid OAuth 2.0 access token with
                      ``https://www.googleapis.com/auth/drive.readonly``
                      scope (or broader).

    Returns:
        On success::

            {"success": True, "content": str, "error": ""}

        On failure::

            {"success": False, "content": "", "error": str}
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GOOGLE_DRIVE_BASE}/files/{file_id}/export",
                headers=_bearer(access_token),
                params={"mimeType": mime_type},
            )
            response.raise_for_status()
            return {"success": True, "content": response.text, "error": ""}

    except httpx.HTTPStatusError as exc:
        error_msg = _extract_google_error(exc.response)
        logger.error(
            "export_drive_file HTTP %s for file %s (mimeType=%s): %s",
            exc.response.status_code,
            file_id,
            mime_type,
            error_msg,
        )
        return {"success": False, "content": "", "error": error_msg}
    except Exception as exc:
        logger.error(
            "export_drive_file unexpected error for file %s: %s", file_id, exc
        )
        return {"success": False, "content": "", "error": str(exc)}


async def read_drive_file(file_id: str, access_token: str) -> dict[str, Any]:
    """Auto-detect a Drive file's type and read it with the appropriate strategy.

    Steps:

    1. Fetch file metadata via :func:`get_file_metadata` to determine the
       ``mimeType``.
    2. Route to the correct reader based on ``mimeType``:

       * ``application/vnd.google-apps.document``    → :func:`read_google_doc`
       * ``application/vnd.google-apps.spreadsheet`` → :func:`read_google_sheet`
       * ``application/pdf``                          → :func:`download_drive_file`
         (returns raw bytes)
       * anything else                                → return metadata only
         (no content download attempted)

    Args:
        file_id: The Google Drive file ID.
        access_token: A valid OAuth 2.0 access token with
                      ``https://www.googleapis.com/auth/drive.readonly``
                      scope (or broader).

    Returns:
        On success::

            {"success": True, "name": str, "mime_type": str, "content": Any,
             "error": ""}

        On failure::

            {"success": False, "name": str, "mime_type": str, "content": None,
             "error": str}

        The type of ``content`` depends on the file type:

        * Google Doc        → ``{"title": str, "text": str}``
        * Google Sheet      → ``{"title": str, "rows": list[list[str]]}``
        * PDF / binary      → ``bytes``
        * Other             → metadata ``dict``
    """
    # 1. Fetch metadata
    meta = await get_file_metadata(file_id, access_token)
    if not meta["success"]:
        return {
            "success": False,
            "name": "",
            "mime_type": "",
            "content": None,
            "error": meta["error"],
        }

    name: str = meta["name"]
    mime_type: str = meta["mimeType"]

    try:
        # 2. Route by mimeType
        if mime_type == "application/vnd.google-apps.document":
            result = await read_google_doc(file_id, access_token)
            if not result["success"]:
                return {
                    "success": False,
                    "name": name,
                    "mime_type": mime_type,
                    "content": None,
                    "error": result["error"],
                }
            content: Any = {"title": result["title"], "text": result["content"]}

        elif mime_type == "application/vnd.google-apps.spreadsheet":
            result = await read_google_sheet(file_id, access_token)
            if not result["success"]:
                return {
                    "success": False,
                    "name": name,
                    "mime_type": mime_type,
                    "content": None,
                    "error": result["error"],
                }
            content = {"title": result["title"], "rows": result["rows"]}

        elif mime_type == "application/pdf":
            result = await download_drive_file(file_id, access_token)
            if not result["success"]:
                return {
                    "success": False,
                    "name": name,
                    "mime_type": mime_type,
                    "content": None,
                    "error": result["error"],
                }
            content = result["bytes"]

        else:
            # Unknown / unsupported type — return metadata dict as content
            content = {
                "id": meta["id"],
                "name": name,
                "mimeType": mime_type,
                "size": meta.get("size", ""),
                "modifiedTime": meta.get("modifiedTime", ""),
            }

        return {
            "success": True,
            "name": name,
            "mime_type": mime_type,
            "content": content,
            "error": "",
        }

    except Exception as exc:
        logger.error(
            "read_drive_file unexpected error for file %s: %s", file_id, exc
        )
        return {
            "success": False,
            "name": name,
            "mime_type": mime_type,
            "content": None,
            "error": str(exc),
        }


async def list_drive_files(
    access_token: str,
    query: str = "",
) -> dict[str, Any]:
    """List files in the authenticated user's Google Drive.

    GET ``https://www.googleapis.com/drive/v3/files`` with ``pageSize=100``
    and fields ``id``, ``name``, ``mimeType``, ``size``, ``modifiedTime``.
    Results are ordered by most-recently-modified first.

    Args:
        access_token: A valid OAuth 2.0 access token with
                      ``https://www.googleapis.com/auth/drive.readonly``
                      scope (or broader).
        query: An optional Drive query string (e.g.
               ``"mimeType='application/pdf'"``).  Pass an empty string to
               list recent files without filtering.  See
               https://developers.google.com/drive/api/guides/search-files
               for query syntax.

    Returns:
        On success::

            {"success": True, "files": list[dict], "error": ""}

        On failure::

            {"success": False, "files": [], "error": str}

        Each file dict contains: ``id``, ``name``, ``mimeType``, ``size``,
        ``modifiedTime``.
    """
    try:
        params: dict[str, Any] = {
            "fields": "files(id,name,mimeType,size,modifiedTime)",
            "pageSize": 100,
            "orderBy": "modifiedTime desc",
        }
        if query:
            params["q"] = query

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GOOGLE_DRIVE_BASE}/files",
                headers=_bearer(access_token),
                params=params,
            )
            response.raise_for_status()
            data: dict[str, Any] = response.json()

        files: list[dict[str, Any]] = data.get("files", [])
        return {"success": True, "files": files, "error": ""}

    except httpx.HTTPStatusError as exc:
        error_msg = _extract_google_error(exc.response)
        logger.error(
            "list_drive_files HTTP %s: %s", exc.response.status_code, error_msg
        )
        return {"success": False, "files": [], "error": error_msg}
    except Exception as exc:
        logger.error("list_drive_files unexpected error: %s", exc)
        return {"success": False, "files": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# URL parsing helpers
# ---------------------------------------------------------------------------


def extract_doc_id_from_url(url: str) -> Optional[str]:
    """Extract the document ID from a Google Docs URL.

    Recognises URLs of the form:

    * ``https://docs.google.com/document/d/{ID}/edit``
    * ``https://docs.google.com/document/d/{ID}/``
    * ``https://docs.google.com/document/d/{ID}``

    Args:
        url: A Google Docs URL string.

    Returns:
        The document ID string, or ``None`` if not found.
    """
    patterns = [
        r"docs\.google\.com/document/d/([a-zA-Z0-9_-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None


def extract_sheet_id_from_url(url: str) -> Optional[str]:
    """Extract the spreadsheet ID from a Google Sheets URL.

    Recognises URLs of the form:

    * ``https://docs.google.com/spreadsheets/d/{ID}/edit``
    * ``https://docs.google.com/spreadsheets/d/{ID}/``
    * ``https://docs.google.com/spreadsheets/d/{ID}``

    Args:
        url: A Google Sheets URL string.

    Returns:
        The spreadsheet ID string, or ``None`` if not found.
    """
    match = re.search(
        r"docs\.google\.com/spreadsheets/d/([a-zA-Z0-9_-]+)", url
    )
    return match.group(1) if match else None


def extract_file_id_from_url(url: str) -> Optional[str]:
    """Extract the file ID from a Google Drive URL.

    Recognises URLs of the form:

    * ``https://drive.google.com/file/d/{ID}/view``
    * ``https://drive.google.com/file/d/{ID}/``
    * ``https://drive.google.com/open?id={ID}``
    * ``https://drive.google.com/uc?id={ID}``

    Args:
        url: A Google Drive URL string.

    Returns:
        The file ID string, or ``None`` if not found.
    """
    # Path-based: /file/d/{ID}/
    path_match = re.search(
        r"drive\.google\.com/file/d/([a-zA-Z0-9_-]+)", url
    )
    if path_match:
        return path_match.group(1)

    # Query-param based: ?id={ID} or &id={ID} (open, uc, etc.)
    param_match = re.search(r"[?&]id=([a-zA-Z0-9_-]+)", url)
    if param_match:
        return param_match.group(1)

    return None


# ---------------------------------------------------------------------------
# Auto-detect URL reader
# ---------------------------------------------------------------------------


async def read_by_url(url: str, access_token: str) -> dict[str, Any]:
    """Auto-detect the type of a Google URL and read its content.

    Detection order:

    1. Google Docs URL   → :func:`extract_doc_id_from_url`   → :func:`read_google_doc`
    2. Google Sheets URL → :func:`extract_sheet_id_from_url` → :func:`read_google_sheet`
    3. Google Drive URL  → :func:`extract_file_id_from_url`  → :func:`read_drive_file`
    4. Unrecognised URL  → return error dict

    Args:
        url: A Google Docs, Sheets, or Drive URL string.
        access_token: A valid OAuth 2.0 access token with appropriate scopes.

    Returns:
        The result dict from the matched reader function (structure varies by
        file type), or on an unrecognised URL::

            {"success": False, "error": str}
    """
    # 1. Google Docs
    doc_id = extract_doc_id_from_url(url)
    if doc_id:
        logger.debug("read_by_url: detected Google Doc id=%s", doc_id)
        return await read_google_doc(doc_id, access_token)

    # 2. Google Sheets
    sheet_id = extract_sheet_id_from_url(url)
    if sheet_id:
        logger.debug("read_by_url: detected Google Sheet id=%s", sheet_id)
        return await read_google_sheet(sheet_id, access_token)

    # 3. Google Drive file
    file_id = extract_file_id_from_url(url)
    if file_id:
        logger.debug("read_by_url: detected Drive file id=%s", file_id)
        return await read_drive_file(file_id, access_token)

    # 4. Unrecognised
    logger.error("read_by_url: unrecognised URL format: %s", url)
    return {
        "success": False,
        "error": (
            f"Unrecognised Google URL: {url!r}. "
            "Expected a Google Docs, Sheets, or Drive URL."
        ),
    }
