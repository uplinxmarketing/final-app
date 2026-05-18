"""
file_processor.py — File processing module for Uplinx Meta Manager.

Handles PDF text extraction, file upload validation, folder scanning,
Post/Story pair matching, and video file validation.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import mimetypes
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiofiles

logger = logging.getLogger("uplinx")

ALLOWED_EXTENSIONS: set[str] = {"jpg", "jpeg", "png", "gif", "mp4", "mov", "pdf", "md"}
UPLOAD_DIR = Path("uploads")

# MIME type families allowed per extension group
_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}
_VIDEO_EXTENSIONS = {"mp4", "mov"}
_DOC_EXTENSIONS = {"pdf", "md"}

# Cache: sha256 → {"text": str, "pages": int, "ts": float}
_pdf_cache: dict[str, dict] = {}
_PDF_CACHE_TTL_SECONDS = 86400  # 24 hours


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


async def compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file asynchronously."""
    sha = hashlib.sha256()
    async with aiofiles.open(file_path, "rb") as fh:
        while True:
            chunk = await fh.read(65536)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


async def extract_pdf_text(file_path: str) -> dict:
    """
    Extract text from PDF using pymupdf (fitz) as primary.
    Falls back to pdfplumber if pymupdf fails.
    Returns {"success": bool, "text": str, "pages": int, "error": str}.
    Caches results by SHA256 for 24 hours.
    Warns when a scanned PDF (no text) is detected.
    """
    result: dict = {"success": False, "text": "", "pages": 0, "error": ""}
    path = Path(file_path)

    if not path.exists():
        result["error"] = f"File not found: {file_path}"
        return result

    # Check cache
    try:
        sha256 = await compute_sha256(file_path)
    except Exception as exc:
        result["error"] = f"Could not hash file: {exc}"
        return result

    cached = _pdf_cache.get(sha256)
    if cached and (time.time() - cached["ts"]) < _PDF_CACHE_TTL_SECONDS:
        logger.debug("PDF cache hit for %s", sha256[:12])
        return {"success": True, "text": cached["text"], "pages": cached["pages"], "error": ""}

    # Primary: pymupdf (fitz)
    text = ""
    pages = 0
    primary_error = ""
    try:
        import fitz  # type: ignore[import]

        doc = fitz.open(file_path)
        pages = doc.page_count
        parts: list[str] = []
        for page in doc:
            parts.append(page.get_text())
        doc.close()
        text = "\n".join(parts)
    except ImportError:
        primary_error = "pymupdf not installed"
    except Exception as exc:
        primary_error = str(exc)
        logger.warning("pymupdf failed for %s: %s", file_path, exc)

    # Fallback: pdfplumber
    if primary_error:
        try:
            import pdfplumber  # type: ignore[import]

            with pdfplumber.open(file_path) as pdf:
                pages = len(pdf.pages)
                parts = []
                for page in pdf.pages:
                    page_text = page.extract_text() or ""
                    parts.append(page_text)
                text = "\n".join(parts)
            primary_error = ""
        except ImportError:
            result["error"] = "Neither pymupdf nor pdfplumber is installed"
            return result
        except Exception as exc:
            result["error"] = f"Both PDF extractors failed. Primary: {primary_error}. Fallback: {exc}"
            return result

    # Detect scanned PDF
    if pages > 0 and len(text.strip()) < 20:
        logger.warning(
            "PDF %s appears to be scanned (no extractable text). "
            "Consider running OCR before processing.",
            file_path,
        )

    # Populate cache
    _pdf_cache[sha256] = {"text": text, "pages": pages, "ts": time.time()}

    result["success"] = True
    result["text"] = text
    result["pages"] = pages
    return result


async def process_uploaded_file(file_bytes: bytes, original_filename: str) -> dict:
    """
    Validate and save an uploaded file.
    - Validates extension against ALLOWED_EXTENSIONS.
    - Validates MIME type is consistent with extension.
    - Checks file size < MAX_UPLOAD_SIZE_MB.
    - Sanitises filename, generates UUID-based storage name.
    - Saves to uploads/ directory.
    Returns {"success": bool, "stored_path": str, "original_name": str,
             "sha256": str, "file_type": str, "error": str}.
    """
    from config import settings  # imported lazily to avoid circular issues

    result: dict = {
        "success": False,
        "stored_path": "",
        "original_name": original_filename,
        "sha256": "",
        "file_type": "",
        "error": "",
    }

    # --- Extension validation ---
    safe_name = Path(original_filename).name
    ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
    if ext not in ALLOWED_EXTENSIONS:
        result["error"] = (
            f"Extension '.{ext}' is not allowed. "
            f"Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )
        return result

    # --- MIME type consistency check ---
    guessed_type, _ = mimetypes.guess_type(safe_name)
    if guessed_type:
        family = guessed_type.split("/")[0]
        if ext in _IMAGE_EXTENSIONS and family not in {"image"}:
            result["error"] = f"MIME type '{guessed_type}' does not match image extension '.{ext}'"
            return result
        if ext in _VIDEO_EXTENSIONS and family not in {"video"}:
            result["error"] = f"MIME type '{guessed_type}' does not match video extension '.{ext}'"
            return result

    # --- Size check ---
    size_bytes = len(file_bytes)
    max_bytes = settings.max_upload_size_bytes
    if size_bytes > max_bytes:
        result["error"] = (
            f"File size {size_bytes / 1024 / 1024:.1f} MB exceeds "
            f"limit of {settings.MAX_UPLOAD_SIZE_MB} MB"
        )
        return result

    # --- Sanitise filename ---
    sanitised = re.sub(r"[^\w.\-]", "_", safe_name)
    sanitised = re.sub(r"\.{2,}", ".", sanitised)  # no path traversal via ..
    if not sanitised or sanitised.startswith("."):
        sanitised = f"upload.{ext}"

    # --- Save file ---
    stored_path = await save_upload_file(file_bytes, f".{ext}")

    # --- SHA256 ---
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    result["success"] = True
    result["stored_path"] = stored_path
    result["sha256"] = sha256
    result["file_type"] = detect_file_type(original_filename)
    return result


async def scan_folder(
    folder_path: str,
    extensions: Optional[list[str]] = None,
) -> dict:
    """
    Scan a local folder for files with given extensions.
    Defaults to image/video types when extensions is None.
    Returns {"success": bool, "files": list[dict], "error": str}.
    Each file dict: {"path": str, "name": str, "extension": str, "size": int}.
    """
    result: dict = {"success": False, "files": [], "error": ""}

    default_extensions = list(_IMAGE_EXTENSIONS | _VIDEO_EXTENSIONS)
    exts = [e.lstrip(".").lower() for e in (extensions or default_extensions)]

    folder = Path(folder_path)
    if not folder.exists():
        result["error"] = f"Folder does not exist: {folder_path}"
        return result
    if not folder.is_dir():
        result["error"] = f"Path is not a directory: {folder_path}"
        return result

    files: list[dict] = []
    try:
        for entry in folder.iterdir():
            if not entry.is_file():
                continue
            entry_ext = entry.suffix.lstrip(".").lower()
            if entry_ext in exts:
                files.append(
                    {
                        "path": str(entry),
                        "name": entry.name,
                        "extension": entry_ext,
                        "size": entry.stat().st_size,
                    }
                )
    except PermissionError as exc:
        result["error"] = f"Permission denied reading folder: {exc}"
        return result
    except OSError as exc:
        result["error"] = f"OS error scanning folder: {exc}"
        return result

    files.sort(key=lambda f: f["name"])
    result["success"] = True
    result["files"] = files
    return result


async def match_post_story_pairs(folder_path: str) -> dict:
    """
    Scan folder and auto-match Post/Story image pairs by filename.

    Logic:
      - Files with "Post" in name → feed creative
      - Files with "Story" in name → story/reels creative
    Pairing: by numeric prefix (e.g. "Ad1Post.png" pairs with "Ad1Story.png").

    Returns {"success": bool, "pairs": list[dict], "unmatched": list[str], "error": str}.
    Each pair: {"number": str, "post_file": str, "story_file": str, "ad_name": str}.
    """
    result: dict = {"success": False, "pairs": [], "unmatched": [], "error": ""}

    scan = await scan_folder(folder_path, extensions=list(_IMAGE_EXTENSIONS))
    if not scan["success"]:
        result["error"] = scan["error"]
        return result

    post_files: dict[str, str] = {}   # number_key → path
    story_files: dict[str, str] = {}  # number_key → path
    unmatched: list[str] = []

    for file_info in scan["files"]:
        name: str = file_info["name"]
        name_lower = name.lower()
        is_post = "post" in name_lower
        is_story = "story" in name_lower

        if not is_post and not is_story:
            unmatched.append(file_info["path"])
            continue

        # Extract numeric prefix/identifier — digits preceding "Post" or "Story"
        number_match = re.search(r"(\d+)", name, re.IGNORECASE)
        number_key = number_match.group(1) if number_match else name

        if is_post:
            post_files[number_key] = file_info["path"]
        elif is_story:
            story_files[number_key] = file_info["path"]

    # Build pairs
    paired_keys: set[str] = set()
    pairs: list[dict] = []

    for key in sorted(post_files.keys()):
        if key in story_files:
            post_path = post_files[key]
            story_path = story_files[key]
            pairs.append(
                {
                    "number": key,
                    "post_file": post_path,
                    "story_file": story_path,
                    "ad_name": f"Ad{key}",
                }
            )
            paired_keys.add(key)

    # Files that couldn't be paired
    for key, path in post_files.items():
        if key not in paired_keys:
            unmatched.append(path)
    for key, path in story_files.items():
        if key not in paired_keys:
            unmatched.append(path)

    result["success"] = True
    result["pairs"] = pairs
    result["unmatched"] = unmatched
    return result


async def validate_video_file(file_path: str) -> dict:
    """
    Validate video file for Meta requirements.
    Checks: file exists, extension is mp4/mov, file size is reasonable.
    Returns {"success": bool, "duration": float, "size_mb": float, "error": str}.
    """
    result: dict = {"success": False, "duration": 0.0, "size_mb": 0.0, "error": ""}

    path = Path(file_path)
    if not path.exists():
        result["error"] = f"File not found: {file_path}"
        return result
    if not path.is_file():
        result["error"] = f"Path is not a file: {file_path}"
        return result

    ext = path.suffix.lstrip(".").lower()
    if ext not in _VIDEO_EXTENSIONS:
        result["error"] = (
            f"Unsupported video extension '.{ext}'. "
            f"Supported: {', '.join(sorted(_VIDEO_EXTENSIONS))}"
        )
        return result

    size_bytes = path.stat().st_size
    size_mb = size_bytes / (1024 * 1024)
    result["size_mb"] = round(size_mb, 2)

    if size_mb > 4096:
        result["error"] = f"Video file is too large ({size_mb:.0f} MB). Meta allows up to 4 GB."
        return result
    if size_mb == 0:
        result["error"] = "Video file is empty."
        return result

    # Attempt duration extraction via moviepy or cv2; graceful fallback
    duration = 0.0
    try:
        import cv2  # type: ignore[import]

        cap = cv2.VideoCapture(file_path)
        fps = cap.get(cv2.CAP_PROP_FPS)
        frame_count = cap.get(cv2.CAP_PROP_FRAME_COUNT)
        cap.release()
        if fps and fps > 0:
            duration = frame_count / fps
    except ImportError:
        logger.debug("cv2 not available; skipping duration extraction for %s", file_path)
    except Exception as exc:
        logger.warning("Could not read video duration for %s: %s", file_path, exc)

    result["success"] = True
    result["duration"] = round(duration, 2)
    return result


def detect_file_type(filename: str) -> str:
    """Return 'image', 'video', 'pdf', 'markdown', or 'unknown'."""
    ext = Path(filename).suffix.lstrip(".").lower()
    if ext in _IMAGE_EXTENSIONS:
        return "image"
    if ext in _VIDEO_EXTENSIONS:
        return "video"
    if ext == "pdf":
        return "pdf"
    if ext == "md":
        return "markdown"
    return "unknown"


async def save_upload_file(file_bytes: bytes, suffix: str) -> str:
    """
    Save bytes to uploads/ with a UUID-based filename.
    Returns the absolute path string of the saved file.
    """
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex}{suffix}"
    dest = UPLOAD_DIR / filename
    async with aiofiles.open(dest, "wb") as fh:
        await fh.write(file_bytes)
    logger.debug("Saved upload: %s (%d bytes)", dest, len(file_bytes))
    return str(dest)


async def cleanup_old_uploads(max_age_hours: int = 24) -> int:
    """
    Delete files in uploads/ older than max_age_hours.
    Returns the count of files deleted.
    """
    if not UPLOAD_DIR.exists():
        return 0

    cutoff = datetime.now(timezone.utc).timestamp() - (max_age_hours * 3600)
    deleted = 0
    errors = 0

    for entry in UPLOAD_DIR.iterdir():
        if not entry.is_file():
            continue
        try:
            mtime = entry.stat().st_mtime
            if mtime < cutoff:
                entry.unlink()
                deleted += 1
                logger.debug("Deleted old upload: %s", entry.name)
        except OSError as exc:
            errors += 1
            logger.warning("Could not delete upload %s: %s", entry, exc)

    if deleted or errors:
        logger.info(
            "Upload cleanup: deleted=%d, errors=%d (max_age=%dh)",
            deleted,
            errors,
            max_age_hours,
        )
    return deleted
