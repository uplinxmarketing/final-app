"""
security.py — Security utilities for Uplinx Meta Manager.

Provides:
- Fernet-based symmetric encryption / decryption for persisted tokens
- Input validation and sanitisation helpers
- Session token creation and verification (itsdangerous)
- OAuth state generation and constant-time comparison
- Application-wide logging setup with rotating file handler
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import logging.handlers
import re
import secrets
import struct
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from config import settings

# ---------------------------------------------------------------------------
# Module-level logger (used before setup_logging may be called)
# ---------------------------------------------------------------------------

_logger = logging.getLogger("uplinx")


# ---------------------------------------------------------------------------
# 1. Fernet encryption
# ---------------------------------------------------------------------------


class FernetEncryption:
    """Symmetric encryption wrapper backed by :class:`cryptography.fernet.Fernet`.

    A single instance is intended to be shared across the application.  The
    encryption key is sourced from :attr:`config.Settings.ENCRYPTION_KEY` at
    construction time.

    Example::

        enc = FernetEncryption()
        ciphertext = enc.encrypt("my-secret-token")
        plaintext  = enc.decrypt(ciphertext)
    """

    def __init__(self) -> None:
        """Initialise the Fernet cipher using the configured encryption key.

        Raises:
            ValueError: If ``ENCRYPTION_KEY`` is empty or not a valid Fernet key.
        """
        raw_key: str = settings.ENCRYPTION_KEY
        if not raw_key:
            _logger.warning(
                "ENCRYPTION_KEY is not set — generating an ephemeral key.  "
                "Persisted tokens will not survive a restart."
            )
            raw_key = Fernet.generate_key().decode()

        self._fernet = Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext* and return a URL-safe base-64 encoded ciphertext.

        Args:
            plaintext: The string value to encrypt.

        Returns:
            A URL-safe base-64 encoded ciphertext string.
        """
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt *ciphertext* and return the original plaintext.

        Args:
            ciphertext: A URL-safe base-64 encoded ciphertext produced by
                :meth:`encrypt`.

        Returns:
            The original plaintext string, or ``""`` if decryption fails (the
            failure is logged at WARNING level so it does not silently swallow
            genuine errors during debugging).
        """
        try:
            return self._fernet.decrypt(
                ciphertext.encode("utf-8") if isinstance(ciphertext, str) else ciphertext
            ).decode("utf-8")
        except (InvalidToken, Exception) as exc:  # noqa: BLE001
            _logger.warning("Fernet decryption failed: %s", exc)
            return ""


# Module-level singleton — import this throughout the application.
fernet_encryption = FernetEncryption()


# ---------------------------------------------------------------------------
# 2. Input validation and sanitisation
# ---------------------------------------------------------------------------

# Matches any HTML/XML tag such as <script>, </div>, <br />, etc.
_HTML_TAG_RE = re.compile(r"<[^>]+>", re.DOTALL)

# Matches characters that are dangerous in file paths or shell contexts.
_DANGEROUS_FILENAME_CHARS_RE = re.compile(r'[\\/:*?"<>|]')

# Allowed file extensions (lower-cased).
_ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    {"jpg", "jpeg", "png", "gif", "mp4", "mov", "pdf", "md"}
)

# Magic-byte signatures for common binary formats.
# Each entry is (offset, magic_bytes, extension_hint).
_MAGIC_SIGNATURES: list[tuple[int, bytes, str]] = [
    # JPEG
    (0, b"\xff\xd8\xff", "jpg"),
    # PNG
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    # GIF87a / GIF89a
    (0, b"GIF87a", "gif"),
    (0, b"GIF89a", "gif"),
    # MP4 / MOV (ftyp box at offset 4)
    (4, b"ftyp", "mp4"),
    # RIFF container (AVI / WAV — broad check)
    (0, b"RIFF", "riff"),
    # PDF
    (0, b"%PDF", "pdf"),
]

# Path-traversal sequences.
_PATH_TRAVERSAL_RE = re.compile(r"(\.\.[\\/]|[\\/]\.\.)")


def sanitize_text(text: str, max_length: int = 10_000) -> str:
    """Remove HTML tags from *text* and enforce a maximum character length.

    Args:
        text: Raw input string, possibly containing HTML markup.
        max_length: Maximum number of characters to retain.  Defaults to
            ``10_000``.

    Returns:
        Sanitised plain-text string, truncated to *max_length* characters.
    """
    stripped = _HTML_TAG_RE.sub("", text)
    return stripped[:max_length]


def validate_numeric_id(value: str) -> bool:
    """Return ``True`` if *value* consists entirely of ASCII decimal digits.

    Meta entity IDs (ad accounts, pages, pixels …) are numeric strings.  This
    helper rejects any value that contains non-digit characters, guarding
    against injection via ID parameters.

    Args:
        value: The string to validate.

    Returns:
        ``True`` if *value* is a non-empty all-digit string, ``False``
        otherwise.
    """
    return bool(value) and value.isdigit()


def validate_url(url: str) -> bool:
    """Return ``True`` if *url* is an absolute HTTP or HTTPS URL.

    Args:
        url: The URL string to validate.

    Returns:
        ``True`` when the URL begins with ``http://`` or ``https://`` and
        parses to a valid structure with a non-empty netloc.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return False

    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def validate_file_extension(filename: str) -> bool:
    """Return ``True`` if *filename* has an allowed extension.

    Allowed extensions: ``jpg``, ``jpeg``, ``png``, ``gif``, ``mp4``,
    ``mov``, ``pdf``, ``md``.

    Args:
        filename: The original file name (may include directory components).

    Returns:
        ``True`` if the extension (lower-cased, without leading dot) is in the
        allowed set.
    """
    suffix = Path(filename).suffix.lstrip(".").lower()
    return suffix in _ALLOWED_EXTENSIONS


def validate_mime_type(file_bytes: bytes, filename: str) -> bool:
    """Validate *file_bytes* against known magic-byte signatures.

    Performs a content-based MIME check rather than trusting the client-
    supplied Content-Type header.  Only image and video formats are validated
    by magic bytes; ``.pdf`` and ``.md`` files are accepted by extension only.

    Args:
        file_bytes: The first bytes of the uploaded file (at least 16 bytes
            recommended for reliable detection).
        filename: The uploaded file name — used to allow extension-only
            validation for formats without a strict magic-byte check.

    Returns:
        ``True`` if the content appears to match a supported format.
    """
    if not file_bytes:
        return False

    ext = Path(filename).suffix.lstrip(".").lower()

    # PDF and Markdown — accept by extension only (no strict magic check needed).
    if ext in {"pdf", "md"}:
        return ext in _ALLOWED_EXTENSIONS

    for offset, magic, _ in _MAGIC_SIGNATURES:
        if file_bytes[offset : offset + len(magic)] == magic:
            return True

    return False


def sanitize_filename(filename: str) -> str:
    """Remove path-traversal and shell-dangerous characters from *filename*.

    Strips leading/trailing whitespace and dots, removes all characters that
    could be used for path traversal or shell injection, and falls back to
    ``"upload"`` if the result is empty.

    Args:
        filename: The raw file name supplied by the client.

    Returns:
        A sanitised file name safe for use in the uploads directory.
    """
    # Take only the final component to neutralise directory separators.
    name = Path(filename).name
    # Strip dangerous characters.
    name = _DANGEROUS_FILENAME_CHARS_RE.sub("", name)
    # Collapse any whitespace runs to underscores.
    name = re.sub(r"\s+", "_", name)
    # Strip leading dots / whitespace.
    name = name.lstrip(". ")
    return name if name else "upload"


def check_path_traversal(path: str) -> bool:
    """Return ``True`` if *path* is free of path-traversal sequences.

    Checks for ``../``, ``..\\``, ``/..``, and ``\\..`` patterns.

    Args:
        path: A file system path string to inspect.

    Returns:
        ``True`` if the path appears safe; ``False`` if it contains traversal
        sequences.
    """
    return not bool(_PATH_TRAVERSAL_RE.search(path))


# ---------------------------------------------------------------------------
# 3. Session utilities
# ---------------------------------------------------------------------------

_serializer: Optional[URLSafeTimedSerializer] = None


def _get_serializer() -> URLSafeTimedSerializer:
    """Return (and lazily create) the shared :class:`URLSafeTimedSerializer`."""
    global _serializer  # noqa: PLW0603
    if _serializer is None:
        _serializer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="session")
    return _serializer


def create_session_token(data: dict[str, Any]) -> str:
    """Sign and serialise *data* into a URL-safe timed token.

    The token embeds a timestamp so that :func:`verify_session_token` can
    enforce maximum-age constraints server-side.

    Args:
        data: A JSON-serialisable dictionary to embed in the token.

    Returns:
        A URL-safe signed token string suitable for use in a cookie or header.
    """
    return _get_serializer().dumps(data)


def verify_session_token(
    token: str,
    max_age: int = 28_800,
) -> Optional[dict[str, Any]]:
    """Verify and decode a session token produced by :func:`create_session_token`.

    Args:
        token: The signed token string to verify.
        max_age: Maximum acceptable token age in seconds.  Defaults to
            ``28_800`` (8 hours).

    Returns:
        The decoded data dictionary if the token is valid and not expired,
        otherwise ``None``.
    """
    try:
        return _get_serializer().loads(token, max_age=max_age)
    except SignatureExpired:
        _logger.warning("Session token has expired.")
        return None
    except BadSignature:
        _logger.warning("Session token has an invalid signature.")
        return None
    except Exception as exc:  # noqa: BLE001
        _logger.warning("Session token verification failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# 4. OAuth state management
# ---------------------------------------------------------------------------


def generate_oauth_state() -> str:
    """Generate a cryptographically random OAuth ``state`` parameter.

    Returns:
        A 32-byte URL-safe base-64 encoded random string.
    """
    return secrets.token_urlsafe(32)


def verify_oauth_state(provided: str, expected: str) -> bool:
    """Compare two OAuth state strings using a constant-time algorithm.

    Using :func:`hmac.compare_digest` prevents timing-based enumeration of the
    expected value.

    Args:
        provided: The ``state`` value received from the OAuth callback.
        expected: The ``state`` value that was originally generated and stored
            server-side (e.g. in the user's session).

    Returns:
        ``True`` if both strings are identical, ``False`` otherwise.
    """
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided, expected)


# ---------------------------------------------------------------------------
# 5. Logging setup
# ---------------------------------------------------------------------------


def setup_logging() -> logging.Logger:
    """Configure application-wide logging with a rotating file handler.

    Sets up two handlers on the ``"uplinx"`` logger:

    * A :class:`~logging.handlers.RotatingFileHandler` writing to
      ``security.log`` (10 MB per file, 5 backup files).
    * A :class:`~logging.StreamHandler` writing to the console (stdout).

    The log level is taken from :attr:`config.Settings.LOG_LEVEL`.

    Returns:
        The configured ``"uplinx"`` :class:`logging.Logger` instance.
    """
    log_level: int = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    log_format = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    # --- Rotating file handler -------------------------------------------
    file_handler = logging.handlers.RotatingFileHandler(
        filename="security.log",
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(log_format)

    # --- Console (stream) handler ----------------------------------------
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(log_format)

    # --- Root "uplinx" logger --------------------------------------------
    logger = logging.getLogger("uplinx")
    logger.setLevel(log_level)

    # Avoid duplicate handlers if setup_logging is called more than once.
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    # Prevent propagation to the root logger to avoid duplicate output.
    logger.propagate = False

    logger.info("Logging initialised at level %s.", settings.LOG_LEVEL)
    return logger
