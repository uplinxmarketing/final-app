"""
config.py — Application settings for Uplinx Meta Manager.

Loads configuration from a .env file using pydantic-settings.
A singleton ``settings`` instance is exported for use across the application.
"""

from __future__ import annotations

from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All runtime configuration for Uplinx Meta Manager.

    Values are read from environment variables or a ``.env`` file located in
    the working directory.  Every attribute maps 1-to-1 to an environment
    variable of the same name (case-insensitive on most platforms).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Meta / Facebook
    # ------------------------------------------------------------------

    META_APP_ID: str = ""
    """Facebook App ID obtained from the Meta developer dashboard."""

    META_APP_SECRET: str = ""
    """Facebook App Secret — keep out of source control."""

    META_API_VERSION: str = "v21.0"
    """Graph API version, e.g. ``v21.0``."""

    META_REDIRECT_URI: str = "http://localhost:8000/auth/meta/callback"
    """OAuth redirect URI registered in the Meta app settings."""

    META_CONFIG_ID: str = ""
    """Facebook Login for Business configuration ID for the Ads app. When set,
    the OAuth flow uses the business-login (config_id) flow instead of the
    classic scope-based flow. Leave blank for classic Facebook Login apps."""

    META_POSTING_APP_ID: str = ""
    """Facebook App ID for the separate Posting app (Instagram & FB Page posting)."""

    META_POSTING_APP_SECRET: str = ""
    """Facebook App Secret for the Posting app — keep out of source control."""

    META_POSTING_REDIRECT_URI: str = ""
    """OAuth redirect URI registered in the Posting Meta app settings."""

    META_POSTING_CONFIG_ID: str = ""
    """Facebook Login for Business configuration ID for the Posting app."""

    # ------------------------------------------------------------------
    # Google
    # ------------------------------------------------------------------

    GOOGLE_CLIENT_ID: str = ""
    """Google OAuth 2.0 client ID."""

    GOOGLE_CLIENT_SECRET: str = ""
    """Google OAuth 2.0 client secret."""

    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"
    """OAuth redirect URI registered in the Google Cloud Console."""

    # ------------------------------------------------------------------
    # Anthropic / Claude
    # ------------------------------------------------------------------

    ANTHROPIC_API_KEY: str = ""
    """Anthropic API key used to authenticate Claude API requests."""

    CLAUDE_MODEL: str = "claude-opus-4-7"
    """Claude model to use, e.g. claude-opus-4-7, claude-sonnet-4-6, claude-haiku-4-5-20251001."""

    # ------------------------------------------------------------------
    # AI Provider
    # ------------------------------------------------------------------

    AI_PROVIDER: str = "claude"
    """Active AI provider: 'claude', 'openai', or 'groq'."""

    OPENAI_API_KEY: str = ""
    """OpenAI API key (used when AI_PROVIDER=openai)."""

    OPENAI_MODEL: str = "gpt-4o"
    """OpenAI model name, e.g. gpt-4o, gpt-4-turbo."""

    GROQ_API_KEY: str = ""
    """Groq API key (used when AI_PROVIDER=groq)."""

    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    """Groq model name, e.g. llama-3.3-70b-versatile."""

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------

    SECRET_KEY: str = "change-me-in-production-use-a-long-random-string"
    """Secret key used to sign session tokens (itsdangerous / JWT)."""

    LOGIN_PASSWORD: str = ""
    """Shared team password. When set, a login screen is shown before the app.
    Leave blank to skip the login screen entirely."""

    ADMIN_EMAIL: str = ""
    """Email address for the built-in admin account. Synced on every startup."""

    # ------------------------------------------------------------------
    # SMTP / Outbound email
    # ------------------------------------------------------------------

    SMTP_HOST: str = ""
    """SMTP server hostname (e.g. smtp.gmail.com)."""

    SMTP_PORT: int = 587
    """SMTP port. 587 = STARTTLS (recommended), 465 = SSL."""

    SMTP_USER: str = ""
    """SMTP login username (usually the sender email address)."""

    SMTP_PASS: str = ""
    """SMTP login password or app-specific password."""

    SMTP_FROM: str = ""
    """From address for outbound CRM emails. Falls back to SMTP_USER if blank."""

    SMTP_FROM_NAME: str = "Uplinx CRM"
    """Display name for the From address."""

    ADMIN_PASSWORD: str = ""
    """If set, the 'admin' account password is created/updated to this value on every startup."""

    ENCRYPTION_KEY: str = ""
    """Fernet symmetric encryption key (base-64 url-safe, 32 bytes).

    Generate with::

        from cryptography.fernet import Fernet
        print(Fernet.generate_key().decode())
    """

    # ------------------------------------------------------------------
    # Server / CORS / Deployment
    # ------------------------------------------------------------------

    BASE_URL: str = "http://localhost:8000"
    """Public base URL of the app (e.g. https://myapp.onrender.com). Used to
    build OAuth redirect URIs and CORS origins automatically when deployed."""

    PORT: int = 8000
    """Port the Uvicorn server listens on."""

    ALLOWED_HOSTS: str = "localhost,127.0.0.1"
    """Comma-separated hosts allowed to access the API."""

    CORS_ORIGINS: str = ""
    """Explicit comma-separated CORS origins. If blank, derived from BASE_URL."""

    DATABASE_URL: str = "sqlite+aiosqlite:///./uplinx.db"
    """Async SQLAlchemy database URL. Defaults to a local SQLite file."""

    @property
    def allowed_hosts_list(self) -> List[str]:
        """Return ALLOWED_HOSTS as a list, supporting comma-separated values."""
        return [h.strip() for h in self.ALLOWED_HOSTS.split(",") if h.strip()]

    @property
    def cors_origins_list(self) -> List[str]:
        """CORS origins derived from CORS_ORIGINS env var or BASE_URL."""
        if self.CORS_ORIGINS.strip():
            return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]
        origins = {self.BASE_URL.rstrip("/")}
        origins.update(["http://localhost:8000", "http://127.0.0.1:8000"])
        return list(origins)

    @property
    def meta_redirect_uri(self) -> str:
        """OAuth callback URI for Meta, built from BASE_URL when not overridden."""
        if self.META_REDIRECT_URI and not self.META_REDIRECT_URI.startswith("http://localhost"):
            return self.META_REDIRECT_URI
        return f"{self.BASE_URL.rstrip('/')}/auth/meta/callback"

    @property
    def meta_posting_redirect_uri(self) -> str:
        """OAuth callback URI for posting Meta app, built from BASE_URL."""
        if self.META_POSTING_REDIRECT_URI and not self.META_POSTING_REDIRECT_URI.startswith("http://localhost"):
            return self.META_POSTING_REDIRECT_URI
        return f"{self.BASE_URL.rstrip('/')}/auth/meta/posting/callback"

    @property
    def google_redirect_uri(self) -> str:
        """OAuth callback URI for Google, built from BASE_URL when not overridden."""
        if self.GOOGLE_REDIRECT_URI and not self.GOOGLE_REDIRECT_URI.startswith("http://localhost"):
            return self.GOOGLE_REDIRECT_URI
        return f"{self.BASE_URL.rstrip('/')}/auth/google/callback"

    # ------------------------------------------------------------------
    # File handling
    # ------------------------------------------------------------------

    MAX_UPLOAD_SIZE_MB: int = 100
    """Maximum file upload size in megabytes."""

    # ------------------------------------------------------------------
    # Caching
    # ------------------------------------------------------------------

    CACHE_TTL_SECONDS: int = 3600
    """Default time-to-live for cached API responses, in seconds."""

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    LOG_LEVEL: str = "INFO"
    """Python logging level name (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``)."""

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    AUTO_CLEAR_UPLOADS_HOURS: int = 24
    """Number of hours after which uploaded files are automatically purged."""

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure LOG_LEVEL is a recognised Python logging level name."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}, got {v!r}")
        return upper

    @field_validator("META_API_VERSION")
    @classmethod
    def validate_api_version(cls, v: str) -> str:
        """Ensure META_API_VERSION follows the ``vNN.N`` pattern."""
        import re

        if not re.match(r"^v\d+\.\d+$", v):
            raise ValueError(
                f"META_API_VERSION must match 'vNN.N' format, got {v!r}"
            )
        return v

    @field_validator("MAX_UPLOAD_SIZE_MB")
    @classmethod
    def validate_upload_size(cls, v: int) -> int:
        """Upload size must be a positive integer."""
        if v <= 0:
            raise ValueError("MAX_UPLOAD_SIZE_MB must be a positive integer")
        return v

    @field_validator("CACHE_TTL_SECONDS")
    @classmethod
    def validate_cache_ttl(cls, v: int) -> int:
        """Cache TTL must be a positive integer."""
        if v <= 0:
            raise ValueError("CACHE_TTL_SECONDS must be a positive integer")
        return v

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------

    @property
    def max_upload_size_bytes(self) -> int:
        """Return :attr:`MAX_UPLOAD_SIZE_MB` converted to bytes."""
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def meta_graph_base_url(self) -> str:
        """Fully-qualified base URL for the Meta Graph API."""
        return f"https://graph.facebook.com/{self.META_API_VERSION}"


# ---------------------------------------------------------------------------
# Singleton — import this throughout the application
# ---------------------------------------------------------------------------

settings = Settings()
