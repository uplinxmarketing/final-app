"""
database.py — Async SQLAlchemy database layer for Uplinx Meta Manager.

Provides:
- ORM models for all application entities
- Async engine and session factory
- Dependency-injection helper ``get_db``
- Cache utilities ``get_cached`` / ``set_cache``
- API call logging utility ``log_api_call``
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.future import select

logger = logging.getLogger("uplinx")

# ---------------------------------------------------------------------------
# Engine & session factory
# ---------------------------------------------------------------------------

import os as _os
DATABASE_URL = _os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./uplinx.db")
# Render/Railway inject postgres:// URLs; translate to async variant
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+asyncpg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

_connect_args: dict = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args = {"check_same_thread": False, "timeout": 30}
elif DATABASE_URL.startswith("postgresql"):
    # statement_cache_size=0 required for Supabase's Supavisor pooler (transaction mode)
    _connect_args = {"ssl": "require", "statement_cache_size": 0}

_engine_kwargs: dict = dict(echo=False, future=True, connect_args=_connect_args)
if DATABASE_URL.startswith("postgresql"):
    # Supabase transaction pooler: keep a small pool, recycle to avoid stale connections.
    # pool_pre_ping is omitted — it adds an extra round-trip per query over the network.
    _engine_kwargs.update(pool_size=3, max_overflow=2, pool_recycle=300, pool_timeout=30)

async_engine = create_async_engine(DATABASE_URL, **_engine_kwargs)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=async_engine,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def _enable_wal(conn):
    """Enable WAL journal mode on SQLite so concurrent reads never block writes."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    await conn.execute(text("PRAGMA journal_mode=WAL"))
    await conn.execute(text("PRAGMA synchronous=NORMAL"))
    await conn.execute(text("PRAGMA busy_timeout=30000"))


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


# ---------------------------------------------------------------------------
# Helper: UTC-aware datetime default
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------


class ConnectedMetaAccount(Base):
    """Stores OAuth credentials for a connected Facebook / Meta user account."""

    __tablename__ = "connected_meta_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    facebook_user_id: Mapped[str] = mapped_column(
        String, unique=True, nullable=False, index=True
    )
    user_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    user_email: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    encrypted_short_token: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_long_token: Mapped[str] = mapped_column(String, nullable=False)
    token_expiry: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    def __repr__(self) -> str:
        return (
            f"<ConnectedMetaAccount id={self.id} "
            f"facebook_user_id={self.facebook_user_id!r}>"
        )


class ConnectedPostingAccount(Base):
    """Stores OAuth credentials for a Meta account connected via the Posting app.

    Used exclusively for FB Page and Instagram posting — separate from the Ads app.
    """
    __tablename__ = "connected_posting_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    facebook_user_id: Mapped[str] = mapped_column(
        String, unique=True, nullable=False, index=True
    )
    user_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    user_email: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    encrypted_short_token: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_long_token: Mapped[str] = mapped_column(String, nullable=False)
    token_expiry: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # App-user who connected this Facebook account.  NULL on legacy rows.
    owner_user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    def __repr__(self) -> str:
        return (
            f"<ConnectedPostingAccount id={self.id} "
            f"facebook_user_id={self.facebook_user_id!r}>"
        )


class MetaApp(Base):
    """A Meta Developer App (App ID + encrypted App Secret) used for OAuth flows.

    Both 'ads' apps (full ads_management scopes) and 'posting' apps
    (page/instagram scopes only) are stored here.  Multiple apps of each
    type are supported so teams can rotate credentials without downtime.
    """
    __tablename__ = "meta_apps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    app_type: Mapped[str] = mapped_column(String(20), nullable=False)
    app_id: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_app_secret: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:
        return f"<MetaApp id={self.id} name={self.name!r} type={self.app_type!r}>"


class AppSetting(Base):
    """Durable key-value store for runtime configuration (API keys, models, etc.).

    On platforms with an ephemeral filesystem (e.g. Render), the ``.env`` file
    is wiped on every redeploy, so keys saved via the setup wizard are lost.
    Persisting them here — in the same Postgres DB that already holds connected
    accounts — lets them survive restarts and redeploys. Secret values are
    stored Fernet-encrypted; non-secret values (provider name, model) in plain.
    """

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_secret: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    def __repr__(self) -> str:
        return f"<AppSetting key={self.key!r} is_secret={self.is_secret}>"


class ConnectedGoogleAccount(Base):
    """Stores OAuth credentials for a connected Google account."""

    __tablename__ = "connected_google_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    google_user_id: Mapped[str] = mapped_column(
        String, unique=True, nullable=False, index=True
    )
    user_email: Mapped[str] = mapped_column(String, nullable=False)
    user_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    encrypted_access_token: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_refresh_token: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )
    token_expiry: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    def __repr__(self) -> str:
        return (
            f"<ConnectedGoogleAccount id={self.id} "
            f"google_user_id={self.google_user_id!r}>"
        )


class Client(Base):
    """Represents an advertising client / brand managed in the app."""

    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    industry: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    website: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    color_tag: Mapped[str] = mapped_column(
        String, nullable=False, default="#6c63ff"
    )
    is_archived: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    # Relationships
    ad_accounts: Mapped[list[ClientAdAccount]] = relationship(
        "ClientAdAccount", back_populates="client", cascade="all, delete-orphan"
    )
    instagram_accounts: Mapped[list[ClientInstagramAccount]] = relationship(
        "ClientInstagramAccount",
        back_populates="client",
        cascade="all, delete-orphan",
    )
    conversations: Mapped[list[Conversation]] = relationship(
        "Conversation", back_populates="client"
    )
    skills: Mapped[list[Skill]] = relationship("Skill", back_populates="client")
    quick_commands: Mapped[list[QuickCommand]] = relationship(
        "QuickCommand", back_populates="client"
    )
    scheduled_posts: Mapped[list[ScheduledPost]] = relationship(
        "ScheduledPost", back_populates="client"
    )
    posting_profiles: Mapped[list[ClientPostingProfile]] = relationship(
        "ClientPostingProfile",
        back_populates="client",
        cascade="all, delete-orphan",
        order_by="ClientPostingProfile.sort_order",
    )

    def __repr__(self) -> str:
        return f"<Client id={self.id} name={self.name!r}>"


class ClientAdAccount(Base):
    """Links a client to a specific Meta Ad Account with default campaign settings."""

    __tablename__ = "client_ad_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    nickname: Mapped[str] = mapped_column(String, nullable=False)
    meta_account_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    default_page_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    default_page_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    default_pixel_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    default_pixel_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    default_instagram_id: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )
    default_instagram_username: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )
    default_daily_budget: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )
    default_countries: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    default_age_min: Mapped[int] = mapped_column(Integer, nullable=False, default=18)
    default_age_max: Mapped[int] = mapped_column(Integer, nullable=False, default=65)
    default_timezone: Mapped[str] = mapped_column(
        String, nullable=False, default="UTC"
    )
    default_objective: Mapped[str] = mapped_column(
        String, nullable=False, default="OUTCOME_SALES"
    )
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    # Relationships
    client: Mapped[Client] = relationship("Client", back_populates="ad_accounts")
    conversations: Mapped[list[Conversation]] = relationship(
        "Conversation", back_populates="client_ad_account"
    )

    def __repr__(self) -> str:
        return (
            f"<ClientAdAccount id={self.id} nickname={self.nickname!r} "
            f"meta_account_id={self.meta_account_id!r}>"
        )


class ClientInstagramAccount(Base):
    """Maps an Instagram account to a client, optionally linked to a Facebook Page."""

    __tablename__ = "client_instagram_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    instagram_account_id: Mapped[str] = mapped_column(
        String, nullable=False, index=True
    )
    instagram_username: Mapped[str] = mapped_column(String, nullable=False)
    linked_page_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    # Relationships
    client: Mapped[Client] = relationship(
        "Client", back_populates="instagram_accounts"
    )

    def __repr__(self) -> str:
        return (
            f"<ClientInstagramAccount id={self.id} "
            f"instagram_username={self.instagram_username!r}>"
        )


class ClientPostingProfile(Base):
    """Links a client to a specific Facebook Page + optional Instagram account for posting.

    Each row represents one 'business location' under a client — a client can have
    multiple profiles (e.g. multiple franchise locations or separate brands).
    """

    __tablename__ = "client_posting_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    label: Mapped[str] = mapped_column(String, nullable=False, default="Main")
    fb_page_id: Mapped[str] = mapped_column(String, nullable=False)
    fb_page_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ig_account_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ig_username: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    client: Mapped[Client] = relationship("Client", back_populates="posting_profiles")

    def __repr__(self) -> str:
        return (
            f"<ClientPostingProfile id={self.id} client_id={self.client_id} "
            f"fb_page_id={self.fb_page_id!r} label={self.label!r}>"
        )


class Conversation(Base):
    """A Claude AI conversation thread, optionally scoped to a client / ad account."""

    __tablename__ = "conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("clients.id", ondelete="SET NULL"), nullable=True
    )
    client_ad_account_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("client_ad_accounts.id", ondelete="SET NULL"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(
        String, nullable=False, default="New Conversation"
    )
    is_pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    # Relationships
    client: Mapped[Optional[Client]] = relationship(
        "Client", back_populates="conversations"
    )
    client_ad_account: Mapped[Optional[ClientAdAccount]] = relationship(
        "ClientAdAccount", back_populates="conversations"
    )
    messages: Mapped[list[Message]] = relationship(
        "Message", back_populates="conversation", cascade="all, delete-orphan"
    )
    active_context: Mapped[Optional[ActiveContext]] = relationship(
        "ActiveContext",
        back_populates="conversation",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Conversation id={self.id} title={self.title!r}>"


class Message(Base):
    """A single message within a :class:`Conversation`."""

    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    conversation_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String, nullable=False)
    content: Mapped[str] = mapped_column(String, nullable=False)
    tool_calls: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    tokens_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    # Relationships
    conversation: Mapped[Conversation] = relationship(
        "Conversation", back_populates="messages"
    )

    def __repr__(self) -> str:
        return (
            f"<Message id={self.id} role={self.role!r} "
            f"conversation_id={self.conversation_id}>"
        )


class ActiveContext(Base):
    """Tracks the currently selected Meta resources for a conversation session."""

    __tablename__ = "active_contexts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    conversation_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    selected_meta_account_id: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )
    selected_ad_account_id: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )
    selected_page_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    selected_pixel_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    selected_instagram_id: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )
    selected_timezone: Mapped[str] = mapped_column(
        String, nullable=False, default="UTC"
    )
    overrides: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    # Relationships
    conversation: Mapped[Conversation] = relationship(
        "Conversation", back_populates="active_context"
    )

    def __repr__(self) -> str:
        return (
            f"<ActiveContext id={self.id} "
            f"conversation_id={self.conversation_id}>"
        )


class MetaCache(Base):
    """Key/value cache for Meta Graph API responses."""

    __tablename__ = "meta_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    cache_key: Mapped[str] = mapped_column(
        String, unique=True, nullable=False, index=True
    )
    cache_value: Mapped[Any] = mapped_column(JSON, nullable=False)
    account_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    def __repr__(self) -> str:
        return f"<MetaCache id={self.id} cache_key={self.cache_key!r}>"


class ImageCache(Base):
    """Maps a local file SHA-256 hash to a previously uploaded Meta image hash."""

    __tablename__ = "image_cache"
    __table_args__ = (
        UniqueConstraint("file_sha256", "ad_account_id", name="uq_image_account"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    file_sha256: Mapped[str] = mapped_column(String, nullable=False, index=True)
    file_name: Mapped[str] = mapped_column(String, nullable=False)
    meta_image_hash: Mapped[str] = mapped_column(String, nullable=False)
    ad_account_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:
        return (
            f"<ImageCache id={self.id} file_sha256={self.file_sha256!r} "
            f"ad_account_id={self.ad_account_id!r}>"
        )


class ApiCallLog(Base):
    """Audit log for outbound API calls made by the application."""

    __tablename__ = "api_call_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    account_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    endpoint: Mapped[str] = mapped_column(String, nullable=False)
    method: Mapped[str] = mapped_column(String, nullable=False)
    response_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    called_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    response_time_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<ApiCallLog id={self.id} endpoint={self.endpoint!r} "
            f"method={self.method!r} response_code={self.response_code}>"
        )


class Skill(Base):
    """A user-defined Python skill file that can be invoked during conversations."""

    __tablename__ = "skills"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    file_path: Mapped[str] = mapped_column(String, nullable=False)
    client_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("clients.id", ondelete="SET NULL"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    # Relationships
    client: Mapped[Optional[Client]] = relationship("Client", back_populates="skills")

    def __repr__(self) -> str:
        return f"<Skill id={self.id} name={self.name!r}>"


class QuickCommand(Base):
    """A saved prompt shortcut triggered by a slash-style command."""

    __tablename__ = "quick_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    trigger: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    prompt_template: Mapped[str] = mapped_column(String, nullable=False)
    client_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("clients.id", ondelete="SET NULL"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    # Relationships
    client: Mapped[Optional[Client]] = relationship(
        "Client", back_populates="quick_commands"
    )

    def __repr__(self) -> str:
        return f"<QuickCommand id={self.id} trigger={self.trigger!r}>"


class User(Base):
    """An application user with role-based access control."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    email: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String(10), nullable=False, default="user")
    interface_access: Mapped[str] = mapped_column(String(10), nullable=False, default="both")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role!r}>"


class UserPageAssignment(Base):
    """Links a user to a specific FB page or IG account they are allowed to access."""

    __tablename__ = "user_page_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    page_id: Mapped[str] = mapped_column(String, nullable=False)
    page_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    platform: Mapped[str] = mapped_column(String(20), nullable=False)
    meta_app_db_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:
        return (
            f"<UserPageAssignment id={self.id} user_id={self.user_id} "
            f"page_id={self.page_id!r} platform={self.platform!r}>"
        )


class UserApiUsage(Base):
    """Durable per-app-user API usage counters (Meta calls + AI tokens).

    One row per user, incremented as work happens.  Survives restarts —
    unlike the in-memory session trackers — so the admin dashboard can show
    lifetime usage per user.
    """

    __tablename__ = "user_api_usage"

    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    meta_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ai_input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ai_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ai_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    def __repr__(self) -> str:
        return f"<UserApiUsage user_id={self.user_id} meta={self.meta_calls} ai={self.ai_input_tokens + self.ai_output_tokens}>"


async def bump_user_usage(
    db: "AsyncSession",
    user_id: Optional[int],
    *,
    meta_calls: int = 0,
    ai_input: int = 0,
    ai_output: int = 0,
    ai_calls: int = 0,
) -> None:
    """Increment a user's durable usage counters.  No-op when user_id is None.

    Commits its own change; swallows errors so usage tracking never breaks the
    request it piggybacks on.
    """
    if not user_id or (not meta_calls and not ai_input and not ai_output and not ai_calls):
        return
    try:
        row = await db.get(UserApiUsage, user_id)
        if row is None:
            row = UserApiUsage(user_id=user_id)
            db.add(row)
        row.meta_calls = (row.meta_calls or 0) + meta_calls
        row.ai_input_tokens = (row.ai_input_tokens or 0) + ai_input
        row.ai_output_tokens = (row.ai_output_tokens or 0) + ai_output
        row.ai_calls = (row.ai_calls or 0) + ai_calls
        row.updated_at = _utcnow()
        await db.commit()
    except Exception:
        try:
            await db.rollback()
        except Exception:
            pass


class UserClientAssignment(Base):
    """Links a user to a client they are allowed to manage."""

    __tablename__ = "user_client_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    client_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (UniqueConstraint("user_id", "client_id"),)

    def __repr__(self) -> str:
        return f"<UserClientAssignment id={self.id} user_id={self.user_id} client_id={self.client_id}>"


class BusinessPortfolio(Base):
    """A user-owned grouping of Facebook Pages + Instagram accounts.

    Lets a user pick one portfolio to target all its assigned pages at once
    (e.g. a brand's FB Page + IG account) instead of selecting each one. Pages
    are stored as a JSON list of ``{platform, id, name}`` entries. Saved per
    user account so each user organises their own portfolios.
    """

    __tablename__ = "business_portfolios"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    pages: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:
        return f"<BusinessPortfolio id={self.id} user_id={self.user_id} name={self.name!r}>"


class MediaProxyToken(Base):
    """A short-lived public token mapping to a Google Drive file.

    Instagram publishing requires a public URL Meta fetches itself. We mint a
    token that points at a Drive file (by id) and the Google account that can
    read it (by user id) — never the access token itself. The ``/media/{token}``
    endpoint resolves a fresh Google token at fetch time and streams the bytes,
    so nothing is written to disk and no secret is stored. DB-backed so it works
    across multiple server workers.
    """

    __tablename__ = "media_proxy_tokens"

    token: Mapped[str] = mapped_column(String, primary_key=True)
    drive_file_id: Mapped[str] = mapped_column(String, nullable=False)
    google_user_id: Mapped[str] = mapped_column(String, nullable=False)
    mime_type: Mapped[str] = mapped_column(
        String, nullable=False, default="application/octet-stream"
    )
    filename: Mapped[str] = mapped_column(String, nullable=False, default="media")
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:
        return f"<MediaProxyToken token={self.token[:8]}… file={self.drive_file_id!r}>"


class ScheduledPost(Base):
    """A social media post scheduled for future publication."""

    __tablename__ = "scheduled_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("clients.id", ondelete="SET NULL"), nullable=True
    )
    ad_account_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    platform: Mapped[str] = mapped_column(String, nullable=False)
    page_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    instagram_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    caption: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    media_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    media_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    scheduled_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    timezone: Mapped[str] = mapped_column(String, nullable=False, default="UTC")
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    meta_post_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Self-published Drive jobs (e.g. Instagram, which has no native scheduling).
    # Holds everything the background worker needs to publish at the due time:
    # {media:[{drive_file_id,mime_type,filename}], hashtags:[...], media_type,
    #  page_id, instagram_id, posting_user_id, google_user_id, base_url}
    job_data: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Atomic-claim fields so multiple workers never publish the same row twice.
    claimed_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    claimed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Earliest time at which a pending retry should be attempted (exponential back-off).
    next_retry_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    published_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    client: Mapped[Optional[Client]] = relationship(
        "Client", back_populates="scheduled_posts"
    )

    def __repr__(self) -> str:
        return (
            f"<ScheduledPost id={self.id} platform={self.platform!r} "
            f"status={self.status!r}>"
        )


class PublishJob(Base):
    """A bulk publish request processed asynchronously by a background worker.

    Lets an employee submit 12–22 posts at once and walk away, while the server
    works through them one item at a time. Multiple users' jobs queue up; each
    job tracks live progress so every user's frontend can show what's happening
    and whether they have to wait.
    """

    __tablename__ = "publish_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_by_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # queued → running → done / failed
    status: Mapped[str] = mapped_column(String, nullable=False, default="queued", index=True)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    succeeded: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scheduled_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # The list of post items to publish + per-item results (JSON).
    items: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    results: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    # Context the worker needs to publish on the submitter's behalf.
    posting_user_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    google_user_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    base_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    claimed_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<PublishJob id={self.id} status={self.status!r} "
            f"{self.completed}/{self.total}>"
        )


# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------


async def init_db() -> None:
    """Create all database tables, run schema migrations, and enable WAL mode on startup."""
    async with async_engine.begin() as conn:
        await _enable_wal(conn)
        await conn.run_sync(Base.metadata.create_all)
        from sqlalchemy import text as _text
        for _stmt in [
            "ALTER TABLE connected_meta_accounts ADD COLUMN IF NOT EXISTS meta_app_db_id INTEGER",
            "ALTER TABLE connected_posting_accounts ADD COLUMN IF NOT EXISTS meta_app_db_id INTEGER",
            "ALTER TABLE scheduled_posts ADD COLUMN IF NOT EXISTS job_data JSON",
            "ALTER TABLE scheduled_posts ADD COLUMN IF NOT EXISTS attempts INTEGER DEFAULT 0",
            "ALTER TABLE scheduled_posts ADD COLUMN IF NOT EXISTS claimed_by VARCHAR",
            "ALTER TABLE scheduled_posts ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE connected_posting_accounts ADD COLUMN IF NOT EXISTS owner_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL",
            "ALTER TABLE scheduled_posts ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMP WITH TIME ZONE",
        ]:
            try:
                await conn.execute(_text(_stmt))
            except Exception:
                pass
    logger.info("Database tables initialised.")


# ---------------------------------------------------------------------------
# Durable app-settings store (survives redeploys on ephemeral filesystems)
# ---------------------------------------------------------------------------

# Which settings are secrets (Fernet-encrypted at rest) vs. plain values.
_SECRET_SETTING_KEYS = {
    "META_APP_SECRET", "META_POSTING_APP_SECRET",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY",
    "GOOGLE_CLIENT_SECRET",
}


async def save_app_setting(key: str, value: str, db: AsyncSession) -> None:
    """Persist a single setting to the DB, encrypting it if it's a secret.

    Empty values are ignored so we never clobber a stored key with a blank.
    """
    if not value:
        return
    is_secret = key in _SECRET_SETTING_KEYS
    stored = value
    if is_secret:
        from security import fernet_encryption
        stored = fernet_encryption.encrypt(value)
    row = await db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=stored, is_secret=is_secret))
    else:
        row.value = stored
        row.is_secret = is_secret


async def delete_app_setting(key: str, db: AsyncSession) -> None:
    """Remove a setting from the DB (used when a key is cleared)."""
    row = await db.get(AppSetting, key)
    if row is not None:
        await db.delete(row)


async def load_app_settings(db: AsyncSession) -> dict[str, str]:
    """Return all stored settings as a plain {key: decrypted_value} dict."""
    result = await db.execute(select(AppSetting))
    out: dict[str, str] = {}
    for row in result.scalars().all():
        val = row.value
        if row.is_secret and val:
            from security import fernet_encryption
            val = fernet_encryption.decrypt(val)
        out[row.key] = val
    return out


# ---------------------------------------------------------------------------
# Dependency injection helper
# ---------------------------------------------------------------------------


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an :class:`AsyncSession`."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ---------------------------------------------------------------------------
# Cache utilities
# ---------------------------------------------------------------------------


async def get_cached(cache_key: str, db: AsyncSession) -> Optional[Any]:
    """Retrieve a cached value by key if it has not yet expired."""
    now = datetime.now(timezone.utc)
    stmt = select(MetaCache).where(
        MetaCache.cache_key == cache_key,
        MetaCache.expires_at > now,
    )
    result = await db.execute(stmt)
    row: Optional[MetaCache] = result.scalar_one_or_none()
    if row is None:
        return None
    return row.cache_value


async def set_cache(
    cache_key: str,
    value: Any,
    account_id: Optional[str],
    ttl_seconds: int,
    db: AsyncSession,
) -> None:
    """Insert or update a cache entry with a TTL."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)

    stmt = select(MetaCache).where(MetaCache.cache_key == cache_key)
    result = await db.execute(stmt)
    existing: Optional[MetaCache] = result.scalar_one_or_none()

    if existing:
        existing.cache_value = value
        existing.account_id = account_id
        existing.cached_at = now
        existing.expires_at = expires_at
    else:
        new_entry = MetaCache(
            cache_key=cache_key,
            cache_value=value,
            account_id=account_id,
            cached_at=now,
            expires_at=expires_at,
        )
        db.add(new_entry)

    logger.debug("Cache set: key=%r ttl=%ds", cache_key, ttl_seconds)


# ---------------------------------------------------------------------------
# API call logging
# ---------------------------------------------------------------------------


async def log_api_call(
    db: AsyncSession,
    endpoint: str,
    method: str,
    account_id: Optional[str] = None,
    response_code: Optional[int] = None,
    error_message: Optional[str] = None,
    response_time_ms: Optional[int] = None,
) -> None:
    """Persist an outbound API call record to :class:`ApiCallLog`."""
    log_entry = ApiCallLog(
        endpoint=endpoint,
        method=method.upper(),
        account_id=account_id,
        response_code=response_code,
        error_message=error_message,
        response_time_ms=response_time_ms,
        called_at=datetime.now(timezone.utc),
    )
    db.add(log_entry)
    await db.flush()
    logger.debug(
        "API call logged: %s %s -> %s (%sms)",
        method.upper(),
        endpoint,
        response_code,
        response_time_ms,
    )
