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
        ]:
            try:
                await conn.execute(_text(_stmt))
            except Exception:
                pass
    logger.info("Database tables initialised.")


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
