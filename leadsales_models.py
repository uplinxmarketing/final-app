"""
leadsales_models.py — Leads & Sales CRM data models.

ISOLATION GUARANTEES (why the posting app can never be harmed):
  - Lives in the 'leadsales' PostgreSQL schema (separate from the posting app's
    'public' schema and from admin_models' crm_ tables).
  - Every table is ls_-prefixed.
  - Uses its own LeadSalesBase — create_all only ever touches ls_* tables.
  - Uses its own async engine reading CRM_DATABASE_URL (a fully separate
    Postgres if you want) or falling back to DATABASE_URL + the leadsales schema.
  - All migrations are additive (CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT
    EXISTS). Nothing is ever dropped or recreated.

Data model (Phase 1):
  ls_leads           — the pipeline (name, stage, meeting, follow-up, notes…)
  ls_services        — reusable single-service catalog
  ls_packages        — reusable named bundles (templates)
  ls_package_items   — line items belonging to a package template
  ls_proposal_items  — the per-lead package being discussed/sold (with per-item note)
  ls_events          — in-app calendar events (fallback when Google isn't connected)
  ls_google_account  — encrypted Google Calendar (read-only) connection
"""
from __future__ import annotations

import logging
import os as _os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, Numeric, String, Text, text as _text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

logger = logging.getLogger("uplinx.leadsales")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Engine — CRM_DATABASE_URL preferred; falls back to main DATABASE_URL
# ---------------------------------------------------------------------------
_raw = _os.environ.get("CRM_DATABASE_URL") or _os.environ.get("DATABASE_URL", "")
if _raw.startswith("postgres://"):
    _raw = _raw.replace("postgres://", "postgresql+asyncpg://", 1)
elif _raw.startswith("postgresql://") and "+asyncpg" not in _raw:
    _raw = _raw.replace("postgresql://", "postgresql+asyncpg://", 1)

_is_pg = _raw.startswith("postgresql")
_connect_args: dict = {}
if _raw.startswith("sqlite"):
    _connect_args = {"check_same_thread": False, "timeout": 30}
elif _is_pg:
    _connect_args = {"ssl": "require", "statement_cache_size": 0}

_engine_kw: dict = dict(echo=False, future=True, connect_args=_connect_args)
if _is_pg:
    _engine_kw.update(pool_size=2, max_overflow=1, pool_recycle=300, pool_timeout=30)

crm_engine = create_async_engine(_raw or "sqlite+aiosqlite:///./leads.db", **_engine_kw)

CRMSession: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=crm_engine, expire_on_commit=False, autocommit=False, autoflush=False,
)

# Schema: 'leadsales' on Postgres, None (public) on SQLite
_SCHEMA: Optional[str] = "leadsales" if _is_pg else None
IS_PG = _is_pg
SCHEMA = _SCHEMA


def _q(table: str) -> str:
    """Return a schema-qualified table name for raw SQL."""
    return f"{_SCHEMA}.{table}" if _SCHEMA else table


_FK_LEADS = _q("ls_leads") + ".id"
_FK_PKG = _q("ls_packages") + ".id"


# ---------------------------------------------------------------------------
# Declarative base — completely separate from Base and AdminBase
# ---------------------------------------------------------------------------
class LeadSalesBase(DeclarativeBase):
    """Isolated base — create_all only touches ls_* tables in leadsales schema."""


def _table_args(extra: dict | None = None) -> dict:
    d: dict = {}
    if _SCHEMA:
        d["schema"] = _SCHEMA
    if extra:
        d.update(extra)
    return d


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class LSLead(LeadSalesBase):
    __tablename__ = "ls_leads"
    __table_args__ = _table_args()

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    company: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    website: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    social_links: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fiverr_link: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False, default="Fiverr")
    # Stored in the legacy "status" column for additive compatibility, but the
    # value domain is the brief's stage enum: new | active | won | lost.
    stage: Mapped[str] = mapped_column("status", String(20), nullable=False, default="new")
    follow_up_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    meeting_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    calendar_event_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_customer: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Stored in the legacy "notes" column; brief calls it general_notes.
    general_notes: Mapped[Optional[str]] = mapped_column("notes", Text, nullable=True)
    won_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    won_package_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    items: Mapped[list["LSProposalItem"]] = relationship(
        "LSProposalItem", back_populates="lead", cascade="all, delete-orphan",
        order_by="LSProposalItem.sort_order, LSProposalItem.id",
    )


class LSService(LeadSalesBase):
    __tablename__ = "ls_services"
    __table_args__ = _table_args()

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    default_price: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False, default=0)
    default_cost: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False, default=0)
    # one_time | monthly
    billing_type: Mapped[str] = mapped_column(String(20), nullable=False, default="one_time")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class LSPackage(LeadSalesBase):
    __tablename__ = "ls_packages"
    __table_args__ = _table_args()

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    items: Mapped[list["LSPackageItem"]] = relationship(
        "LSPackageItem", back_populates="package", cascade="all, delete-orphan",
        order_by="LSPackageItem.sort_order, LSPackageItem.id",
    )


class LSPackageItem(LeadSalesBase):
    __tablename__ = "ls_package_items"
    __table_args__ = _table_args()

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    package_id: Mapped[int] = mapped_column(
        Integer, ForeignKey(_FK_PKG, ondelete="CASCADE"), nullable=False, index=True
    )
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    price: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False, default=0)
    cost: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False, default=0)
    qty: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    billing_type: Mapped[str] = mapped_column(String(20), nullable=False, default="one_time")
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    package: Mapped["LSPackage"] = relationship("LSPackage", back_populates="items")


class LSProposalItem(LeadSalesBase):
    __tablename__ = "ls_proposal_items"
    __table_args__ = _table_args()

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead_id: Mapped[int] = mapped_column(
        Integer, ForeignKey(_FK_LEADS, ondelete="CASCADE"), nullable=False, index=True
    )
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    price: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False, default=0)
    cost: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False, default=0)
    qty: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    billing_type: Mapped[str] = mapped_column(String(20), nullable=False, default="one_time")
    # What was discussed about THIS specific service line.
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Locked = part of a Won snapshot, read-only.
    locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    lead: Mapped["LSLead"] = relationship("LSLead", back_populates="items")


class LSEvent(LeadSalesBase):
    """In-app calendar event — fallback scheduling when Google isn't connected."""
    __tablename__ = "ls_events"
    __table_args__ = _table_args()

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    start_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    lead_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class LSGoogleAccount(LeadSalesBase):
    """Encrypted Google Calendar (read-only) connection for the CRM only."""
    __tablename__ = "ls_google_account"
    __table_args__ = _table_args()

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    google_user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    user_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    user_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    encrypted_access_token: Mapped[str] = mapped_column(Text, nullable=False, default="")
    encrypted_refresh_token: Mapped[str] = mapped_column(Text, nullable=False, default="")
    token_expiry: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


# ---------------------------------------------------------------------------
# DB init — additive only
# ---------------------------------------------------------------------------
# Columns that were added after the first cut shipped. On an existing database
# create_all() will NOT add columns to a table that already exists, so we run
# explicit, idempotent ADD COLUMN IF NOT EXISTS statements (Postgres only).
_ADDITIVE_COLUMNS: list[tuple[str, str, str]] = [
    ("ls_leads", "meeting_at", "TIMESTAMPTZ"),
    ("ls_leads", "calendar_event_id", "VARCHAR(255)"),
    ("ls_leads", "won_at", "TIMESTAMPTZ"),
    ("ls_leads", "won_package_name", "VARCHAR(255)"),
    ("ls_proposal_items", "note", "TEXT"),
    ("ls_proposal_items", "sort_order", "INTEGER NOT NULL DEFAULT 0"),
    ("ls_proposal_items", "locked", "BOOLEAN NOT NULL DEFAULT FALSE"),
]

# Legacy stage values from the first cut → brief's stage enum. Idempotent.
_STAGE_REMAP = [
    ("prospect", "new"),
    ("follow_up", "active"),
]


async def _run_isolated(engine, sql: str, params: dict | None = None) -> None:
    """Run one DDL/DML statement in its own transaction so a failure here can't
    abort sibling migration statements (Postgres aborts the whole tx on error)."""
    try:
        async with engine.begin() as conn:
            await conn.execute(_text(sql), params or {})
    except Exception as exc:
        logger.warning("Migration step skipped (%s): %s", sql.split(" IF ")[0][:60], exc)


async def init_leadsales_db(engine=None) -> None:
    """Create schema + tables and run additive migrations. Never drops anything."""
    if engine is None:
        engine = crm_engine

    if _is_pg:
        await _run_isolated(engine, "CREATE SCHEMA IF NOT EXISTS leadsales")

    # Create any missing tables (additive — never alters/drops existing ones).
    async with engine.begin() as conn:
        await conn.run_sync(LeadSalesBase.metadata.create_all)

    if _is_pg:
        # Additive column backfill for tables that predate these fields. Each in
        # its own transaction for isolation.
        for table, col, coltype in _ADDITIVE_COLUMNS:
            await _run_isolated(
                engine, f"ALTER TABLE {_q(table)} ADD COLUMN IF NOT EXISTS {col} {coltype}"
            )
        # Remap legacy stage values from the first cut.
        for old, new in _STAGE_REMAP:
            await _run_isolated(
                engine, f"UPDATE {_q('ls_leads')} SET status=:new WHERE status=:old",
                {"new": new, "old": old},
            )

    logger.info("Leads & Sales tables ready (schema=%s).", _SCHEMA or "public")


async def get_crm_db():
    """FastAPI dependency — CRM async DB session."""
    async with CRMSession() as session:
        yield session
