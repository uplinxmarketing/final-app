"""
leadsales_models.py — Leads & Sales CRM data models.

Lives in the 'leadsales' PostgreSQL schema so it never collides with:
  - posting-app tables (public schema, no prefix)
  - admin CRM tables  (public schema, crm_ prefix, admin_models.py)

Uses its own LeadSalesBase — create_all only ever touches these 3 tables.
Uses its own async engine reading CRM_DATABASE_URL (separate Postgres) or
falling back to DATABASE_URL + leadsales schema.
"""
from __future__ import annotations

import logging
import os as _os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Numeric, String, Text, text as _text
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
_FK_LEADS = f"{_SCHEMA}.ls_leads.id" if _SCHEMA else "ls_leads.id"


# ---------------------------------------------------------------------------
# Declarative base — completely separate from Base and AdminBase
# ---------------------------------------------------------------------------
class LeadSalesBase(DeclarativeBase):
    """Isolated base — create_all only touches ls_* tables in leadsales schema."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
def _table_args(extra: dict | None = None) -> dict:
    d: dict = {}
    if _SCHEMA:
        d["schema"] = _SCHEMA
    if extra:
        d.update(extra)
    return d


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
    # prospect | follow_up | won | lost
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="prospect")
    follow_up_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_customer: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    items: Mapped[list[LSProposalItem]] = relationship(
        "LSProposalItem", back_populates="lead", cascade="all, delete-orphan"
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
    # one_time | monthly
    billing_type: Mapped[str] = mapped_column(String(20), nullable=False, default="one_time")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    lead: Mapped[LSLead] = relationship("LSLead", back_populates="items")


# ---------------------------------------------------------------------------
# DB init
# ---------------------------------------------------------------------------
async def init_leadsales_db(engine=None) -> None:
    """Create leadsales schema + tables. Additive only — never drops anything."""
    if engine is None:
        engine = crm_engine
    async with engine.begin() as conn:
        if _is_pg:
            try:
                await conn.execute(_text("CREATE SCHEMA IF NOT EXISTS leadsales"))
            except Exception as exc:
                logger.warning("Could not create leadsales schema: %s", exc)
        await conn.run_sync(LeadSalesBase.metadata.create_all)
    logger.info("Leads & Sales tables ready (schema=%s).", _SCHEMA or "public")


async def get_crm_db():
    """FastAPI dependency — CRM async DB session."""
    async with CRMSession() as session:
        yield session
