"""
leadsales_router.py — FastAPI router for the Leads & Sales CRM module.

Route namespace (all isolated from the posting app):
  /crm                       — standalone CRM SPA
  /api/crm/*                 — JSON API
  /api/crm/google/*          — dedicated Google Calendar (read-only) OAuth
  /api/crm/calendar/events   — merged Google + in-app events
  /api/crm/events/*          — in-app calendar CRUD (fallback scheduler)

Auth: piggybacks on main.py's login_guard, which already authorises /crm and
/api/crm for the posting-app session OR the admin_session cookie.
DB:   its own CRM engine/session from leadsales_models (leadsales schema).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

import leadsales_gcal as gcal
from leadsales_models import (
    LSEvent, LSGoogleAccount, LSLead, LSPackage, LSPackageItem,
    LSProposalItem, LSService, get_crm_db,
)
from security import fernet_encryption, generate_oauth_state, verify_oauth_state

logger = logging.getLogger("uplinx.leadsales")
router = APIRouter(tags=["leadsales"])

_CRM_HTML = Path("frontend/crm.html")

VALID_STAGES = {"new", "active", "won", "lost"}
VALID_BILLING = {"one_time", "monthly"}


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------
def _compute_color(stage: str, follow_up_at: Optional[datetime]) -> str:
    """Automatic card colour (brief's rules)."""
    if stage == "won":
        return "green"
    if stage == "lost":
        return "red"
    if stage == "active" and follow_up_at and follow_up_at > datetime.now(timezone.utc):
        return "blue"
    return "yellow"


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _item_dict(item: LSProposalItem) -> dict:
    return {
        "id": item.id,
        "lead_id": item.lead_id,
        "service_name": item.service_name,
        "price": float(item.price),
        "cost": float(item.cost),
        "qty": item.qty,
        "billing_type": item.billing_type,
        "note": item.note,
        "sort_order": item.sort_order,
        "locked": item.locked,
        "created_at": _iso(item.created_at),
    }


def _lead_dict(lead: LSLead, items: list[LSProposalItem] | None = None) -> dict:
    if items is None:
        items = lead.items
    proposal_value = sum(float(i.price) * i.qty for i in items)
    monthly_value = sum(float(i.price) * i.qty for i in items if i.billing_type == "monthly")
    return {
        "id": lead.id,
        "name": lead.name,
        "company": lead.company,
        "website": lead.website,
        "social_links": lead.social_links,
        "fiverr_link": lead.fiverr_link,
        "source": lead.source,
        "stage": lead.stage,
        "color": _compute_color(lead.stage, lead.follow_up_at),
        "follow_up_at": _iso(lead.follow_up_at),
        "meeting_at": _iso(lead.meeting_at),
        "calendar_event_id": lead.calendar_event_id,
        "is_customer": lead.is_customer,
        "assigned_to": lead.assigned_to,
        "general_notes": lead.general_notes,
        "won_at": _iso(lead.won_at),
        "won_package_name": lead.won_package_name,
        "created_at": _iso(lead.created_at),
        "updated_at": _iso(lead.updated_at),
        "proposal_value": proposal_value,
        "monthly_value": monthly_value,
        "items": [_item_dict(i) for i in items],
    }


def _service_dict(svc: LSService) -> dict:
    return {
        "id": svc.id,
        "name": svc.name,
        "default_price": float(svc.default_price),
        "default_cost": float(svc.default_cost),
        "billing_type": svc.billing_type,
        "active": svc.active,
        "created_at": _iso(svc.created_at),
    }


def _pkg_item_dict(it: LSPackageItem) -> dict:
    return {
        "id": it.id,
        "package_id": it.package_id,
        "service_name": it.service_name,
        "price": float(it.price),
        "cost": float(it.cost),
        "qty": it.qty,
        "billing_type": it.billing_type,
        "sort_order": it.sort_order,
    }


def _pkg_dict(pkg: LSPackage, items: list[LSPackageItem] | None = None) -> dict:
    if items is None:
        items = pkg.items
    return {
        "id": pkg.id,
        "name": pkg.name,
        "created_at": _iso(pkg.created_at),
        "items": [_pkg_item_dict(i) for i in items],
        "total_one_time": sum(float(i.price) * i.qty for i in items if i.billing_type == "one_time"),
        "total_monthly": sum(float(i.price) * i.qty for i in items if i.billing_type == "monthly"),
    }


def _event_dict(ev: LSEvent) -> dict:
    return {
        "source": "local",
        "id": ev.id,
        "title": ev.title,
        "start_at": _iso(ev.start_at),
        "end_at": _iso(ev.end_at),
        "location": ev.location,
        "description": ev.notes,
        "html_link": None,
        "all_day": False,
        "lead_id": ev.lead_id,
    }


def _parse_dt(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class LeadCreate(BaseModel):
    name: str
    company: Optional[str] = None
    website: Optional[str] = None
    social_links: Optional[str] = None
    fiverr_link: Optional[str] = None
    source: str = "Fiverr"
    stage: str = "new"
    follow_up_at: Optional[str] = None
    meeting_at: Optional[str] = None
    calendar_event_id: Optional[str] = None
    assigned_to: Optional[str] = None
    general_notes: Optional[str] = None


class LeadFromEvent(BaseModel):
    name: str
    meeting_at: Optional[str] = None
    calendar_event_id: Optional[str] = None
    source: str = "Calendar"


class LeadUpdate(BaseModel):
    name: Optional[str] = None
    company: Optional[str] = None
    website: Optional[str] = None
    social_links: Optional[str] = None
    fiverr_link: Optional[str] = None
    source: Optional[str] = None
    stage: Optional[str] = None
    follow_up_at: Optional[str] = None
    meeting_at: Optional[str] = None
    assigned_to: Optional[str] = None
    general_notes: Optional[str] = None


class WinBody(BaseModel):
    package_name: Optional[str] = "Custom package"
    package_id: Optional[int] = None


class ServiceCreate(BaseModel):
    name: str
    default_price: float = 0
    default_cost: float = 0
    billing_type: str = "one_time"
    active: bool = True


class ServiceUpdate(BaseModel):
    name: Optional[str] = None
    default_price: Optional[float] = None
    default_cost: Optional[float] = None
    billing_type: Optional[str] = None
    active: Optional[bool] = None


class ItemCreate(BaseModel):
    service_name: str
    price: float = 0
    cost: float = 0
    qty: int = 1
    billing_type: str = "one_time"
    note: Optional[str] = None


class ItemUpdate(BaseModel):
    service_name: Optional[str] = None
    price: Optional[float] = None
    cost: Optional[float] = None
    qty: Optional[int] = None
    billing_type: Optional[str] = None
    note: Optional[str] = None


class PackageCreate(BaseModel):
    name: str


class PackageUpdate(BaseModel):
    name: str


class PackageItemCreate(BaseModel):
    service_name: str
    price: float = 0
    cost: float = 0
    qty: int = 1
    billing_type: str = "one_time"


class PackageItemUpdate(BaseModel):
    service_name: Optional[str] = None
    price: Optional[float] = None
    cost: Optional[float] = None
    qty: Optional[int] = None
    billing_type: Optional[str] = None


class EventCreate(BaseModel):
    title: str
    start_at: str
    end_at: Optional[str] = None
    location: Optional[str] = None
    notes: Optional[str] = None
    lead_id: Optional[int] = None


class EventUpdate(BaseModel):
    title: Optional[str] = None
    start_at: Optional[str] = None
    end_at: Optional[str] = None
    location: Optional[str] = None
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
@router.get("/crm", response_class=HTMLResponse)
async def crm_ui():
    try:
        html = _CRM_HTML.read_text(encoding="utf-8")
    except FileNotFoundError:
        html = "<h1>CRM not found</h1>"
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
@router.get("/api/crm/stats")
async def crm_stats(db: AsyncSession = Depends(get_crm_db)):
    rows = (await db.execute(
        select(LSLead.stage, func.count(LSLead.id)).group_by(LSLead.stage)
    )).all()
    counts = {r[0]: r[1] for r in rows}
    active = counts.get("new", 0) + counts.get("active", 0)
    won = counts.get("won", 0)
    lost = counts.get("lost", 0)
    win_rate = round(won / (won + lost) * 100, 1) if (won + lost) > 0 else 0.0

    # Open pipeline value + projected MRR (new + active leads' proposals).
    open_items = (await db.execute(
        select(LSProposalItem)
        .join(LSLead, LSProposalItem.lead_id == LSLead.id)
        .where(LSLead.stage.in_(["new", "active"]))
    )).scalars().all()
    pipeline_value = sum(float(i.price) * i.qty for i in open_items)
    projected_mrr = sum(float(i.price) * i.qty for i in open_items if i.billing_type == "monthly")

    # Realised MRR from won customers.
    won_items = (await db.execute(
        select(LSProposalItem)
        .join(LSLead, LSProposalItem.lead_id == LSLead.id)
        .where(LSLead.stage == "won")
    )).scalars().all()
    won_mrr = sum(float(i.price) * i.qty for i in won_items if i.billing_type == "monthly")
    won_value = sum(float(i.price) * i.qty for i in won_items)

    return {
        "active_leads": active,
        "pipeline_value": pipeline_value,
        "projected_mrr": projected_mrr,
        "won_value": won_value,
        "won_mrr": won_mrr,
        "win_rate": win_rate,
    }


# ---------------------------------------------------------------------------
# Leads
# ---------------------------------------------------------------------------
@router.get("/api/crm/leads")
async def list_leads(
    stage: Optional[str] = None,
    assigned: Optional[str] = None,
    q: Optional[str] = None,
    meeting_date: Optional[str] = None,
    db: AsyncSession = Depends(get_crm_db),
):
    query = select(LSLead).options(selectinload(LSLead.items))
    if stage == "customers":
        query = query.where(LSLead.is_customer == True)  # noqa: E712
    elif stage and stage in VALID_STAGES:
        query = query.where(LSLead.stage == stage)
    if assigned:
        query = query.where(LSLead.assigned_to == assigned)
    if q:
        like = f"%{q.strip()}%"
        query = query.where(or_(LSLead.name.ilike(like), LSLead.company.ilike(like)))
    if meeting_date:
        d = _parse_dt(meeting_date + "T00:00:00")
        if d:
            query = query.where(
                LSLead.meeting_at >= d, LSLead.meeting_at < d + timedelta(days=1)
            )
    # Blue (follow-up) cards float to the top by soonest follow-up, then by
    # soonest meeting, then newest.
    query = query.order_by(
        LSLead.follow_up_at.asc().nulls_last(),
        LSLead.meeting_at.asc().nulls_last(),
        LSLead.created_at.desc(),
    )
    leads = (await db.execute(query)).scalars().all()
    return [_lead_dict(lead) for lead in leads]


@router.get("/api/crm/assignees")
async def list_assignees(db: AsyncSession = Depends(get_crm_db)):
    rows = (await db.execute(
        select(LSLead.assigned_to).where(LSLead.assigned_to.isnot(None)).distinct()
    )).all()
    return sorted({r[0] for r in rows if r[0]})


@router.post("/api/crm/leads", status_code=201)
async def create_lead(body: LeadCreate, db: AsyncSession = Depends(get_crm_db)):
    if not body.name.strip():
        raise HTTPException(400, "name is required")
    stage = body.stage if body.stage in VALID_STAGES else "new"
    lead = LSLead(
        name=body.name.strip(),
        company=body.company,
        website=body.website,
        social_links=body.social_links,
        fiverr_link=body.fiverr_link,
        source=body.source or "Fiverr",
        stage=stage,
        follow_up_at=_parse_dt(body.follow_up_at),
        meeting_at=_parse_dt(body.meeting_at),
        calendar_event_id=body.calendar_event_id,
        is_customer=(stage == "won"),
        assigned_to=body.assigned_to,
        general_notes=body.general_notes,
    )
    db.add(lead)
    await db.commit()
    await db.refresh(lead)
    return _lead_dict(lead, [])


@router.post("/api/crm/leads/from-event", status_code=201)
async def create_lead_from_event(body: LeadFromEvent, db: AsyncSession = Depends(get_crm_db)):
    if not body.name.strip():
        raise HTTPException(400, "name is required")
    # If a lead already exists for this calendar event, return it (idempotent).
    if body.calendar_event_id:
        existing = (await db.execute(
            select(LSLead).options(selectinload(LSLead.items))
            .where(LSLead.calendar_event_id == body.calendar_event_id)
        )).scalar_one_or_none()
        if existing:
            return _lead_dict(existing)
    lead = LSLead(
        name=body.name.strip(),
        source=body.source or "Calendar",
        stage="new",
        meeting_at=_parse_dt(body.meeting_at),
        calendar_event_id=body.calendar_event_id,
    )
    db.add(lead)
    await db.commit()
    await db.refresh(lead)
    return _lead_dict(lead, [])


@router.get("/api/crm/leads/{lead_id}")
async def get_lead(lead_id: int, db: AsyncSession = Depends(get_crm_db)):
    lead = (await db.execute(
        select(LSLead).options(selectinload(LSLead.items)).where(LSLead.id == lead_id)
    )).scalar_one_or_none()
    if not lead:
        raise HTTPException(404, "Lead not found")
    return _lead_dict(lead)


@router.patch("/api/crm/leads/{lead_id}")
async def update_lead(lead_id: int, body: LeadUpdate, db: AsyncSession = Depends(get_crm_db)):
    lead = await db.get(LSLead, lead_id)
    if not lead:
        raise HTTPException(404, "Lead not found")
    data = body.model_dump(exclude_unset=True)
    if "stage" in data and data["stage"] is not None:
        s = data["stage"]
        if s not in VALID_STAGES:
            raise HTTPException(400, f"Invalid stage: {s}")
        was_won = lead.stage == "won"
        lead.stage = s
        if s == "won":
            lead.is_customer = True
        elif was_won:
            # Re-opening a won deal: unlock its line items so they're editable
            # again and clear the won timestamp (keep the package name as history).
            lead.won_at = None
            unlock_items = (await db.execute(
                select(LSProposalItem).where(LSProposalItem.lead_id == lead.id)
            )).scalars().all()
            for it in unlock_items:
                it.locked = False
    for key in ("follow_up_at", "meeting_at"):
        if key in data:
            setattr(lead, key, _parse_dt(data[key]))
    for field in ("name", "company", "website", "social_links", "fiverr_link",
                  "source", "assigned_to", "general_notes"):
        if field in data:
            setattr(lead, field, data[field])
    lead.updated_at = datetime.now(timezone.utc)
    await db.commit()
    lead2 = (await db.execute(
        select(LSLead).options(selectinload(LSLead.items)).where(LSLead.id == lead_id)
    )).scalar_one()
    return _lead_dict(lead2)


@router.post("/api/crm/leads/{lead_id}/win")
async def win_lead(lead_id: int, body: WinBody, db: AsyncSession = Depends(get_crm_db)):
    lead = (await db.execute(
        select(LSLead).options(selectinload(LSLead.items)).where(LSLead.id == lead_id)
    )).scalar_one_or_none()
    if not lead:
        raise HTTPException(404, "Lead not found")

    pkg_name = (body.package_name or "Custom package").strip() or "Custom package"

    # Optionally seed the proposal from a saved package if it's currently empty.
    if body.package_id and not lead.items:
        pkg = (await db.execute(
            select(LSPackage).options(selectinload(LSPackage.items))
            .where(LSPackage.id == body.package_id)
        )).scalar_one_or_none()
        if pkg:
            pkg_name = pkg.name
            for pi in pkg.items:
                db.add(LSProposalItem(
                    lead_id=lead.id, service_name=pi.service_name, price=pi.price,
                    cost=pi.cost, qty=pi.qty, billing_type=pi.billing_type,
                    sort_order=pi.sort_order,
                ))
            await db.flush()

    # Lock the proposal as the sold record.
    items = (await db.execute(
        select(LSProposalItem).where(LSProposalItem.lead_id == lead.id)
    )).scalars().all()
    for it in items:
        it.locked = True

    lead.stage = "won"
    lead.is_customer = True
    lead.won_at = datetime.now(timezone.utc)
    lead.won_package_name = pkg_name
    lead.updated_at = datetime.now(timezone.utc)
    await db.commit()

    lead2 = (await db.execute(
        select(LSLead).options(selectinload(LSLead.items)).where(LSLead.id == lead_id)
    )).scalar_one()
    return _lead_dict(lead2)


@router.delete("/api/crm/leads/{lead_id}", status_code=204)
async def delete_lead(lead_id: int, db: AsyncSession = Depends(get_crm_db)):
    lead = await db.get(LSLead, lead_id)
    if not lead:
        raise HTTPException(404, "Lead not found")
    await db.delete(lead)
    await db.commit()


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------
@router.get("/api/crm/services")
async def list_services(db: AsyncSession = Depends(get_crm_db)):
    svcs = (await db.execute(
        select(LSService).where(LSService.active == True).order_by(LSService.name)  # noqa: E712
    )).scalars().all()
    return [_service_dict(s) for s in svcs]


@router.get("/api/crm/services/all")
async def list_all_services(db: AsyncSession = Depends(get_crm_db)):
    svcs = (await db.execute(select(LSService).order_by(LSService.name))).scalars().all()
    return [_service_dict(s) for s in svcs]


@router.post("/api/crm/services", status_code=201)
async def create_service(body: ServiceCreate, db: AsyncSession = Depends(get_crm_db)):
    if not body.name.strip():
        raise HTTPException(400, "name is required")
    if body.billing_type not in VALID_BILLING:
        raise HTTPException(400, "billing_type must be one_time or monthly")
    svc = LSService(
        name=body.name.strip(), default_price=body.default_price,
        default_cost=body.default_cost, billing_type=body.billing_type, active=body.active,
    )
    db.add(svc)
    await db.commit()
    await db.refresh(svc)
    return _service_dict(svc)


@router.patch("/api/crm/services/{svc_id}")
async def update_service(svc_id: int, body: ServiceUpdate, db: AsyncSession = Depends(get_crm_db)):
    svc = await db.get(LSService, svc_id)
    if not svc:
        raise HTTPException(404, "Service not found")
    data = body.model_dump(exclude_unset=True)
    if "billing_type" in data and data["billing_type"] not in VALID_BILLING:
        raise HTTPException(400, "billing_type must be one_time or monthly")
    for field, val in data.items():
        setattr(svc, field, val)
    await db.commit()
    await db.refresh(svc)
    return _service_dict(svc)


@router.delete("/api/crm/services/{svc_id}", status_code=204)
async def delete_service(svc_id: int, db: AsyncSession = Depends(get_crm_db)):
    svc = await db.get(LSService, svc_id)
    if not svc:
        raise HTTPException(404, "Service not found")
    await db.delete(svc)
    await db.commit()


# ---------------------------------------------------------------------------
# Packages (reusable templates)
# ---------------------------------------------------------------------------
@router.get("/api/crm/packages")
async def list_packages(db: AsyncSession = Depends(get_crm_db)):
    pkgs = (await db.execute(
        select(LSPackage).options(selectinload(LSPackage.items)).order_by(LSPackage.name)
    )).scalars().all()
    return [_pkg_dict(p) for p in pkgs]


@router.post("/api/crm/packages", status_code=201)
async def create_package(body: PackageCreate, db: AsyncSession = Depends(get_crm_db)):
    if not body.name.strip():
        raise HTTPException(400, "name is required")
    pkg = LSPackage(name=body.name.strip())
    db.add(pkg)
    await db.commit()
    await db.refresh(pkg)
    return _pkg_dict(pkg, [])


@router.get("/api/crm/packages/{pkg_id}")
async def get_package(pkg_id: int, db: AsyncSession = Depends(get_crm_db)):
    pkg = (await db.execute(
        select(LSPackage).options(selectinload(LSPackage.items)).where(LSPackage.id == pkg_id)
    )).scalar_one_or_none()
    if not pkg:
        raise HTTPException(404, "Package not found")
    return _pkg_dict(pkg)


@router.patch("/api/crm/packages/{pkg_id}")
async def update_package(pkg_id: int, body: PackageUpdate, db: AsyncSession = Depends(get_crm_db)):
    pkg = await db.get(LSPackage, pkg_id)
    if not pkg:
        raise HTTPException(404, "Package not found")
    if body.name.strip():
        pkg.name = body.name.strip()
    await db.commit()
    pkg2 = (await db.execute(
        select(LSPackage).options(selectinload(LSPackage.items)).where(LSPackage.id == pkg_id)
    )).scalar_one()
    return _pkg_dict(pkg2)


@router.delete("/api/crm/packages/{pkg_id}", status_code=204)
async def delete_package(pkg_id: int, db: AsyncSession = Depends(get_crm_db)):
    pkg = await db.get(LSPackage, pkg_id)
    if not pkg:
        raise HTTPException(404, "Package not found")
    await db.delete(pkg)
    await db.commit()


@router.post("/api/crm/packages/{pkg_id}/items", status_code=201)
async def add_package_item(pkg_id: int, body: PackageItemCreate, db: AsyncSession = Depends(get_crm_db)):
    pkg = await db.get(LSPackage, pkg_id)
    if not pkg:
        raise HTTPException(404, "Package not found")
    if not body.service_name.strip():
        raise HTTPException(400, "service_name is required")
    if body.billing_type not in VALID_BILLING:
        raise HTTPException(400, "billing_type must be one_time or monthly")
    n = (await db.execute(
        select(func.count(LSPackageItem.id)).where(LSPackageItem.package_id == pkg_id)
    )).scalar() or 0
    item = LSPackageItem(
        package_id=pkg_id, service_name=body.service_name.strip(), price=body.price,
        cost=body.cost, qty=max(1, body.qty), billing_type=body.billing_type, sort_order=n,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return _pkg_item_dict(item)


@router.patch("/api/crm/packages/{pkg_id}/items/{item_id}")
async def update_package_item(pkg_id: int, item_id: int, body: PackageItemUpdate,
                              db: AsyncSession = Depends(get_crm_db)):
    item = await db.get(LSPackageItem, item_id)
    if not item or item.package_id != pkg_id:
        raise HTTPException(404, "Item not found")
    data = body.model_dump(exclude_unset=True)
    if "billing_type" in data and data["billing_type"] not in VALID_BILLING:
        raise HTTPException(400, "billing_type must be one_time or monthly")
    if "qty" in data and data["qty"] is not None:
        data["qty"] = max(1, int(data["qty"]))
    for field, val in data.items():
        setattr(item, field, val)
    await db.commit()
    await db.refresh(item)
    return _pkg_item_dict(item)


@router.delete("/api/crm/packages/{pkg_id}/items/{item_id}", status_code=204)
async def delete_package_item(pkg_id: int, item_id: int, db: AsyncSession = Depends(get_crm_db)):
    item = await db.get(LSPackageItem, item_id)
    if not item or item.package_id != pkg_id:
        raise HTTPException(404, "Item not found")
    await db.delete(item)
    await db.commit()


# ---------------------------------------------------------------------------
# Proposal items (per-lead package being built)
# ---------------------------------------------------------------------------
async def _guard_unlocked(lead_id: int, db: AsyncSession) -> LSLead:
    lead = await db.get(LSLead, lead_id)
    if not lead:
        raise HTTPException(404, "Lead not found")
    if lead.stage == "won":
        raise HTTPException(409, "This deal is won — its package is locked.")
    return lead


@router.post("/api/crm/leads/{lead_id}/items", status_code=201)
async def add_item(lead_id: int, body: ItemCreate, db: AsyncSession = Depends(get_crm_db)):
    await _guard_unlocked(lead_id, db)
    if not body.service_name.strip():
        raise HTTPException(400, "service_name is required")
    if body.billing_type not in VALID_BILLING:
        raise HTTPException(400, "billing_type must be one_time or monthly")
    n = (await db.execute(
        select(func.count(LSProposalItem.id)).where(LSProposalItem.lead_id == lead_id)
    )).scalar() or 0
    item = LSProposalItem(
        lead_id=lead_id, service_name=body.service_name.strip(), price=body.price,
        cost=body.cost, qty=max(1, body.qty), billing_type=body.billing_type,
        note=body.note, sort_order=n,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return _item_dict(item)


@router.patch("/api/crm/leads/{lead_id}/items/{item_id}")
async def update_item(lead_id: int, item_id: int, body: ItemUpdate,
                      db: AsyncSession = Depends(get_crm_db)):
    item = await db.get(LSProposalItem, item_id)
    if not item or item.lead_id != lead_id:
        raise HTTPException(404, "Item not found")
    if item.locked:
        raise HTTPException(409, "This line is part of a won deal and is locked.")
    data = body.model_dump(exclude_unset=True)
    if "billing_type" in data and data["billing_type"] not in VALID_BILLING:
        raise HTTPException(400, "billing_type must be one_time or monthly")
    if "qty" in data and data["qty"] is not None:
        data["qty"] = max(1, int(data["qty"]))
    for field, val in data.items():
        setattr(item, field, val)
    await db.commit()
    await db.refresh(item)
    return _item_dict(item)


@router.delete("/api/crm/leads/{lead_id}/items/{item_id}", status_code=204)
async def delete_item(lead_id: int, item_id: int, db: AsyncSession = Depends(get_crm_db)):
    item = await db.get(LSProposalItem, item_id)
    if not item or item.lead_id != lead_id:
        raise HTTPException(404, "Item not found")
    if item.locked:
        raise HTTPException(409, "This line is part of a won deal and is locked.")
    await db.delete(item)
    await db.commit()


@router.post("/api/crm/leads/{lead_id}/apply-package/{pkg_id}")
async def apply_package(lead_id: int, pkg_id: int, db: AsyncSession = Depends(get_crm_db)):
    await _guard_unlocked(lead_id, db)
    pkg = (await db.execute(
        select(LSPackage).options(selectinload(LSPackage.items)).where(LSPackage.id == pkg_id)
    )).scalar_one_or_none()
    if not pkg:
        raise HTTPException(404, "Package not found")
    n = (await db.execute(
        select(func.count(LSProposalItem.id)).where(LSProposalItem.lead_id == lead_id)
    )).scalar() or 0
    for offset, pi in enumerate(pkg.items):
        db.add(LSProposalItem(
            lead_id=lead_id, service_name=pi.service_name, price=pi.price, cost=pi.cost,
            qty=pi.qty, billing_type=pi.billing_type, sort_order=n + offset,
        ))
    await db.commit()
    lead2 = (await db.execute(
        select(LSLead).options(selectinload(LSLead.items)).where(LSLead.id == lead_id)
    )).scalar_one()
    return _lead_dict(lead2)


# ---------------------------------------------------------------------------
# In-app calendar events (fallback scheduler)
# ---------------------------------------------------------------------------
@router.post("/api/crm/events", status_code=201)
async def create_event(body: EventCreate, db: AsyncSession = Depends(get_crm_db)):
    if not body.title.strip():
        raise HTTPException(400, "title is required")
    start = _parse_dt(body.start_at)
    if not start:
        raise HTTPException(400, "valid start_at is required")
    ev = LSEvent(
        title=body.title.strip(), start_at=start, end_at=_parse_dt(body.end_at),
        location=body.location, notes=body.notes, lead_id=body.lead_id,
    )
    db.add(ev)
    await db.commit()
    await db.refresh(ev)
    return _event_dict(ev)


@router.patch("/api/crm/events/{event_id}")
async def update_event(event_id: int, body: EventUpdate, db: AsyncSession = Depends(get_crm_db)):
    ev = await db.get(LSEvent, event_id)
    if not ev:
        raise HTTPException(404, "Event not found")
    data = body.model_dump(exclude_unset=True)
    if "title" in data and data["title"] is not None:
        ev.title = data["title"].strip() or ev.title
    if "start_at" in data and data["start_at"]:
        ev.start_at = _parse_dt(data["start_at"]) or ev.start_at
    if "end_at" in data:
        ev.end_at = _parse_dt(data["end_at"])
    for field in ("location", "notes"):
        if field in data:
            setattr(ev, field, data[field])
    ev.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(ev)
    return _event_dict(ev)


@router.delete("/api/crm/events/{event_id}", status_code=204)
async def delete_event(event_id: int, db: AsyncSession = Depends(get_crm_db)):
    ev = await db.get(LSEvent, event_id)
    if not ev:
        raise HTTPException(404, "Event not found")
    await db.delete(ev)
    await db.commit()


# ---------------------------------------------------------------------------
# Google Calendar (read-only) — dedicated OAuth, fully isolated
# ---------------------------------------------------------------------------
def _redirect_uri(request: Request) -> str:
    fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    fwd_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    scheme = fwd_proto or request.url.scheme
    host = fwd_host or request.url.netloc
    return f"{scheme}://{host}/api/crm/google/callback"


async def _active_google_account(db: AsyncSession) -> Optional[LSGoogleAccount]:
    return (await db.execute(
        select(LSGoogleAccount).where(LSGoogleAccount.is_active == True)  # noqa: E712
        .order_by(LSGoogleAccount.id.desc())
    )).scalars().first()


async def _google_access_token(db: AsyncSession) -> Optional[str]:
    """Return a valid access token for the connected calendar, refreshing if needed."""
    acc = await _active_google_account(db)
    if not acc:
        return None
    now = datetime.now(timezone.utc)
    expiry = acc.token_expiry
    if expiry is not None and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    token = fernet_encryption.decrypt(acc.encrypted_access_token or "")
    if token and expiry and expiry > now + timedelta(seconds=60):
        return token
    # Refresh.
    refresh_token = fernet_encryption.decrypt(acc.encrypted_refresh_token or "")
    if not refresh_token:
        return token or None
    res = await gcal.refresh_access_token(refresh_token)
    if not res.get("success"):
        logger.warning("CRM Google token refresh failed: %s", res.get("error"))
        return token or None
    new_token = res.get("access_token", "")
    acc.encrypted_access_token = fernet_encryption.encrypt(new_token)
    acc.token_expiry = now + timedelta(seconds=res.get("expires_in", 3600))
    acc.updated_at = now
    await db.commit()
    return new_token


@router.get("/api/crm/google/connect")
async def google_connect(request: Request):
    cfg = gcal.oauth_config()
    if not cfg["configured"]:
        return RedirectResponse("/crm?gerror=not_configured")
    state = generate_oauth_state()
    redirect_uri = _redirect_uri(request)
    url = gcal.build_auth_url(redirect_uri, state)
    resp = RedirectResponse(url)
    resp.set_cookie("crm_oauth_state", state, max_age=600, httponly=True, samesite="lax")
    resp.set_cookie("crm_google_redirect", redirect_uri, max_age=600, httponly=True, samesite="lax")
    return resp


@router.get("/api/crm/google/callback")
async def google_callback(request: Request, code: str = "", state: str = "",
                          error: str = "", db: AsyncSession = Depends(get_crm_db)):
    if error:
        return RedirectResponse(f"/crm?gerror={error}")
    expected = request.cookies.get("crm_oauth_state", "")
    if not verify_oauth_state(state, expected):
        return RedirectResponse("/crm?gerror=invalid_state")
    redirect_uri = request.cookies.get("crm_google_redirect") or _redirect_uri(request)
    tokens = await gcal.exchange_code(code, redirect_uri)
    if not tokens.get("success"):
        return RedirectResponse("/crm?gerror=token_failed")
    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    expires_in = tokens.get("expires_in", 3600)

    info = await gcal.get_user_info(access_token)
    uid = info.get("id", "") if info.get("success") else ""
    email = info.get("email", "") if info.get("success") else ""
    name = info.get("name", "") if info.get("success") else ""

    now = datetime.now(timezone.utc)
    acc = await _active_google_account(db)
    if acc is None and uid:
        acc = (await db.execute(
            select(LSGoogleAccount).where(LSGoogleAccount.google_user_id == uid)
        )).scalars().first()
    if acc:
        acc.google_user_id = uid or acc.google_user_id
        acc.user_email = email or acc.user_email
        acc.user_name = name or acc.user_name
        acc.encrypted_access_token = fernet_encryption.encrypt(access_token)
        if refresh_token:
            acc.encrypted_refresh_token = fernet_encryption.encrypt(refresh_token)
        acc.token_expiry = now + timedelta(seconds=expires_in)
        acc.is_active = True
        acc.updated_at = now
    else:
        acc = LSGoogleAccount(
            google_user_id=uid or "unknown",
            user_email=email, user_name=name,
            encrypted_access_token=fernet_encryption.encrypt(access_token),
            encrypted_refresh_token=fernet_encryption.encrypt(refresh_token) if refresh_token else "",
            token_expiry=now + timedelta(seconds=expires_in),
            is_active=True,
        )
        db.add(acc)
    await db.commit()
    return RedirectResponse("/crm?gconnected=1")


@router.get("/api/crm/google/status")
async def google_status(db: AsyncSession = Depends(get_crm_db)):
    cfg = gcal.oauth_config()
    acc = await _active_google_account(db)
    return {
        "configured": cfg["configured"],
        "client_source": cfg["source"],
        "connected": bool(acc),
        "email": acc.user_email if acc else None,
    }


@router.post("/api/crm/google/disconnect", status_code=204)
async def google_disconnect(db: AsyncSession = Depends(get_crm_db)):
    acc = await _active_google_account(db)
    if acc:
        acc.is_active = False
        acc.encrypted_access_token = ""
        acc.encrypted_refresh_token = ""
        acc.updated_at = datetime.now(timezone.utc)
        await db.commit()


@router.get("/api/crm/calendar/events")
async def calendar_events(days: int = 30, db: AsyncSession = Depends(get_crm_db)):
    """Merged upcoming events: Google Calendar (read-only) + in-app events."""
    days = max(1, min(days, 120))
    now = datetime.now(timezone.utc)
    window_end = now + timedelta(days=days)

    google_connected = False
    google_events: list[dict] = []
    token = await _google_access_token(db)
    if token:
        google_connected = True
        try:
            google_events = await gcal.list_events(token, now - timedelta(days=1), window_end)
        except Exception as exc:
            logger.warning("CRM calendar fetch failed: %s", exc)
            google_events = []

    # Local in-app events in the same window.
    rows = (await db.execute(
        select(LSEvent).where(LSEvent.start_at >= now - timedelta(days=1),
                              LSEvent.start_at <= window_end)
        .order_by(LSEvent.start_at.asc())
    )).scalars().all()
    local_events = [_event_dict(e) for e in rows]

    # Which Google events already became leads?
    linked = (await db.execute(
        select(LSLead.calendar_event_id, LSLead.id)
        .where(LSLead.calendar_event_id.isnot(None))
    )).all()
    linked_map = {r[0]: r[1] for r in linked}
    for ev in google_events:
        if ev["id"] in linked_map:
            ev["lead_id"] = linked_map[ev["id"]]

    merged = google_events + local_events
    merged.sort(key=lambda e: e.get("start_at") or "")
    return {
        "google_connected": google_connected,
        "google_configured": gcal.oauth_config()["configured"],
        "events": merged,
    }
