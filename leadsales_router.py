"""
leadsales_router.py — FastAPI router for the Leads & Sales CRM module.

Route namespace:
  /crm          — standalone CRM HTML page
  /api/crm/*    — JSON API

Auth: handled automatically by main.py session_middleware (not in PUBLIC_PATHS).
DB:   uses its own CRM engine/session from leadsales_models.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from leadsales_models import LSLead, LSProposalItem, LSService, get_crm_db, init_leadsales_db, crm_engine

logger = logging.getLogger("uplinx.leadsales")
router = APIRouter(tags=["leadsales"])

_CRM_HTML = Path("frontend/crm.html")

VALID_STATUSES = {"prospect", "follow_up", "won", "lost"}
VALID_BILLING  = {"one_time", "monthly"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _lead_dict(lead: LSLead, items: list[LSProposalItem] | None = None) -> dict:
    if items is None:
        items = lead.items
    proposal_value = sum(float(i.price) * i.qty for i in items)
    monthly_value  = sum(float(i.price) * i.qty for i in items if i.billing_type == "monthly")
    return {
        "id": lead.id,
        "name": lead.name,
        "company": lead.company,
        "website": lead.website,
        "social_links": lead.social_links,
        "fiverr_link": lead.fiverr_link,
        "source": lead.source,
        "status": lead.status,
        "follow_up_at": lead.follow_up_at.isoformat() if lead.follow_up_at else None,
        "is_customer": lead.is_customer,
        "assigned_to": lead.assigned_to,
        "notes": lead.notes,
        "created_at": lead.created_at.isoformat(),
        "updated_at": lead.updated_at.isoformat(),
        "proposal_value": proposal_value,
        "monthly_value": monthly_value,
        "items": [_item_dict(i) for i in items],
    }


def _item_dict(item: LSProposalItem) -> dict:
    return {
        "id": item.id,
        "lead_id": item.lead_id,
        "service_name": item.service_name,
        "price": float(item.price),
        "cost": float(item.cost),
        "qty": item.qty,
        "billing_type": item.billing_type,
        "created_at": item.created_at.isoformat(),
    }


def _service_dict(svc: LSService) -> dict:
    return {
        "id": svc.id,
        "name": svc.name,
        "default_price": float(svc.default_price),
        "default_cost": float(svc.default_cost),
        "billing_type": svc.billing_type,
        "active": svc.active,
        "created_at": svc.created_at.isoformat(),
    }


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
    status: str = "prospect"
    follow_up_at: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class LeadUpdate(BaseModel):
    name: Optional[str] = None
    company: Optional[str] = None
    website: Optional[str] = None
    social_links: Optional[str] = None
    fiverr_link: Optional[str] = None
    source: Optional[str] = None
    status: Optional[str] = None
    follow_up_at: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


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


class ItemUpdate(BaseModel):
    service_name: Optional[str] = None
    price: Optional[float] = None
    cost: Optional[float] = None
    qty: Optional[int] = None
    billing_type: Optional[str] = None


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
    # Count by status
    rows = (await db.execute(
        select(LSLead.status, func.count(LSLead.id)).group_by(LSLead.status)
    )).all()
    counts = {r[0]: r[1] for r in rows}
    active = counts.get("prospect", 0) + counts.get("follow_up", 0)
    won    = counts.get("won", 0)
    lost   = counts.get("lost", 0)
    win_rate = round(won / (won + lost) * 100, 1) if (won + lost) > 0 else 0.0

    # Pipeline value + MRR from won leads
    won_items = (await db.execute(
        select(LSProposalItem)
        .join(LSLead, LSProposalItem.lead_id == LSLead.id)
        .where(LSLead.status == "won")
    )).scalars().all()

    pipeline_value = sum(float(i.price) * i.qty for i in won_items)
    mrr = sum(float(i.price) * i.qty for i in won_items if i.billing_type == "monthly")

    return {
        "active_leads": active,
        "pipeline_value": pipeline_value,
        "mrr": mrr,
        "win_rate": win_rate,
    }


# ---------------------------------------------------------------------------
# Leads
# ---------------------------------------------------------------------------
@router.get("/api/crm/leads")
async def list_leads(status: Optional[str] = None, db: AsyncSession = Depends(get_crm_db)):
    q = select(LSLead).options(selectinload(LSLead.items))
    if status == "customers":
        q = q.where(LSLead.is_customer == True)
    elif status and status in VALID_STATUSES:
        q = q.where(LSLead.status == status)
    # Follow-up cards sort by soonest first, then by created_at
    q = q.order_by(
        # follow_up_at ASC (NULLs last), then created_at DESC
        LSLead.follow_up_at.asc().nulls_last(),
        LSLead.created_at.desc(),
    )
    leads = (await db.execute(q)).scalars().all()
    return [_lead_dict(lead) for lead in leads]


@router.post("/api/crm/leads", status_code=201)
async def create_lead(body: LeadCreate, db: AsyncSession = Depends(get_crm_db)):
    if not body.name.strip():
        raise HTTPException(400, "name is required")
    status = body.status if body.status in VALID_STATUSES else "prospect"
    follow_up_at = None
    if body.follow_up_at:
        try:
            follow_up_at = datetime.fromisoformat(body.follow_up_at.replace("Z", "+00:00"))
        except Exception:
            pass
    lead = LSLead(
        name=body.name.strip(),
        company=body.company,
        website=body.website,
        social_links=body.social_links,
        fiverr_link=body.fiverr_link,
        source=body.source or "Fiverr",
        status=status,
        follow_up_at=follow_up_at,
        is_customer=(status == "won"),
        assigned_to=body.assigned_to,
        notes=body.notes,
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
    data = body.model_dump(exclude_none=True)
    if "status" in data:
        s = data["status"]
        if s not in VALID_STATUSES:
            raise HTTPException(400, f"Invalid status: {s}")
        lead.status = s
        if s == "won":
            lead.is_customer = True
    if "follow_up_at" in data:
        raw = data.pop("follow_up_at")
        if raw:
            try:
                lead.follow_up_at = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except Exception:
                pass
        else:
            lead.follow_up_at = None
    for field in ("name", "company", "website", "social_links", "fiverr_link",
                  "source", "assigned_to", "notes"):
        if field in data:
            setattr(lead, field, data[field])
    from datetime import timezone
    lead.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(lead)
    # reload items
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
        select(LSService).where(LSService.active == True).order_by(LSService.name)
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
        name=body.name.strip(),
        default_price=body.default_price,
        default_cost=body.default_cost,
        billing_type=body.billing_type,
        active=body.active,
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
    data = body.model_dump(exclude_none=True)
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
# Proposal items
# ---------------------------------------------------------------------------
@router.post("/api/crm/leads/{lead_id}/items", status_code=201)
async def add_item(lead_id: int, body: ItemCreate, db: AsyncSession = Depends(get_crm_db)):
    lead = await db.get(LSLead, lead_id)
    if not lead:
        raise HTTPException(404, "Lead not found")
    if not body.service_name.strip():
        raise HTTPException(400, "service_name is required")
    if body.billing_type not in VALID_BILLING:
        raise HTTPException(400, "billing_type must be one_time or monthly")
    item = LSProposalItem(
        lead_id=lead_id,
        service_name=body.service_name.strip(),
        price=body.price,
        cost=body.cost,
        qty=max(1, body.qty),
        billing_type=body.billing_type,
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
    data = body.model_dump(exclude_none=True)
    if "billing_type" in data and data["billing_type"] not in VALID_BILLING:
        raise HTTPException(400, "billing_type must be one_time or monthly")
    if "qty" in data:
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
    await db.delete(item)
    await db.commit()


# ---------------------------------------------------------------------------
# Calendly URL (from env var CALENDLY_URL)
# ---------------------------------------------------------------------------
@router.get("/api/crm/calendly-url")
async def get_calendly_url():
    return {"url": os.environ.get("CALENDLY_URL", "")}
