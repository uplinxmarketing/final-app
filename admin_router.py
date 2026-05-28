"""
admin_router.py — FastAPI router for the Uplinx Admin / CRM system.
All routes are mounted under /admin. Auth uses a separate 'admin_session' cookie.
"""
from __future__ import annotations

import hashlib
import secrets
import base64 as _b64
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, func, desc, delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database import get_db
from admin_models import (
    AdminBase, CRMRole, StaffMember, CRMCustomer, CRMContact, CRMNote,
    CRMLead, CRMLeadSource, CRMLeadStatus, CRMProject, CRMProjectMember,
    CRMTask, CRMTaskComment, CRMTimesheet, CRMInvoice, CRMProposal,
    CRMLineItem, CRMPayment, CRMPaymentMode, CRMExpense, CRMExpenseCategory,
    CRMContract, CRMContractType, CRMEvent, CRMAnnouncement,
    CRMAnnouncementComment, CRMActivity, CRMSetting, CRMEmailTemplate,
    CRMCatalogItem, CRMTaxRate, CRMCurrency, CRMCustomerGroup, CRMTodo,
    CRMStaffNote,
)

router = APIRouter(prefix="/admin")

# ── Password helpers ──────────────────────────────────────────────────────────

def _hash_pw(pw: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:260000${salt}${_b64.b64encode(dk).decode()}"


def _verify_pw(pw: str, hashed: str) -> bool:
    try:
        _, _, rest = hashed.split(":", 2)
        iters_s, salt, stored = rest.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), int(iters_s))
        return secrets.compare_digest(_b64.b64encode(dk).decode(), stored)
    except Exception:
        return False


# ── Session helpers ───────────────────────────────────────────────────────────

_ADMIN_SESSION_LIFETIME = 86400 * 7  # 7 days

def _make_admin_token(staff_id: int) -> str:
    from security import create_session_token
    return create_session_token({"sub": str(staff_id), "type": "admin"})


def _decode_admin_token(token: str) -> Optional[dict]:
    from security import verify_session_token
    try:
        return verify_session_token(token, max_age=_ADMIN_SESSION_LIFETIME)
    except Exception:
        return None


async def get_current_admin(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> StaffMember:
    token = request.cookies.get("admin_session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = _decode_admin_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Session expired")
    staff_id = int(payload.get("sub", 0))
    result = await db.execute(select(StaffMember).where(StaffMember.id == staff_id, StaffMember.is_active == True))
    staff = result.scalar_one_or_none()
    if not staff:
        raise HTTPException(status_code=401, detail="Staff not found")
    return staff


def _perm(staff: StaffMember, module: str, action: str) -> bool:
    """Check if staff has a given permission, respecting role + overrides."""
    if staff.is_admin:
        return True
    # Check overrides first
    overrides = staff.permission_overrides or {}
    mod_overrides = overrides.get(module, {})
    if action in mod_overrides:
        return bool(mod_overrides[action])
    # Fall back to role
    if staff.role and staff.role.permissions:
        return bool(staff.role.permissions.get(module, {}).get(action, False))
    return False


async def _log(db: AsyncSession, staff: StaffMember, module: str, action: str,
               record_id: Optional[int] = None, record_name: Optional[str] = None,
               description: Optional[str] = None):
    entry = CRMActivity(
        staff_id=staff.id, module=module, action=action,
        record_id=record_id, record_name=record_name, description=description,
    )
    db.add(entry)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _staff_dict(s: StaffMember) -> dict:
    return {
        "id": s.id, "first_name": s.first_name, "last_name": s.last_name,
        "full_name": s.full_name, "email": s.email, "phone": s.phone,
        "role_id": s.role_id, "role_name": s.role.name if s.role else None,
        "is_admin": s.is_admin, "is_active": s.is_active,
        "profile_photo": s.profile_photo,
        "last_login": s.last_login.isoformat() if s.last_login else None,
        "created_at": s.created_at.isoformat(),
    }


def _customer_dict(c: CRMCustomer) -> dict:
    return {
        "id": c.id, "company_name": c.company_name, "vat_number": c.vat_number,
        "phone": c.phone, "website": c.website, "currency": c.currency,
        "language": c.language, "address": c.address, "city": c.city,
        "state": c.state, "zip_code": c.zip_code, "country": c.country,
        "group_ids": c.group_ids or [], "tags": c.tags or [],
        "allow_portal_login": c.allow_portal_login, "is_active": c.is_active,
        "created_at": c.created_at.isoformat(),
        "primary_contact": None,  # filled separately
    }


def _lead_dict(l: CRMLead) -> dict:
    return {
        "id": l.id, "full_name": l.full_name, "first_name": l.first_name,
        "last_name": l.last_name, "company": l.company, "email": l.email,
        "phone": l.phone, "website": l.website, "title": l.title,
        "salutation": l.salutation, "description": l.description,
        "source_id": l.source_id, "source_name": l.source.name if l.source else None,
        "status_id": l.status_id, "status_name": l.status.name if l.status else None,
        "status_color": l.status.color if l.status else None,
        "assigned_to": l.assigned_to,
        "assigned_name": l.assignee.full_name if l.assignee else None,
        "address": l.address, "city": l.city, "state": l.state,
        "zip_code": l.zip_code, "country": l.country,
        "is_public": l.is_public, "tags": l.tags or [],
        "last_contact": l.last_contact.isoformat() if l.last_contact else None,
        "converted_customer_id": l.converted_customer_id,
        "created_at": l.created_at.isoformat(),
    }


def _project_dict(p: CRMProject) -> dict:
    return {
        "id": p.id, "name": p.name,
        "customer_id": p.customer_id,
        "customer_name": p.customer.company_name if p.customer else None,
        "status": p.status, "billing_type": p.billing_type,
        "total_rate": p.total_rate, "estimated_hours": p.estimated_hours,
        "progress": p.progress,
        "calculate_progress_from_tasks": p.calculate_progress_from_tasks,
        "start_date": p.start_date.isoformat() if p.start_date else None,
        "deadline": p.deadline.isoformat() if p.deadline else None,
        "description": p.description, "tags": p.tags or [],
        "member_ids": [m.staff_id for m in (p.members or [])],
        "created_at": p.created_at.isoformat(),
    }


def _task_dict(t: CRMTask) -> dict:
    return {
        "id": t.id, "name": t.name, "project_id": t.project_id,
        "project_name": t.project.name if t.project else None,
        "description": t.description, "status": t.status, "priority": t.priority,
        "start_date": t.start_date.isoformat() if t.start_date else None,
        "due_date": t.due_date.isoformat() if t.due_date else None,
        "assignees": t.assignees or [], "followers": t.followers or [],
        "tags": t.tags or [], "checklist": t.checklist or [],
        "total_logged_time": t.total_logged_time,
        "created_at": t.created_at.isoformat(),
    }


def _invoice_dict(inv: CRMInvoice) -> dict:
    return {
        "id": inv.id, "invoice_number": inv.invoice_number,
        "customer_id": inv.customer_id,
        "customer_name": inv.customer.company_name if inv.customer else None,
        "project_id": inv.project_id, "status": inv.status,
        "date": inv.date.isoformat() if inv.date else None,
        "due_date": inv.due_date.isoformat() if inv.due_date else None,
        "currency": inv.currency, "subtotal": inv.subtotal,
        "tax_total": inv.tax_total, "total": inv.total,
        "amount_paid": inv.amount_paid, "tags": inv.tags or [],
        "is_recurring": inv.is_recurring,
        "created_at": inv.created_at.isoformat(),
    }


def _proposal_dict(p: CRMProposal) -> dict:
    return {
        "id": p.id, "proposal_number": p.proposal_number, "subject": p.subject,
        "customer_id": p.customer_id,
        "customer_name": p.customer.company_name if p.customer else None,
        "status": p.status,
        "date": p.date.isoformat() if p.date else None,
        "open_till": p.open_till.isoformat() if p.open_till else None,
        "total": p.total, "currency": p.currency, "tags": p.tags or [],
        "created_at": p.created_at.isoformat(),
    }


# ── Frontend serving ──────────────────────────────────────────────────────────

_admin_html: Optional[str] = None

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def admin_frontend():
    global _admin_html
    if _admin_html is None:
        p = Path("frontend/admin.html")
        _admin_html = p.read_text(encoding="utf-8") if p.exists() else "<h1>Admin panel not found</h1>"
    return HTMLResponse(_admin_html, headers={"Cache-Control": "no-store"})


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginReq(BaseModel):
    email: str
    password: str


@router.post("/api/auth/seed-admin")
async def seed_admin_recovery(db: AsyncSession = Depends(get_db)):
    """Recovery: creates default admin account if no staff exist."""
    staff_exist = await db.execute(select(func.count()).select_from(StaffMember))
    if (staff_exist.scalar() or 0) > 0:
        return {"ok": False, "detail": "Staff already exist — use normal login."}
    role_r = await db.execute(select(CRMRole).where(CRMRole.name == "Administrator"))
    role = role_r.scalar_one_or_none()
    if not role:
        role = CRMRole(name="Administrator", permissions={"*": {"*": True}})
        db.add(role)
        await db.flush()
    admin = StaffMember(
        first_name="Uplinx", last_name="Admin", email="uplinxmarketing@gmail.com",
        hashed_password=_hash_pw("@UPlinx2026!!"),
        role_id=role.id, is_admin=True,
    )
    db.add(admin)
    await db.commit()
    return {"ok": True, "detail": "Admin created. Email: uplinxmarketing@gmail.com"}


@router.post("/api/auth/login")
async def admin_login(req: LoginReq, response: Response, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(StaffMember).where(
        StaffMember.email == req.email.lower().strip(),
        StaffMember.is_active == True,
    ))
    staff = result.scalar_one_or_none()
    if not staff or not _verify_pw(req.password, staff.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    staff.last_login = _utcnow()
    token = _make_admin_token(staff.id)
    response.set_cookie("admin_session", token, httponly=True, samesite="lax",
                        max_age=_ADMIN_SESSION_LIFETIME)
    return {"ok": True, "staff": _staff_dict(staff)}


@router.post("/api/auth/logout")
async def admin_logout(response: Response):
    response.delete_cookie("admin_session")
    return {"ok": True}


@router.get("/api/auth/me")
async def admin_me(staff: StaffMember = Depends(get_current_admin)):
    return _staff_dict(staff)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@router.get("/api/search")
async def global_search(
    q: str = "",
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    if not q or len(q) < 2:
        return {"customers": [], "invoices": [], "projects": [], "tasks": [], "leads": []}
    like = f"%{q}%"
    customers = (await db.execute(
        select(CRMCustomer.id, CRMCustomer.company_name.label("name"))
        .where(CRMCustomer.company_name.ilike(like)).limit(5)
    )).mappings().all()
    invoices = (await db.execute(
        select(CRMInvoice.id, CRMInvoice.invoice_number.label("name"))
        .where(CRMInvoice.invoice_number.ilike(like)).limit(5)
    )).mappings().all()
    projects = (await db.execute(
        select(CRMProject.id, CRMProject.name)
        .where(CRMProject.name.ilike(like)).limit(5)
    )).mappings().all()
    tasks = (await db.execute(
        select(CRMTask.id, CRMTask.name)
        .where(CRMTask.name.ilike(like)).limit(5)
    )).mappings().all()
    leads = (await db.execute(
        select(CRMLead.id, CRMLead.first_name.label("name"))
        .where(CRMLead.first_name.ilike(like) | CRMLead.last_name.ilike(like) | CRMLead.company.ilike(like)).limit(5)
    )).mappings().all()
    return {
        "customers": [dict(r) for r in customers],
        "invoices": [dict(r) for r in invoices],
        "projects": [dict(r) for r in projects],
        "tasks": [dict(r) for r in tasks],
        "leads": [dict(r) for r in leads],
    }


@router.get("/api/dashboard/stats")
async def dashboard_stats(
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    async def count(model, *wheres):
        q = select(func.count()).select_from(model)
        for w in wheres:
            q = q.where(w)
        r = await db.execute(q)
        return r.scalar() or 0

    async def sum_col(model, col, *wheres):
        q = select(func.sum(col)).select_from(model)
        for w in wheres:
            q = q.where(w)
        r = await db.execute(q)
        return float(r.scalar() or 0)

    total_customers = await count(CRMCustomer, CRMCustomer.is_active == True)
    total_leads = await count(CRMLead)
    total_projects = await count(CRMProject)
    projects_in_progress = await count(CRMProject, CRMProject.status == "in_progress")
    total_tasks = await count(CRMTask)
    tasks_not_done = await count(CRMTask, CRMTask.status != "complete")

    # Invoices
    inv_unpaid = await count(CRMInvoice, CRMInvoice.status.in_(["unpaid", "not_sent"]))
    inv_overdue = await count(CRMInvoice, CRMInvoice.status == "overdue")
    inv_paid = await count(CRMInvoice, CRMInvoice.status == "paid")
    inv_draft = await count(CRMInvoice, CRMInvoice.status == "draft")
    inv_total = await count(CRMInvoice)

    outstanding = await sum_col(CRMInvoice, CRMInvoice.total - CRMInvoice.amount_paid,
                                CRMInvoice.status.in_(["unpaid", "not_sent", "partially_paid"]))
    paid_total = await sum_col(CRMInvoice, CRMInvoice.amount_paid)

    # Proposals
    prop_draft = await count(CRMProposal, CRMProposal.status == "draft")
    prop_sent = await count(CRMProposal, CRMProposal.status == "sent")
    prop_accepted = await count(CRMProposal, CRMProposal.status == "accepted")
    prop_declined = await count(CRMProposal, CRMProposal.status == "declined")
    prop_total = await count(CRMProposal)

    # My tasks
    my_tasks_res = await db.execute(
        select(CRMTask)
        .where(CRMTask.assignees.contains([staff.id]))
        .where(CRMTask.status != "complete")
        .order_by(desc(CRMTask.created_at))
        .limit(10)
        .options(selectinload(CRMTask.project))
    )
    my_tasks = [_task_dict(t) for t in my_tasks_res.scalars().all()]

    # Recent activity
    act_res = await db.execute(
        select(CRMActivity)
        .options(selectinload(CRMActivity.staff))
        .order_by(desc(CRMActivity.created_at))
        .limit(15)
    )
    activity = [
        {
            "id": a.id, "module": a.module, "action": a.action,
            "record_name": a.record_name, "description": a.description,
            "staff_name": a.staff.full_name if a.staff else "System",
            "created_at": a.created_at.isoformat(),
        }
        for a in act_res.scalars().all()
    ]

    # Contracts expiring soon (7 days)
    soon = _utcnow() + timedelta(days=7)
    exp_res = await db.execute(
        select(CRMContract)
        .where(CRMContract.end_date <= soon, CRMContract.end_date >= _utcnow(),
               CRMContract.status == "active")
        .options(selectinload(CRMContract.customer))
        .limit(10)
    )
    expiring_contracts = [
        {
            "id": c.id, "contract_number": c.contract_number, "subject": c.subject,
            "customer_name": c.customer.company_name if c.customer else None,
            "end_date": c.end_date.isoformat() if c.end_date else None,
        }
        for c in exp_res.scalars().all()
    ]

    return {
        "customers": {"total": total_customers},
        "leads": {"total": total_leads},
        "projects": {"total": total_projects, "in_progress": projects_in_progress},
        "tasks": {"total": total_tasks, "not_done": tasks_not_done},
        "invoices": {
            "total": inv_total, "draft": inv_draft, "unpaid": inv_unpaid,
            "overdue": inv_overdue, "paid": inv_paid,
            "outstanding": outstanding, "paid_total": paid_total,
        },
        "proposals": {
            "total": prop_total, "draft": prop_draft, "sent": prop_sent,
            "accepted": prop_accepted, "declined": prop_declined,
        },
        "my_tasks": my_tasks,
        "activity": activity,
        "expiring_contracts": expiring_contracts,
    }


# ── Staff ─────────────────────────────────────────────────────────────────────

class StaffCreateReq(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    phone: Optional[str] = None
    role_id: Optional[int] = None
    is_admin: bool = False
    is_active: bool = True


class StaffUpdateReq(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    linkedin: Optional[str] = None
    role_id: Optional[int] = None
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None
    permission_overrides: Optional[dict] = None
    email_signature: Optional[str] = None


@router.get("/api/staff")
async def list_staff(
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(StaffMember).options(selectinload(StaffMember.role)).order_by(StaffMember.created_at))
    return [_staff_dict(s) for s in r.scalars().all()]


@router.post("/api/staff")
async def create_staff(
    req: StaffCreateReq,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    if not staff.is_admin:
        raise HTTPException(403, "Admin only")
    existing = await db.execute(select(StaffMember).where(StaffMember.email == req.email.lower()))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Email already in use")
    s = StaffMember(
        first_name=req.first_name, last_name=req.last_name,
        email=req.email.lower().strip(), hashed_password=_hash_pw(req.password),
        phone=req.phone, role_id=req.role_id, is_admin=req.is_admin, is_active=req.is_active,
    )
    db.add(s)
    await db.flush()
    await _log(db, staff, "staff", "created", s.id, s.full_name)
    return {"id": s.id}


@router.get("/api/staff/{staff_id}")
async def get_staff(staff_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(StaffMember).where(StaffMember.id == staff_id).options(selectinload(StaffMember.role)))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Not found")
    d = _staff_dict(s)
    d["permission_overrides"] = s.permission_overrides
    d["email_signature"] = s.email_signature
    d["linkedin"] = s.linkedin
    return d


@router.put("/api/staff/{staff_id}")
async def update_staff(
    staff_id: int, req: StaffUpdateReq,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(StaffMember).where(StaffMember.id == staff_id))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Not found")
    if req.first_name is not None: s.first_name = req.first_name
    if req.last_name is not None: s.last_name = req.last_name
    if req.email is not None: s.email = req.email.lower().strip()
    if req.phone is not None: s.phone = req.phone
    if req.linkedin is not None: s.linkedin = req.linkedin
    if req.role_id is not None: s.role_id = req.role_id
    if req.is_admin is not None and staff.is_admin: s.is_admin = req.is_admin
    if req.is_active is not None: s.is_active = req.is_active
    if req.password: s.hashed_password = _hash_pw(req.password)
    if req.permission_overrides is not None: s.permission_overrides = req.permission_overrides
    if req.email_signature is not None: s.email_signature = req.email_signature
    await _log(db, staff, "staff", "updated", s.id, s.full_name)
    return {"ok": True}


@router.delete("/api/staff/{staff_id}")
async def delete_staff(staff_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not staff.is_admin:
        raise HTTPException(403, "Admin only")
    if staff_id == staff.id:
        raise HTTPException(400, "Cannot delete yourself")
    await db.execute(delete(StaffMember).where(StaffMember.id == staff_id))
    return {"ok": True}


# ── Roles ─────────────────────────────────────────────────────────────────────

class RoleReq(BaseModel):
    name: str
    permissions: Optional[dict] = None


@router.get("/api/roles")
async def list_roles(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMRole).order_by(CRMRole.name))
    return [{"id": ro.id, "name": ro.name, "permissions": ro.permissions, "created_at": ro.created_at.isoformat()} for ro in r.scalars().all()]


@router.post("/api/roles")
async def create_role(req: RoleReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not staff.is_admin:
        raise HTTPException(403)
    ro = CRMRole(name=req.name, permissions=req.permissions or {})
    db.add(ro)
    await db.flush()
    return {"id": ro.id}


@router.put("/api/roles/{role_id}")
async def update_role(role_id: int, req: RoleReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMRole).where(CRMRole.id == role_id))
    ro = r.scalar_one_or_none()
    if not ro:
        raise HTTPException(404)
    ro.name = req.name
    if req.permissions is not None:
        ro.permissions = req.permissions
    return {"ok": True}


@router.delete("/api/roles/{role_id}")
async def delete_role(role_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMRole).where(CRMRole.id == role_id))
    return {"ok": True}


# ── Customers ─────────────────────────────────────────────────────────────────

class CustomerReq(BaseModel):
    company_name: str
    vat_number: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    currency: str = "USD"
    language: str = "en"
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: Optional[str] = None
    group_ids: Optional[list] = None
    tags: Optional[list] = None
    allow_portal_login: bool = False
    is_active: bool = True


@router.get("/api/customers")
async def list_customers(
    q: Optional[str] = None,
    is_active: Optional[bool] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    query = select(CRMCustomer).options(selectinload(CRMCustomer.contacts))
    if q:
        query = query.where(CRMCustomer.company_name.ilike(f"%{q}%"))
    if is_active is not None:
        query = query.where(CRMCustomer.is_active == is_active)
    query = query.order_by(CRMCustomer.company_name)
    r = await db.execute(query)
    customers = r.scalars().all()
    result = []
    for c in customers:
        d = _customer_dict(c)
        primary = next((ct for ct in c.contacts if ct.is_primary), None) or (c.contacts[0] if c.contacts else None)
        if primary:
            d["primary_contact"] = {"name": primary.full_name, "email": primary.email, "phone": primary.phone}
        result.append(d)
    return result


@router.post("/api/customers")
async def create_customer(req: CustomerReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    c = CRMCustomer(**req.model_dump())
    db.add(c)
    await db.flush()
    await _log(db, staff, "customers", "created", c.id, c.company_name)
    return {"id": c.id}


@router.get("/api/customers/{cid}")
async def get_customer(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMCustomer).where(CRMCustomer.id == cid)
                         .options(selectinload(CRMCustomer.contacts), selectinload(CRMCustomer.notes)))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    d = _customer_dict(c)
    d["contacts"] = [{"id": ct.id, "full_name": ct.full_name, "email": ct.email,
                       "phone": ct.phone, "title": ct.title, "is_primary": ct.is_primary,
                       "is_active": ct.is_active} for ct in c.contacts]
    d["notes"] = [{"id": n.id, "content": n.content, "created_at": n.created_at.isoformat()} for n in c.notes]
    return d


@router.put("/api/customers/{cid}")
async def update_customer(cid: int, req: CustomerReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMCustomer).where(CRMCustomer.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    for k, v in req.model_dump(exclude_unset=True).items():
        setattr(c, k, v)
    c.updated_at = _utcnow()
    await _log(db, staff, "customers", "updated", c.id, c.company_name)
    return {"ok": True}


@router.delete("/api/customers/{cid}")
async def delete_customer(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMCustomer).where(CRMCustomer.id == cid))
    return {"ok": True}


# Contacts CRUD
class ContactReq(BaseModel):
    first_name: str
    last_name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    title: Optional[str] = None
    is_primary: bool = False
    allow_portal: bool = False


@router.post("/api/customers/{cid}/contacts")
async def add_contact(cid: int, req: ContactReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    ct = CRMContact(customer_id=cid, **req.model_dump())
    db.add(ct)
    await db.flush()
    return {"id": ct.id}


@router.put("/api/contacts/{ct_id}")
async def update_contact(ct_id: int, req: ContactReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContact).where(CRMContact.id == ct_id))
    ct = r.scalar_one_or_none()
    if not ct:
        raise HTTPException(404)
    for k, v in req.model_dump(exclude_unset=True).items():
        setattr(ct, k, v)
    return {"ok": True}


@router.delete("/api/contacts/{ct_id}")
async def delete_contact(ct_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMContact).where(CRMContact.id == ct_id))
    return {"ok": True}


# Customer Notes
class NoteReq(BaseModel):
    content: str


@router.post("/api/customers/{cid}/notes")
async def add_customer_note(cid: int, req: NoteReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    n = CRMNote(customer_id=cid, author_id=staff.id, content=req.content)
    db.add(n)
    await db.flush()
    return {"id": n.id}


@router.delete("/api/notes/{note_id}")
async def delete_note(note_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMNote).where(CRMNote.id == note_id))
    return {"ok": True}


# ── Leads ─────────────────────────────────────────────────────────────────────

class LeadReq(BaseModel):
    first_name: str
    last_name: str
    salutation: Optional[str] = None
    company: Optional[str] = None
    title: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    source_id: Optional[int] = None
    status_id: Optional[int] = None
    assigned_to: Optional[int] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: Optional[str] = None
    description: Optional[str] = None
    is_public: bool = True
    tags: Optional[list] = None


@router.get("/api/leads")
async def list_leads(
    q: Optional[str] = None,
    status_id: Optional[int] = None,
    source_id: Optional[int] = None,
    assigned_to: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    query = (select(CRMLead)
             .options(selectinload(CRMLead.source), selectinload(CRMLead.status), selectinload(CRMLead.assignee))
             .order_by(desc(CRMLead.created_at)))
    if q:
        query = query.where((CRMLead.first_name + " " + CRMLead.last_name).ilike(f"%{q}%") | CRMLead.email.ilike(f"%{q}%") | CRMLead.company.ilike(f"%{q}%"))
    if status_id:
        query = query.where(CRMLead.status_id == status_id)
    if source_id:
        query = query.where(CRMLead.source_id == source_id)
    if assigned_to:
        query = query.where(CRMLead.assigned_to == assigned_to)
    r = await db.execute(query)
    return [_lead_dict(l) for l in r.scalars().all()]


@router.post("/api/leads")
async def create_lead(req: LeadReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    l = CRMLead(**req.model_dump())
    db.add(l)
    await db.flush()
    await _log(db, staff, "leads", "created", l.id, l.full_name)
    return {"id": l.id}


@router.get("/api/leads/{lead_id}")
async def get_lead(lead_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMLead).where(CRMLead.id == lead_id)
                         .options(selectinload(CRMLead.source), selectinload(CRMLead.status),
                                  selectinload(CRMLead.assignee), selectinload(CRMLead.notes)))
    l = r.scalar_one_or_none()
    if not l:
        raise HTTPException(404)
    d = _lead_dict(l)
    d["notes"] = [{"id": n.id, "content": n.content, "created_at": n.created_at.isoformat()} for n in l.notes]
    return d


@router.put("/api/leads/{lead_id}")
async def update_lead(lead_id: int, req: LeadReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMLead).where(CRMLead.id == lead_id))
    l = r.scalar_one_or_none()
    if not l:
        raise HTTPException(404)
    for k, v in req.model_dump(exclude_unset=True).items():
        setattr(l, k, v)
    l.updated_at = _utcnow()
    await _log(db, staff, "leads", "updated", l.id, l.full_name)
    return {"ok": True}


@router.delete("/api/leads/{lead_id}")
async def delete_lead(lead_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMLead).where(CRMLead.id == lead_id))
    return {"ok": True}


@router.post("/api/leads/{lead_id}/convert")
async def convert_lead(lead_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMLead).where(CRMLead.id == lead_id))
    l = r.scalar_one_or_none()
    if not l:
        raise HTTPException(404)
    c = CRMCustomer(company_name=l.company or l.full_name, phone=l.phone, website=l.website,
                    address=l.address, city=l.city, state=l.state, zip_code=l.zip_code, country=l.country)
    db.add(c)
    await db.flush()
    ct = CRMContact(customer_id=c.id, first_name=l.first_name, last_name=l.last_name,
                    email=l.email, phone=l.phone, title=l.title, is_primary=True)
    db.add(ct)
    l.converted_customer_id = c.id
    await _log(db, staff, "leads", "converted", l.id, l.full_name, f"Converted to customer #{c.id}")
    return {"customer_id": c.id}


@router.post("/api/leads/{lead_id}/notes")
async def add_lead_note(lead_id: int, req: NoteReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    n = CRMNote(lead_id=lead_id, author_id=staff.id, content=req.content)
    db.add(n)
    await db.flush()
    return {"id": n.id}


# Lead Sources & Statuses
@router.get("/api/lead-sources")
async def list_lead_sources(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMLeadSource).order_by(CRMLeadSource.name))
    return [{"id": s.id, "name": s.name} for s in r.scalars().all()]


@router.post("/api/lead-sources")
async def create_lead_source(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    s = CRMLeadSource(name=req["name"])
    db.add(s)
    await db.flush()
    return {"id": s.id}


@router.delete("/api/lead-sources/{sid}")
async def delete_lead_source(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMLeadSource).where(CRMLeadSource.id == sid))
    return {"ok": True}


@router.get("/api/lead-statuses")
async def list_lead_statuses(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMLeadStatus).order_by(CRMLeadStatus.sort_order, CRMLeadStatus.name))
    return [{"id": s.id, "name": s.name, "color": s.color} for s in r.scalars().all()]


@router.post("/api/lead-statuses")
async def create_lead_status(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    s = CRMLeadStatus(name=req["name"], color=req.get("color", "#6366f1"))
    db.add(s)
    await db.flush()
    return {"id": s.id}


@router.delete("/api/lead-statuses/{sid}")
async def delete_lead_status(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMLeadStatus).where(CRMLeadStatus.id == sid))
    return {"ok": True}


# ── Projects ──────────────────────────────────────────────────────────────────

class ProjectReq(BaseModel):
    name: str
    customer_id: Optional[int] = None
    status: str = "in_progress"
    billing_type: str = "fixed_rate"
    total_rate: Optional[float] = None
    estimated_hours: Optional[float] = None
    calculate_progress_from_tasks: bool = True
    progress: int = 0
    start_date: Optional[str] = None
    deadline: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list] = None
    member_ids: Optional[list] = None


@router.get("/api/projects")
async def list_projects(
    status: Optional[str] = None,
    customer_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = (select(CRMProject)
         .options(selectinload(CRMProject.customer), selectinload(CRMProject.members))
         .order_by(desc(CRMProject.created_at)))
    if status:
        q = q.where(CRMProject.status == status)
    if customer_id:
        q = q.where(CRMProject.customer_id == customer_id)
    r = await db.execute(q)
    projects = r.scalars().all()
    result = []
    for p in projects:
        d = _project_dict(p)
        # task stats
        task_r = await db.execute(select(func.count(), func.count().filter(CRMTask.status == "complete")).select_from(CRMTask).where(CRMTask.project_id == p.id))
        row = task_r.one()
        d["task_total"] = row[0]
        d["task_done"] = row[1]
        result.append(d)
    return result


@router.post("/api/projects")
async def create_project(req: ProjectReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    data = req.model_dump(exclude={"member_ids", "start_date", "deadline"})
    if req.start_date:
        data["start_date"] = datetime.fromisoformat(req.start_date)
    if req.deadline:
        data["deadline"] = datetime.fromisoformat(req.deadline)
    data["created_by"] = staff.id
    p = CRMProject(**data)
    db.add(p)
    await db.flush()
    member_ids = req.member_ids or [staff.id]
    for mid in member_ids:
        db.add(CRMProjectMember(project_id=p.id, staff_id=mid))
    await _log(db, staff, "projects", "created", p.id, p.name)
    return {"id": p.id}


@router.get("/api/projects/{pid}")
async def get_project(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProject).where(CRMProject.id == pid)
                         .options(selectinload(CRMProject.customer), selectinload(CRMProject.members),
                                  selectinload(CRMProject.tasks)))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    d = _project_dict(p)
    d["tasks"] = [_task_dict(t) for t in p.tasks]
    return d


@router.put("/api/projects/{pid}")
async def update_project(pid: int, req: ProjectReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProject).where(CRMProject.id == pid))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    data = req.model_dump(exclude={"member_ids", "start_date", "deadline"}, exclude_unset=True)
    if req.start_date:
        data["start_date"] = datetime.fromisoformat(req.start_date)
    if req.deadline:
        data["deadline"] = datetime.fromisoformat(req.deadline)
    for k, v in data.items():
        setattr(p, k, v)
    if req.member_ids is not None:
        await db.execute(delete(CRMProjectMember).where(CRMProjectMember.project_id == pid))
        for mid in req.member_ids:
            db.add(CRMProjectMember(project_id=pid, staff_id=mid))
    await _log(db, staff, "projects", "updated", p.id, p.name)
    return {"ok": True}


@router.delete("/api/projects/{pid}")
async def delete_project(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMProject).where(CRMProject.id == pid))
    return {"ok": True}


# ── Tasks ─────────────────────────────────────────────────────────────────────

class TaskReq(BaseModel):
    name: str
    project_id: Optional[int] = None
    description: Optional[str] = None
    status: str = "not_started"
    priority: str = "normal"
    start_date: Optional[str] = None
    due_date: Optional[str] = None
    assignees: Optional[list] = None
    tags: Optional[list] = None


@router.get("/api/tasks")
async def list_tasks(
    project_id: Optional[int] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to_me: Optional[bool] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(CRMTask).options(selectinload(CRMTask.project)).order_by(desc(CRMTask.created_at))
    if project_id:
        q = q.where(CRMTask.project_id == project_id)
    if status:
        q = q.where(CRMTask.status == status)
    if priority:
        q = q.where(CRMTask.priority == priority)
    if assigned_to_me:
        q = q.where(CRMTask.assignees.contains([staff.id]))
    r = await db.execute(q)
    return [_task_dict(t) for t in r.scalars().all()]


@router.post("/api/tasks")
async def create_task(req: TaskReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    data = req.model_dump(exclude={"start_date", "due_date"})
    if req.start_date:
        data["start_date"] = datetime.fromisoformat(req.start_date)
    if req.due_date:
        data["due_date"] = datetime.fromisoformat(req.due_date)
    if not data.get("assignees"):
        data["assignees"] = [staff.id]
    data["created_by"] = staff.id
    t = CRMTask(**data)
    db.add(t)
    await db.flush()
    await _log(db, staff, "tasks", "created", t.id, t.name)
    return {"id": t.id}


@router.get("/api/tasks/{tid}")
async def get_task(tid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTask).where(CRMTask.id == tid)
                         .options(selectinload(CRMTask.project), selectinload(CRMTask.comments).selectinload(CRMTaskComment.author)))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    d = _task_dict(t)
    d["comments"] = [{"id": c.id, "content": c.content, "author_name": c.author.full_name if c.author else "?",
                       "created_at": c.created_at.isoformat()} for c in t.comments]
    return d


@router.put("/api/tasks/{tid}")
async def update_task(tid: int, req: TaskReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTask).where(CRMTask.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    data = req.model_dump(exclude={"start_date", "due_date"}, exclude_unset=True)
    if req.start_date:
        data["start_date"] = datetime.fromisoformat(req.start_date)
    if req.due_date:
        data["due_date"] = datetime.fromisoformat(req.due_date)
    for k, v in data.items():
        setattr(t, k, v)
    t.updated_at = _utcnow()
    return {"ok": True}


@router.delete("/api/tasks/{tid}")
async def delete_task(tid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMTask).where(CRMTask.id == tid))
    return {"ok": True}


@router.put("/api/tasks/{tid}/checklist")
async def update_task_checklist(tid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTask).where(CRMTask.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    t.checklist = req.get("checklist", [])
    return {"ok": True}


class CommentReq(BaseModel):
    content: str


@router.post("/api/tasks/{tid}/comments")
async def add_task_comment(tid: int, req: CommentReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    c = CRMTaskComment(task_id=tid, author_id=staff.id, content=req.content)
    db.add(c)
    await db.flush()
    return {"id": c.id}


# ── Invoices ──────────────────────────────────────────────────────────────────

class InvoiceReq(BaseModel):
    customer_id: Optional[int] = None
    project_id: Optional[int] = None
    invoice_number: Optional[str] = None
    status: str = "draft"
    date: Optional[str] = None
    due_date: Optional[str] = None
    currency: str = "USD"
    discount_type: str = "before_tax"
    discount_value: float = 0.0
    adjustment: float = 0.0
    client_note: Optional[str] = None
    terms: Optional[str] = None
    admin_note: Optional[str] = None
    tags: Optional[list] = None
    assigned_to: Optional[int] = None
    items: Optional[list] = None


@router.get("/api/invoices")
async def list_invoices(
    status: Optional[str] = None,
    customer_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(CRMInvoice).options(selectinload(CRMInvoice.customer)).order_by(desc(CRMInvoice.created_at))
    if status:
        q = q.where(CRMInvoice.status == status)
    if customer_id:
        q = q.where(CRMInvoice.customer_id == customer_id)
    r = await db.execute(q)
    return [_invoice_dict(i) for i in r.scalars().all()]


async def _next_inv_number(db: AsyncSession) -> str:
    r = await db.execute(select(func.count()).select_from(CRMInvoice))
    n = (r.scalar() or 0) + 1
    return f"INV-{n:04d}"


@router.post("/api/invoices")
async def create_invoice(req: InvoiceReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    inv_num = req.invoice_number or await _next_inv_number(db)
    items = req.items or []
    subtotal = sum(it.get("amount", it.get("qty", 1) * it.get("rate", 0)) for it in items)
    inv = CRMInvoice(
        invoice_number=inv_num, customer_id=req.customer_id, project_id=req.project_id,
        status=req.status, currency=req.currency, discount_type=req.discount_type,
        discount_value=req.discount_value, adjustment=req.adjustment,
        subtotal=subtotal, total=subtotal + req.adjustment - req.discount_value,
        client_note=req.client_note, terms=req.terms, admin_note=req.admin_note,
        tags=req.tags or [], assigned_to=req.assigned_to,
        date=datetime.fromisoformat(req.date) if req.date else _utcnow(),
        due_date=datetime.fromisoformat(req.due_date) if req.due_date else None,
    )
    db.add(inv)
    await db.flush()
    for so, it in enumerate(items):
        li = CRMLineItem(invoice_id=inv.id, description=it.get("description", ""),
                         long_description=it.get("long_description"), qty=it.get("qty", 1),
                         rate=it.get("rate", 0), discount=it.get("discount", 0),
                         tax_ids=it.get("tax_ids", []), amount=it.get("amount", 0), sort_order=so)
        db.add(li)
    await _log(db, staff, "invoices", "created", inv.id, inv.invoice_number)
    return {"id": inv.id, "invoice_number": inv.invoice_number}


@router.get("/api/invoices/{inv_id}")
async def get_invoice(inv_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMInvoice).where(CRMInvoice.id == inv_id)
                         .options(selectinload(CRMInvoice.customer), selectinload(CRMInvoice.items),
                                  selectinload(CRMInvoice.payments)))
    inv = r.scalar_one_or_none()
    if not inv:
        raise HTTPException(404)
    d = _invoice_dict(inv)
    d["items"] = [{"id": i.id, "description": i.description, "long_description": i.long_description,
                    "qty": i.qty, "rate": i.rate, "discount": i.discount,
                    "tax_ids": i.tax_ids or [], "amount": i.amount} for i in inv.items]
    d["payments"] = [{"id": p.id, "amount": p.amount, "date": p.date.isoformat(),
                       "transaction_id": p.transaction_id} for p in inv.payments]
    d["bill_to"] = inv.bill_to
    d["client_note"] = inv.client_note
    d["terms"] = inv.terms
    return d


@router.put("/api/invoices/{inv_id}")
async def update_invoice(inv_id: int, req: InvoiceReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMInvoice).where(CRMInvoice.id == inv_id))
    inv = r.scalar_one_or_none()
    if not inv:
        raise HTTPException(404)
    fields = req.model_dump(exclude={"items", "date", "due_date", "invoice_number"}, exclude_unset=True)
    for k, v in fields.items():
        setattr(inv, k, v)
    if req.date:
        inv.date = datetime.fromisoformat(req.date)
    if req.due_date:
        inv.due_date = datetime.fromisoformat(req.due_date)
    if req.items is not None:
        await db.execute(delete(CRMLineItem).where(CRMLineItem.invoice_id == inv_id))
        for so, it in enumerate(req.items):
            db.add(CRMLineItem(invoice_id=inv_id, description=it.get("description", ""),
                               qty=it.get("qty", 1), rate=it.get("rate", 0),
                               discount=it.get("discount", 0), tax_ids=it.get("tax_ids", []),
                               amount=it.get("amount", 0), sort_order=so))
    return {"ok": True}


@router.delete("/api/invoices/{inv_id}")
async def delete_invoice(inv_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMInvoice).where(CRMInvoice.id == inv_id))
    return {"ok": True}


class PaymentReq(BaseModel):
    amount: float
    date: Optional[str] = None
    payment_mode_id: Optional[int] = None
    transaction_id: Optional[str] = None
    note: Optional[str] = None


@router.post("/api/invoices/{inv_id}/payments")
async def record_payment(inv_id: int, req: PaymentReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMInvoice).where(CRMInvoice.id == inv_id))
    inv = r.scalar_one_or_none()
    if not inv:
        raise HTTPException(404)
    p = CRMPayment(invoice_id=inv_id, amount=req.amount, payment_mode_id=req.payment_mode_id,
                   transaction_id=req.transaction_id, note=req.note,
                   date=datetime.fromisoformat(req.date) if req.date else _utcnow())
    db.add(p)
    inv.amount_paid += req.amount
    if inv.amount_paid >= inv.total:
        inv.status = "paid"
    elif inv.amount_paid > 0:
        inv.status = "partially_paid"
    await _log(db, staff, "invoices", "payment_recorded", inv.id, inv.invoice_number)
    return {"ok": True}


# ── Proposals ─────────────────────────────────────────────────────────────────

class ProposalReq(BaseModel):
    subject: str
    customer_id: Optional[int] = None
    lead_id: Optional[int] = None
    status: str = "draft"
    date: Optional[str] = None
    open_till: Optional[str] = None
    currency: str = "USD"
    discount_type: str = "before_tax"
    discount_value: float = 0.0
    adjustment: float = 0.0
    client_note: Optional[str] = None
    terms: Optional[str] = None
    tags: Optional[list] = None
    assigned_to: Optional[int] = None
    items: Optional[list] = None


@router.get("/api/proposals")
async def list_proposals(
    status: Optional[str] = None, customer_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    q = select(CRMProposal).options(selectinload(CRMProposal.customer)).order_by(desc(CRMProposal.created_at))
    if status:
        q = q.where(CRMProposal.status == status)
    if customer_id:
        q = q.where(CRMProposal.customer_id == customer_id)
    r = await db.execute(q)
    return [_proposal_dict(p) for p in r.scalars().all()]


async def _next_prop_number(db: AsyncSession) -> str:
    r = await db.execute(select(func.count()).select_from(CRMProposal))
    n = (r.scalar() or 0) + 1
    return f"PROP-{n:04d}"


@router.post("/api/proposals")
async def create_proposal(req: ProposalReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    items = req.items or []
    subtotal = sum(it.get("amount", 0) for it in items)
    prop = CRMProposal(
        proposal_number=await _next_prop_number(db), subject=req.subject,
        customer_id=req.customer_id, lead_id=req.lead_id, status=req.status,
        currency=req.currency, discount_type=req.discount_type, discount_value=req.discount_value,
        adjustment=req.adjustment, subtotal=subtotal,
        total=subtotal + req.adjustment - req.discount_value,
        client_note=req.client_note, terms=req.terms, tags=req.tags or [],
        assigned_to=req.assigned_to,
        date=datetime.fromisoformat(req.date) if req.date else _utcnow(),
        open_till=datetime.fromisoformat(req.open_till) if req.open_till else None,
    )
    db.add(prop)
    await db.flush()
    for so, it in enumerate(items):
        db.add(CRMLineItem(proposal_id=prop.id, description=it.get("description", ""),
                           qty=it.get("qty", 1), rate=it.get("rate", 0),
                           discount=it.get("discount", 0), amount=it.get("amount", 0), sort_order=so))
    await _log(db, staff, "proposals", "created", prop.id, prop.subject)
    return {"id": prop.id, "proposal_number": prop.proposal_number}


@router.get("/api/proposals/{pid}")
async def get_proposal(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid)
                         .options(selectinload(CRMProposal.customer), selectinload(CRMProposal.items)))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    d = _proposal_dict(p)
    d["items"] = [{"id": i.id, "description": i.description, "qty": i.qty, "rate": i.rate,
                    "discount": i.discount, "tax_ids": i.tax_ids or [], "amount": i.amount} for i in p.items]
    d["client_note"] = p.client_note
    d["terms"] = p.terms
    return d


@router.put("/api/proposals/{pid}")
async def update_proposal(pid: int, req: ProposalReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    fields = req.model_dump(exclude={"items", "date", "open_till"}, exclude_unset=True)
    for k, v in fields.items():
        setattr(p, k, v)
    if req.date:
        p.date = datetime.fromisoformat(req.date)
    if req.open_till:
        p.open_till = datetime.fromisoformat(req.open_till)
    return {"ok": True}


@router.delete("/api/proposals/{pid}")
async def delete_proposal(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMProposal).where(CRMProposal.id == pid))
    return {"ok": True}


# ── Expenses ──────────────────────────────────────────────────────────────────

@router.get("/api/expenses")
async def list_expenses(
    category_id: Optional[int] = None, customer_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    q = select(CRMExpense).options(selectinload(CRMExpense.category), selectinload(CRMExpense.customer)).order_by(desc(CRMExpense.expense_date))
    if category_id:
        q = q.where(CRMExpense.category_id == category_id)
    if customer_id:
        q = q.where(CRMExpense.customer_id == customer_id)
    r = await db.execute(q)
    return [
        {"id": e.id, "name": e.name, "category": e.category.name if e.category else None,
         "amount": e.amount, "currency": e.currency, "reference": e.reference,
         "note": e.note, "expense_date": e.expense_date.isoformat(),
         "customer_name": e.customer.company_name if e.customer else None,
         "is_billable": e.is_billable, "is_billed": e.is_billed}
        for e in r.scalars().all()
    ]


class ExpenseReq(BaseModel):
    name: Optional[str] = None
    category_id: Optional[int] = None
    customer_id: Optional[int] = None
    project_id: Optional[int] = None
    amount: float
    currency: str = "USD"
    tax_id: Optional[int] = None
    payment_mode_id: Optional[int] = None
    reference: Optional[str] = None
    note: Optional[str] = None
    expense_date: Optional[str] = None
    is_billable: bool = False


@router.post("/api/expenses")
async def create_expense(req: ExpenseReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    data = req.model_dump(exclude={"expense_date"})
    data["expense_date"] = datetime.fromisoformat(req.expense_date) if req.expense_date else _utcnow()
    data["created_by"] = staff.id
    e = CRMExpense(**data)
    db.add(e)
    await db.flush()
    await _log(db, staff, "expenses", "created", e.id, e.name)
    return {"id": e.id}


@router.delete("/api/expenses/{eid}")
async def delete_expense(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMExpense).where(CRMExpense.id == eid))
    return {"ok": True}


@router.get("/api/expense-categories")
async def list_expense_cats(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMExpenseCategory).order_by(CRMExpenseCategory.name))
    return [{"id": c.id, "name": c.name} for c in r.scalars().all()]


@router.post("/api/expense-categories")
async def create_expense_cat(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    c = CRMExpenseCategory(name=req["name"])
    db.add(c)
    await db.flush()
    return {"id": c.id}


@router.delete("/api/expense-categories/{cid}")
async def delete_expense_cat(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMExpenseCategory).where(CRMExpenseCategory.id == cid))
    return {"ok": True}


# ── Contracts ─────────────────────────────────────────────────────────────────

class ContractReq(BaseModel):
    subject: str
    customer_id: Optional[int] = None
    project_id: Optional[int] = None
    contract_type_id: Optional[int] = None
    value: Optional[float] = None
    currency: str = "USD"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    status: str = "draft"
    description: Optional[str] = None
    allow_esign: bool = False


@router.get("/api/contracts")
async def list_contracts(
    status: Optional[str] = None, customer_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    q = select(CRMContract).options(selectinload(CRMContract.customer), selectinload(CRMContract.contract_type)).order_by(desc(CRMContract.created_at))
    if status:
        q = q.where(CRMContract.status == status)
    if customer_id:
        q = q.where(CRMContract.customer_id == customer_id)
    r = await db.execute(q)
    return [
        {"id": c.id, "contract_number": c.contract_number, "subject": c.subject,
         "customer_name": c.customer.company_name if c.customer else None,
         "contract_type": c.contract_type.name if c.contract_type else None,
         "value": c.value, "currency": c.currency, "status": c.status,
         "start_date": c.start_date.isoformat() if c.start_date else None,
         "end_date": c.end_date.isoformat() if c.end_date else None,
         "signed_at": c.signed_at.isoformat() if c.signed_at else None}
        for c in r.scalars().all()
    ]


@router.post("/api/contracts")
async def create_contract(req: ContractReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r2 = await db.execute(select(func.count()).select_from(CRMContract))
    n = (r2.scalar() or 0) + 1
    data = req.model_dump(exclude={"start_date", "end_date"})
    if req.start_date:
        data["start_date"] = datetime.fromisoformat(req.start_date)
    if req.end_date:
        data["end_date"] = datetime.fromisoformat(req.end_date)
    data["contract_number"] = f"CON-{n:04d}"
    data["created_by"] = staff.id
    c = CRMContract(**data)
    db.add(c)
    await db.flush()
    await _log(db, staff, "contracts", "created", c.id, c.subject)
    return {"id": c.id, "contract_number": c.contract_number}


@router.delete("/api/contracts/{cid}")
async def delete_contract(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMContract).where(CRMContract.id == cid))
    return {"ok": True}


@router.get("/api/contract-types")
async def list_contract_types(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContractType).order_by(CRMContractType.name))
    return [{"id": ct.id, "name": ct.name} for ct in r.scalars().all()]


@router.post("/api/contract-types")
async def create_contract_type(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    ct = CRMContractType(name=req["name"])
    db.add(ct)
    await db.flush()
    return {"id": ct.id}


@router.delete("/api/contract-types/{ctid}")
async def delete_contract_type(ctid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMContractType).where(CRMContractType.id == ctid))
    return {"ok": True}


# ── Events / Calendar ─────────────────────────────────────────────────────────

class EventReq(BaseModel):
    title: str
    description: Optional[str] = None
    start_date: str
    end_date: Optional[str] = None
    color: str = "#6366f1"
    is_public: bool = True
    notification_minutes: int = 30


@router.get("/api/events")
async def list_events(
    year: Optional[int] = None, month: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    q = select(CRMEvent).options(selectinload(CRMEvent.creator)).order_by(CRMEvent.start_date)
    if year and month:
        from_d = datetime(year, month, 1, tzinfo=timezone.utc)
        if month == 12:
            to_d = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            to_d = datetime(year, month + 1, 1, tzinfo=timezone.utc)
        q = q.where(CRMEvent.start_date >= from_d, CRMEvent.start_date < to_d)
    r = await db.execute(q)
    return [
        {"id": e.id, "title": e.title, "description": e.description, "color": e.color,
         "is_public": e.is_public,
         "start_date": e.start_date.isoformat(),
         "end_date": e.end_date.isoformat() if e.end_date else None,
         "creator": e.creator.full_name if e.creator else None}
        for e in r.scalars().all()
    ]


@router.post("/api/events")
async def create_event(req: EventReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    e = CRMEvent(
        title=req.title, description=req.description, color=req.color,
        is_public=req.is_public, notification_minutes=req.notification_minutes,
        start_date=datetime.fromisoformat(req.start_date),
        end_date=datetime.fromisoformat(req.end_date) if req.end_date else None,
        created_by=staff.id,
    )
    db.add(e)
    await db.flush()
    return {"id": e.id}


@router.delete("/api/events/{eid}")
async def delete_event(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMEvent).where(CRMEvent.id == eid))
    return {"ok": True}


# ── Announcements ─────────────────────────────────────────────────────────────

@router.get("/api/announcements")
async def list_announcements(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMAnnouncement).options(selectinload(CRMAnnouncement.author)).order_by(desc(CRMAnnouncement.created_at)).limit(50))
    return [
        {"id": a.id, "content": a.content, "department": a.department,
         "likes": a.likes or [], "likes_count": len(a.likes or []),
         "author_name": a.author.full_name if a.author else "?",
         "created_at": a.created_at.isoformat()}
        for a in r.scalars().all()
    ]


@router.post("/api/announcements")
async def create_announcement(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    a = CRMAnnouncement(author_id=staff.id, content=req["content"], department=req.get("department"))
    db.add(a)
    await db.flush()
    return {"id": a.id}


@router.post("/api/announcements/{aid}/like")
async def like_announcement(aid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMAnnouncement).where(CRMAnnouncement.id == aid))
    a = r.scalar_one_or_none()
    if not a:
        raise HTTPException(404)
    likes = list(a.likes or [])
    if staff.id in likes:
        likes.remove(staff.id)
    else:
        likes.append(staff.id)
    a.likes = likes
    return {"likes": likes}


# ── Activity Log ──────────────────────────────────────────────────────────────

@router.get("/api/activity")
async def list_activity(
    module: Optional[str] = None, limit: int = 50,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    q = select(CRMActivity).options(selectinload(CRMActivity.staff)).order_by(desc(CRMActivity.created_at)).limit(limit)
    if module:
        q = q.where(CRMActivity.module == module)
    r = await db.execute(q)
    return [
        {"id": a.id, "module": a.module, "action": a.action, "record_id": a.record_id,
         "record_name": a.record_name, "description": a.description,
         "staff_name": a.staff.full_name if a.staff else "System",
         "created_at": a.created_at.isoformat()}
        for a in r.scalars().all()
    ]


# ── Settings ──────────────────────────────────────────────────────────────────

@router.get("/api/settings")
async def get_settings(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMSetting))
    return {s.key: s.value for s in r.scalars().all()}


@router.put("/api/settings")
async def update_settings(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not staff.is_admin:
        raise HTTPException(403)
    for key, value in req.items():
        r = await db.execute(select(CRMSetting).where(CRMSetting.key == key))
        setting = r.scalar_one_or_none()
        if setting:
            setting.value = str(value)
            setting.updated_at = _utcnow()
        else:
            db.add(CRMSetting(key=key, value=str(value)))
    return {"ok": True}


# ── Email Templates ───────────────────────────────────────────────────────────

@router.get("/api/email-templates")
async def list_email_templates(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEmailTemplate).order_by(CRMEmailTemplate.group, CRMEmailTemplate.name))
    result: dict = {}
    for t in r.scalars().all():
        result.setdefault(t.group, []).append({
            "id": t.id, "name": t.name, "slug": t.slug,
            "subject": t.subject, "is_active": t.is_active,
        })
    return result


@router.get("/api/email-templates/{tid}")
async def get_email_template(tid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEmailTemplate).where(CRMEmailTemplate.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    return {"id": t.id, "group": t.group, "name": t.name, "slug": t.slug,
            "subject": t.subject, "body": t.body, "is_active": t.is_active}


@router.put("/api/email-templates/{tid}")
async def update_email_template(tid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEmailTemplate).where(CRMEmailTemplate.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    if "subject" in req:
        t.subject = req["subject"]
    if "body" in req:
        t.body = req["body"]
    if "is_active" in req:
        t.is_active = req["is_active"]
    t.updated_at = _utcnow()
    return {"ok": True}


# ── Customer Groups ───────────────────────────────────────────────────────────

@router.get("/api/customer-groups")
async def list_customer_groups(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMCustomerGroup).order_by(CRMCustomerGroup.name))
    return [{"id": g.id, "name": g.name} for g in r.scalars().all()]


@router.post("/api/customer-groups")
async def create_customer_group(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    g = CRMCustomerGroup(name=req["name"])
    db.add(g)
    await db.flush()
    return {"id": g.id}


@router.delete("/api/customer-groups/{gid}")
async def delete_customer_group(gid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMCustomerGroup).where(CRMCustomerGroup.id == gid))
    return {"ok": True}


# ── To-Do ─────────────────────────────────────────────────────────────────────

@router.get("/api/todos")
async def list_todos(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTodo).where(CRMTodo.staff_id == staff.id).order_by(CRMTodo.created_at))
    return [{"id": t.id, "title": t.title, "is_done": t.is_done,
             "done_at": t.done_at.isoformat() if t.done_at else None,
             "created_at": t.created_at.isoformat()} for t in r.scalars().all()]


@router.post("/api/todos")
async def create_todo(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    t = CRMTodo(staff_id=staff.id, title=req["title"])
    db.add(t)
    await db.flush()
    return {"id": t.id}


@router.put("/api/todos/{tid}/toggle")
async def toggle_todo(tid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTodo).where(CRMTodo.id == tid, CRMTodo.staff_id == staff.id))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    t.is_done = not t.is_done
    t.done_at = _utcnow() if t.is_done else None
    return {"is_done": t.is_done}


@router.delete("/api/todos/{tid}")
async def delete_todo(tid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMTodo).where(CRMTodo.id == tid, CRMTodo.staff_id == staff.id))
    return {"ok": True}


# ── Timesheets ────────────────────────────────────────────────────────────────

@router.get("/api/timesheets")
async def list_timesheets(
    staff_id: Optional[int] = None, project_id: Optional[int] = None,
    current_staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    target_id = staff_id if (current_staff.is_admin and staff_id) else current_staff.id
    q = (select(CRMTimesheet)
         .options(selectinload(CRMTimesheet.task), selectinload(CRMTimesheet.project))
         .where(CRMTimesheet.staff_id == target_id)
         .order_by(desc(CRMTimesheet.start_time)))
    if project_id:
        q = q.where(CRMTimesheet.project_id == project_id)
    r = await db.execute(q)
    return [
        {"id": ts.id, "task_name": ts.task.name if ts.task else None,
         "project_name": ts.project.name if ts.project else None,
         "start_time": ts.start_time.isoformat(),
         "end_time": ts.end_time.isoformat() if ts.end_time else None,
         "duration": ts.duration, "note": ts.note}
        for ts in r.scalars().all()
    ]


@router.post("/api/timesheets")
async def create_timesheet(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    ts = CRMTimesheet(
        staff_id=staff.id, task_id=req.get("task_id"), project_id=req.get("project_id"),
        start_time=datetime.fromisoformat(req["start_time"]) if "start_time" in req else _utcnow(),
        end_time=datetime.fromisoformat(req["end_time"]) if "end_time" in req else None,
        duration=req.get("duration", 0), note=req.get("note"),
    )
    db.add(ts)
    await db.flush()
    return {"id": ts.id}


# ── DB initialisation ─────────────────────────────────────────────────────────

async def init_admin_db(engine) -> None:
    """Create all admin CRM tables and seed default data."""
    from sqlalchemy.ext.asyncio import AsyncConnection
    async with engine.begin() as conn:
        await conn.run_sync(AdminBase.metadata.create_all)

    # Seed from a short session
    from sqlalchemy.ext.asyncio import AsyncSession as _AS, async_sessionmaker as _asm
    session_factory = _asm(bind=engine, expire_on_commit=False)
    async with session_factory() as db:
        # Default roles
        roles_exist = await db.execute(select(func.count()).select_from(CRMRole))
        if (roles_exist.scalar() or 0) == 0:
            default_roles = [
                CRMRole(name="Administrator", permissions={"*": {"*": True}}),
                CRMRole(name="Manager", permissions={}),
                CRMRole(name="Sales", permissions={"proposals": {"view": True, "create": True}, "leads": {"view": True, "create": True}}),
                CRMRole(name="Copywriter", permissions={"tasks": {"view": True, "create": True}}),
            ]
            for ro in default_roles:
                db.add(ro)

        # Default payment modes
        pm_exist = await db.execute(select(func.count()).select_from(CRMPaymentMode))
        if (pm_exist.scalar() or 0) == 0:
            for name in ["Bank Transfer", "Cash", "Credit Card", "PayPal", "Stripe"]:
                db.add(CRMPaymentMode(name=name))

        # Default contract types
        ct_exist = await db.execute(select(func.count()).select_from(CRMContractType))
        if (ct_exist.scalar() or 0) == 0:
            for name in ["Meta Ads", "SEO", "Retainer", "One-time Project", "Consulting"]:
                db.add(CRMContractType(name=name))

        # Default lead sources
        ls_exist = await db.execute(select(func.count()).select_from(CRMLeadSource))
        if (ls_exist.scalar() or 0) == 0:
            for name in ["Website", "Referral", "Social Media", "Cold Call", "Email Campaign", "Trade Show"]:
                db.add(CRMLeadSource(name=name))

        # Default lead statuses
        lst_exist = await db.execute(select(func.count()).select_from(CRMLeadStatus))
        if (lst_exist.scalar() or 0) == 0:
            for i, (name, color) in enumerate([
                ("New", "#6366f1"), ("Contacted", "#3b82f6"), ("Qualified", "#f59e0b"),
                ("Proposal Sent", "#8b5cf6"), ("Negotiation", "#ec4899"), ("Won", "#10b981"), ("Lost", "#ef4444"),
            ]):
                db.add(CRMLeadStatus(name=name, color=color, sort_order=i))

        # Default expense categories
        ec_exist = await db.execute(select(func.count()).select_from(CRMExpenseCategory))
        if (ec_exist.scalar() or 0) == 0:
            for name in ["Software", "Hardware", "Travel", "Marketing", "Office Supplies", "Meals", "Other"]:
                db.add(CRMExpenseCategory(name=name))

        # Default currency
        cur_exist = await db.execute(select(func.count()).select_from(CRMCurrency))
        if (cur_exist.scalar() or 0) == 0:
            db.add(CRMCurrency(code="USD", name="US Dollar", symbol="$", is_default=True))
            db.add(CRMCurrency(code="EUR", name="Euro", symbol="€"))
            db.add(CRMCurrency(code="GBP", name="British Pound", symbol="£"))

        # Seed default admin staff if none exist
        await db.flush()  # ensure roles are visible to this query
        staff_exist = await db.execute(select(func.count()).select_from(StaffMember))
        if (staff_exist.scalar() or 0) == 0:
            admin_role_r = await db.execute(select(CRMRole).where(CRMRole.name == "Administrator"))
            admin_role = admin_role_r.scalar_one_or_none()
            admin = StaffMember(
                first_name="Uplinx", last_name="Admin", email="uplinxmarketing@gmail.com",
                hashed_password=_hash_pw("@UPlinx2026!!"),
                role_id=admin_role.id if admin_role else None,
                is_admin=True,
            )
            db.add(admin)

        await db.commit()
