"""
admin_router.py — FastAPI router for the Uplinx Admin / CRM system.
All routes are mounted under /admin. Auth uses a separate 'admin_session' cookie.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import base64 as _b64
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, func, desc, delete, update, extract, or_, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database import get_db
from admin_models import (
    AdminBase, CRMRole, CRMApp, CRMUserAppAccess, CRMUserAppClientAccess,
    StaffMember, CRMCustomer, CRMContact, CRMNote,
    CRMLead, CRMLeadSource, CRMLeadStatus, CRMProject, CRMProjectMember,
    CRMTask, CRMTaskComment, CRMTimesheet, CRMInvoice, CRMProposal,
    CRMEstimate, CRMEstimateRequestForm, CRMEstimateRequest, CRMEstimateRequestStatus,
    CRMLineItem, CRMPayment, CRMPaymentMode,
    CRMCreditNote, CRMCreditApplication, CRMCreditRefund,
    CRMSubscription, CRMExpense, CRMExpenseCategory,
    CRMContract, CRMContractType, CRMContractRenewal,
    CRMMilestone, CRMProjectDiscussion, CRMDiscussionComment, CRMPinnedProject,
    CRMEvent, CRMAnnouncement,
    CRMAnnouncementComment, CRMActivity, CRMSetting, CRMEmailTemplate,
    CRMCatalogItem, CRMTaxRate, CRMCurrency, CRMCustomerGroup, CRMTodo,
    CRMStaffNote, CRMTag,
    CRMCustomField, CRMCustomFieldValue, CRMTaggable, CRMReminder,
    CRMPolyNote, CRMFile, CRMFilter, CRMFilterDefault, CRMNotification,
    CRMSalesActivity, CRMProjectActivity, CRMMailQueue, CRMTrackedMail,
    CRMScheduledEmail, CRMDashboardLayout,
    CRMTicketDepartment, CRMTicketPriority, CRMTicketStatus, CRMTicketService,
    CRMTicket, CRMTicketReply, CRMPredefinedReply, CRMSpamFilter,
    CRMKBGroup, CRMKBArticle, CRMKBArticleFeedback,
    CRMVaultEntry, CRMVaultEntryAccess,
    CRMGoal,
)

import logging
logger = logging.getLogger("uplinx.admin")

router = APIRouter(prefix="/admin")

# ── Capability matrix ─────────────────────────────────────────────────────────
# { module_key: { capability_key: display_label } }
CAPABILITY_MATRIX: dict[str, dict[str, str]] = {
    "dashboard":      {"view": "View Dashboard"},
    "customers":      {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete", "import": "Import", "export": "Export"},
    "leads":          {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete", "convert": "Convert to Customer", "import": "Import"},
    "estimates":      {"view": "View", "view_all": "View All", "create": "Create", "edit": "Edit", "delete": "Delete",
                       "send": "Send to Client", "mark_sent": "Mark Sent", "convert_to_invoice": "Convert to Invoice"},
    "estimate_requests": {"view": "View Requests", "edit": "Edit", "delete": "Delete",
                          "convert_to_estimate": "Convert to Estimate",
                          "manage_forms": "Manage Forms", "manage_statuses": "Manage Statuses"},
    "proposals":      {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete", "send": "Send to Client"},
    "invoices":       {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete", "send": "Send to Client", "record_payment": "Record Payment"},
    "payments":       {"view": "View", "create": "Create", "delete": "Delete"},
    "credit_notes":   {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete"},
    "subscriptions":  {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete"},
    "expenses":       {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete"},
    "contracts":      {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete"},
    "projects":       {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete"},
    "tasks":          {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete"},
    "time_tracking":  {"view": "View", "create": "Log Time", "edit": "Edit", "delete": "Delete"},
    "tickets":        {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete", "close": "Close"},
    "knowledge_base": {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete"},
    "calendar":       {"view": "View", "create": "Create Events", "edit": "Edit", "delete": "Delete"},
    "goals":          {"view": "View", "create": "Create", "edit": "Edit"},
    "reports":        {"view": "View", "export": "Export"},
    "settings":       {"view": "View", "edit": "Edit Settings"},
    "staff":          {"view": "View Staff", "create": "Create", "edit": "Edit", "delete": "Delete"},
    "roles":          {"view": "View Roles", "create": "Create", "edit": "Edit", "delete": "Delete"},
}

MODULE_LABELS: dict[str, str] = {
    "dashboard": "Dashboard", "customers": "Customers", "leads": "Leads",
    "estimates": "Estimates", "proposals": "Proposals", "invoices": "Invoices",
    "payments": "Payments", "credit_notes": "Credit Notes", "subscriptions": "Subscriptions",
    "expenses": "Expenses", "contracts": "Contracts", "projects": "Projects",
    "tasks": "Tasks", "time_tracking": "Time Tracking", "tickets": "Tickets",
    "knowledge_base": "Knowledge Base", "calendar": "Calendar", "goals": "Goals & Reports",
    "reports": "Reports", "settings": "Settings", "staff": "Staff Management", "roles": "Roles",
}

# Default role permission sets (is_admin handles Administrator fully)
_DEFAULT_ROLES = [
    ("Administrator", "Full access — bypasses all permission checks", {"*": {"*": True}}),
    ("Account Manager", "Manages clients, projects, invoices, and leads end-to-end", {
        "dashboard": {"view": True},
        "customers": {"view": True, "create": True, "edit": True, "delete": True, "import": True, "export": True},
        "leads": {"view": True, "create": True, "edit": True, "delete": True, "convert": True},
        "estimates": {"view": True, "create": True, "edit": True, "send": True},
        "proposals": {"view": True, "create": True, "edit": True, "send": True},
        "invoices": {"view": True, "create": True, "edit": True, "send": True, "record_payment": True},
        "payments": {"view": True, "create": True},
        "contracts": {"view": True, "create": True, "edit": True},
        "projects": {"view": True, "create": True, "edit": True},
        "tasks": {"view": True, "create": True, "edit": True, "delete": True},
        "time_tracking": {"view": True, "create": True, "edit": True},
        "calendar": {"view": True, "create": True, "edit": True},
        "reports": {"view": True, "export": True},
    }),
    ("Media Buyer", "Runs paid media campaigns; limited CRM access", {
        "dashboard": {"view": True},
        "customers": {"view": True},
        "projects": {"view": True},
        "tasks": {"view": True, "create": True, "edit": True},
        "time_tracking": {"view": True, "create": True, "edit": True},
        "calendar": {"view": True, "create": True},
    }),
    ("Copywriter", "Content creation and knowledge base management", {
        "dashboard": {"view": True},
        "customers": {"view": True},
        "projects": {"view": True},
        "tasks": {"view": True, "create": True, "edit": True},
        "time_tracking": {"view": True, "create": True, "edit": True},
        "knowledge_base": {"view": True, "create": True, "edit": True},
        "calendar": {"view": True},
    }),
    ("Sales", "Leads, proposals, estimates, and new client acquisition", {
        "dashboard": {"view": True},
        "customers": {"view": True, "create": True},
        "leads": {"view": True, "create": True, "edit": True, "delete": True, "convert": True, "import": True},
        "estimates": {"view": True, "create": True, "edit": True, "send": True},
        "proposals": {"view": True, "create": True, "edit": True, "send": True},
        "contracts": {"view": True, "create": True, "edit": True},
        "calendar": {"view": True, "create": True},
    }),
    ("Contractor", "External contractor — tasks and time tracking only", {
        "dashboard": {"view": True},
        "projects": {"view": True},
        "tasks": {"view": True, "create": True, "edit": True},
        "time_tracking": {"view": True, "create": True, "edit": True},
    }),
]

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


# ── Cross-app SSO ──────────────────────────────────────────────────────────
# The CRM (crm_staff) is the single source of truth. When a staff member signs
# in to the CRM, also establish a Meta Ads app session so they can open the
# Meta app without logging in again. We provision/sync the linked Meta `users`
# row (never deleting Meta data — only linking/back-filling/keeping in sync).
META_SESSION_COOKIE = "uplinx_session"

async def _set_meta_session(staff: StaffMember, response: Response, db: AsyncSession, remember_me: bool = False):
    from database import User
    from security import create_session_token
    conds = []
    if staff.username:
        conds.append(User.username == staff.username)
    if staff.email:
        conds.append(func.lower(User.email) == staff.email.lower())
    user = None
    if conds:
        user = (await db.execute(select(User).where(or_(*conds)))).scalars().first()

    derived_username = staff.username or (staff.email.split("@")[0] if staff.email else f"user{staff.id}")
    role = "admin" if staff.is_admin else "user"
    if user:
        user.hashed_password = staff.hashed_password
        user.is_active = True
        user.role = role
        if staff.email and not user.email:
            user.email = staff.email
    else:
        user = User(
            username=derived_username, email=staff.email,
            hashed_password=staff.hashed_password, role=role,
            interface_access="both", is_active=True,
        )
        db.add(user)
    await db.flush()
    token = create_session_token({
        "user_id": user.id, "user_role": user.role,
        "user_access": user.interface_access, "username": user.username,
    })
    response.set_cookie(
        META_SESSION_COOKIE, token, httponly=True, samesite="lax",
        max_age=(86400 * 30 if remember_me else None),
    )


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
    result = await db.execute(select(StaffMember).options(selectinload(StaffMember.role)).where(StaffMember.id == staff_id, StaffMember.is_active == True))
    staff = result.scalar_one_or_none()
    if not staff:
        raise HTTPException(status_code=401, detail="Staff not found")
    return staff


async def _require_staff(request: Request, db: AsyncSession) -> StaffMember:
    """Direct (non-Depends) version of get_current_admin for use inside endpoint bodies."""
    return await get_current_admin(request, db)


def _perm(staff: StaffMember, module: str, action: str) -> bool:
    """Check if staff has a given permission, respecting role + overrides."""
    if staff.is_admin:
        return True
    overrides = staff.permission_overrides or {}
    mod_overrides = overrides.get(module, {})
    if action in mod_overrides:
        return bool(mod_overrides[action])
    if staff.role and staff.role.permissions:
        rp = staff.role.permissions
        # Wildcard role (Administrator JSON)
        if rp.get("*", {}).get("*"):
            return True
        return bool(rp.get(module, {}).get(action, False))
    return False


def _effective_perms(staff: StaffMember) -> dict:
    """Return a flat { module: { action: bool } } dict of effective permissions."""
    if staff.is_admin:
        return {m: {a: True for a in caps} for m, caps in CAPABILITY_MATRIX.items()}
    result: dict[str, dict[str, bool]] = {}
    role_perms = {}
    if staff.role and staff.role.permissions:
        rp = staff.role.permissions
        if rp.get("*", {}).get("*"):
            return {m: {a: True for a in caps} for m, caps in CAPABILITY_MATRIX.items()}
        role_perms = rp
    overrides = staff.permission_overrides or {}
    for module, caps in CAPABILITY_MATRIX.items():
        result[module] = {}
        for action in caps:
            mod_ov = overrides.get(module, {})
            if action in mod_ov:
                result[module][action] = bool(mod_ov[action])
            else:
                result[module][action] = bool(role_perms.get(module, {}).get(action, False))
    return result


async def can_manage_client_in_app(
    staff: StaffMember, app_key: str, client_id: int, db: AsyncSession
) -> bool:
    """Returns True if staff can manage the given client in the given app."""
    if staff.is_admin:
        return True
    app_r = await db.execute(select(CRMApp).where(CRMApp.key == app_key, CRMApp.is_active == True))
    app = app_r.scalar_one_or_none()
    if not app:
        return False
    access_r = await db.execute(
        select(CRMUserAppAccess).where(
            CRMUserAppAccess.staff_id == staff.id,
            CRMUserAppAccess.app_id == app.id,
        )
    )
    if not access_r.scalar_one_or_none():
        return False
    client_r = await db.execute(
        select(CRMUserAppClientAccess).where(
            CRMUserAppClientAccess.staff_id == staff.id,
            CRMUserAppClientAccess.app_id == app.id,
            CRMUserAppClientAccess.client_id == client_id,
        )
    )
    return client_r.scalar_one_or_none() is not None


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
        "username": s.username,
        "role_id": s.role_id, "role_name": s.role.name if s.role else None,
        "is_admin": s.is_admin, "is_active": s.is_active,
        "profile_photo": s.profile_photo,
        "email_signature": s.email_signature,
        "language": s.language,
        "timezone": s.timezone,
        "last_login": s.last_login.isoformat() if s.last_login else None,
        "last_ip": s.last_ip,
        "force_password_change": s.force_password_change,
        "permissions": _effective_perms(s),
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
        "total_rate": p.total_rate, "rate_per_hour": p.rate_per_hour,
        "project_cost": p.project_cost,
        "estimated_hours": p.estimated_hours,
        "progress": p.progress,
        "calculate_progress_from_tasks": p.calculate_progress_from_tasks,
        "start_date": p.start_date.isoformat() if p.start_date else None,
        "deadline": p.deadline.isoformat() if p.deadline else None,
        "date_finished": p.date_finished.isoformat() if p.date_finished else None,
        "description": p.description, "tags": p.tags or [],
        "member_ids": [m.staff_id for m in (p.members or [])],
        "created_at": p.created_at.isoformat(),
    }


def _contract_dict(c: CRMContract) -> dict:
    return {
        "id": c.id, "contract_number": c.contract_number, "subject": c.subject,
        "customer_id": c.customer_id,
        "customer_name": c.customer.company_name if c.customer else None,
        "project_id": c.project_id,
        "contract_type_id": c.contract_type_id,
        "contract_type": c.contract_type.name if c.contract_type else None,
        "value": c.value, "currency": c.currency, "status": c.status,
        "description": c.description, "content": c.content,
        "allow_esign": c.allow_esign, "signed": c.signed,
        "marked_as_signed": c.marked_as_signed,
        "signed_at": c.signed_at.isoformat() if c.signed_at else None,
        "signed_ip": c.signed_ip,
        "acceptance_first_name": c.acceptance_first_name,
        "acceptance_last_name": c.acceptance_last_name,
        "acceptance_email": c.acceptance_email,
        "acceptance_date": c.acceptance_date.isoformat() if c.acceptance_date else None,
        "acceptance_ip": c.acceptance_ip,
        "acceptance_signature": c.acceptance_signature,
        "hash": c.hash, "trashed": c.trashed,
        "not_visible_to_client": c.not_visible_to_client,
        "last_sent_at": c.last_sent_at.isoformat() if c.last_sent_at else None,
        "tags": c.tags or [],
        "start_date": c.start_date.isoformat() if c.start_date else None,
        "end_date": c.end_date.isoformat() if c.end_date else None,
        "created_at": c.created_at.isoformat(),
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
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
        "number": getattr(inv, "number", 0), "prefix": getattr(inv, "prefix", "INV"),
        "formatted_number": getattr(inv, "formatted_number", inv.invoice_number),
        "customer_id": inv.customer_id,
        "customer_name": inv.customer.company_name if inv.customer else None,
        "project_id": inv.project_id, "status": inv.status,
        "date": inv.date.isoformat() if inv.date else None,
        "due_date": inv.due_date.isoformat() if inv.due_date else None,
        "currency": inv.currency, "subtotal": inv.subtotal,
        "discount_type": inv.discount_type, "discount_value": inv.discount_value,
        "discount_total": getattr(inv, "discount_total", 0.0),
        "tax_total": inv.tax_total, "adjustment": inv.adjustment,
        "total": inv.total, "amount_paid": inv.amount_paid,
        "tags": inv.tags or [], "is_recurring": inv.is_recurring,
        "admin_note": inv.admin_note, "bill_to": inv.bill_to,
        "order_number": inv.order_number,
        "assigned_to": inv.assigned_to,
        "sale_agent_id": getattr(inv, "sale_agent_id", None),
        "hash": getattr(inv, "hash", ""),
        "sent_at": inv.sent_at.isoformat() if inv.sent_at else None,
        "created_at": inv.created_at.isoformat(),
        "updated_at": inv.updated_at.isoformat() if getattr(inv, "updated_at", None) else None,
    }


def _proposal_dict(p: CRMProposal) -> dict:
    return {
        "id": p.id, "proposal_number": p.proposal_number, "subject": p.subject,
        "number": getattr(p, "number", 0), "prefix": getattr(p, "prefix", "PROP"),
        "formatted_number": getattr(p, "formatted_number", p.proposal_number),
        "customer_id": p.customer_id,
        "customer_name": p.customer.company_name if p.customer else None,
        "lead_id": p.lead_id,
        "sale_agent_id": getattr(p, "sale_agent_id", None),
        "status": p.status,
        "pipeline_order": getattr(p, "pipeline_order", 0),
        "date": p.date.isoformat() if p.date else None,
        "open_till": p.open_till.isoformat() if p.open_till else None,
        "currency": p.currency,
        "discount_type": p.discount_type, "discount_value": p.discount_value,
        "discount_total": getattr(p, "discount_total", 0.0),
        "subtotal": p.subtotal, "tax_total": p.tax_total,
        "adjustment": p.adjustment, "total": p.total,
        "allow_comments": getattr(p, "allow_comments", False),
        "admin_note": getattr(p, "admin_note", None),
        "tags": p.tags or [],
        "assigned_to": p.assigned_to,
        "hash": getattr(p, "hash", ""),
        "converted_to_invoice_id": getattr(p, "converted_to_invoice_id", None),
        "converted_at": p.converted_at.isoformat() if getattr(p, "converted_at", None) else None,
        "acceptance_date": p.acceptance_date.isoformat() if getattr(p, "acceptance_date", None) else None,
        "sent_at": p.sent_at.isoformat() if p.sent_at else None,
        "created_at": p.created_at.isoformat(),
        "updated_at": p.updated_at.isoformat() if getattr(p, "updated_at", None) else None,
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

_LOGIN_LOCKOUT_ATTEMPTS = 5
_LOGIN_LOCKOUT_MINUTES = 15
_RESET_TOKEN_HOURS = 1
_REMEMBER_ME_DAYS = 30


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    return xff.split(",")[0].strip() if xff else (request.client.host if request.client else "unknown")


async def _send_email(to: str, subject: str, html: str) -> bool:
    """Send a transactional email. Returns True on success, False if SMTP not configured."""
    from config import settings as _s
    import smtplib, ssl
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    if not _s.SMTP_HOST or not _s.SMTP_USER:
        return False
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{_s.SMTP_FROM_NAME} <{_s.SMTP_FROM or _s.SMTP_USER}>"
    msg["To"] = to
    msg.attach(MIMEText(html, "html"))
    try:
        ctx = ssl.create_default_context()
        if _s.SMTP_PORT == 465:
            with smtplib.SMTP_SSL(_s.SMTP_HOST, _s.SMTP_PORT, context=ctx) as srv:
                srv.login(_s.SMTP_USER, _s.SMTP_PASS)
                srv.sendmail(msg["From"], [to], msg.as_string())
        else:
            with smtplib.SMTP(_s.SMTP_HOST, _s.SMTP_PORT) as srv:
                srv.starttls(context=ctx)
                srv.login(_s.SMTP_USER, _s.SMTP_PASS)
                srv.sendmail(msg["From"], [to], msg.as_string())
        return True
    except Exception:
        return False


class LoginReq(BaseModel):
    email: str  # accepts email OR username (the field name is kept for compatibility)
    password: str
    remember_me: bool = False


class ForgotPasswordReq(BaseModel):
    email: str


class ResetPasswordReq(BaseModel):
    token: str
    new_password: str


class ChangePasswordReq(BaseModel):
    current_password: str
    new_password: str


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
async def admin_login(req: LoginReq, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    now = _utcnow()
    # Accept either an email or a username as the login identifier.
    ident = (req.email or "").strip()
    result = await db.execute(
        select(StaffMember).options(selectinload(StaffMember.role)).where(
            or_(
                func.lower(StaffMember.email) == ident.lower(),
                StaffMember.username == ident,
            )
        )
    )
    staff = result.scalar_one_or_none()

    # Always spend the same time even on unknown email (prevent enumeration)
    if not staff:
        _verify_pw(req.password, "pbkdf2:sha256:260000$x$x")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Check lockout
    if staff.locked_until and staff.locked_until > now:
        remaining = int((staff.locked_until - now).total_seconds() / 60) + 1
        raise HTTPException(status_code=429, detail=f"Account locked. Try again in {remaining} minute(s).")

    if not staff.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled. Contact your administrator.")

    if not _verify_pw(req.password, staff.hashed_password):
        staff.failed_login_attempts = (staff.failed_login_attempts or 0) + 1
        if staff.failed_login_attempts >= _LOGIN_LOCKOUT_ATTEMPTS:
            staff.locked_until = now + timedelta(minutes=_LOGIN_LOCKOUT_MINUTES)
            staff.failed_login_attempts = 0
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Success — reset counters, log IP/time
    staff.failed_login_attempts = 0
    staff.locked_until = None
    staff.last_login = now
    staff.last_ip = _client_ip(request)
    await db.commit()

    max_age = 86400 * _REMEMBER_ME_DAYS if req.remember_me else _ADMIN_SESSION_LIFETIME
    token = _make_admin_token(staff.id)
    response.set_cookie("admin_session", token, httponly=True, samesite="lax", max_age=max_age)
    # Single sign-on: also establish a Meta Ads app session so the same login
    # grants access to the connected app without a second sign-in.
    try:
        await _set_meta_session(staff, response, db, remember_me=req.remember_me)
        await db.commit()
    except Exception as _sso_e:
        logger.debug("Meta SSO session not set: %s", _sso_e)
    return {"ok": True, "staff": _staff_dict(staff), "force_password_change": staff.force_password_change}


@router.post("/api/auth/logout")
async def admin_logout(response: Response):
    response.delete_cookie("admin_session")
    return {"ok": True}


@router.get("/api/auth/me")
async def admin_me(staff: StaffMember = Depends(get_current_admin)):
    return {**_staff_dict(staff), "force_password_change": staff.force_password_change}


@router.post("/api/auth/forgot-password")
async def admin_forgot_password(req: ForgotPasswordReq, request: Request, db: AsyncSession = Depends(get_db)):
    """Send a password-reset email. Always returns 200 to prevent enumeration."""
    from config import settings as _s
    result = await db.execute(
        select(StaffMember).where(StaffMember.email == req.email.lower().strip(), StaffMember.is_active == True)
    )
    staff = result.scalar_one_or_none()
    if staff:
        token = secrets.token_urlsafe(64)
        staff.password_reset_token = token
        staff.password_reset_expires = _utcnow() + timedelta(hours=_RESET_TOKEN_HOURS)
        await db.commit()
        base = _s.BASE_URL.rstrip("/")
        reset_url = f"{base}/admin?reset_token={token}"
        html = f"""
        <p>Hi {staff.first_name},</p>
        <p>Someone requested a password reset for your Uplinx CRM account.</p>
        <p><a href="{reset_url}" style="background:#6366f1;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;">Reset my password</a></p>
        <p>This link expires in {_RESET_TOKEN_HOURS} hour(s). If you didn't request this, ignore this email.</p>
        """
        await _send_email(staff.email, "Uplinx CRM — Password Reset", html)
    return {"ok": True, "detail": "If that email exists, a reset link has been sent."}


@router.post("/api/auth/reset-password")
async def admin_reset_password(req: ResetPasswordReq, db: AsyncSession = Depends(get_db)):
    now = _utcnow()
    result = await db.execute(
        select(StaffMember).where(
            StaffMember.password_reset_token == req.token,
            StaffMember.password_reset_expires > now,
            StaffMember.is_active == True,
        )
    )
    staff = result.scalar_one_or_none()
    if not staff:
        raise HTTPException(status_code=400, detail="Reset link is invalid or has expired.")
    if len(req.new_password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")
    staff.hashed_password = _hash_pw(req.new_password)
    staff.password_reset_token = None
    staff.password_reset_expires = None
    staff.last_password_change_at = now
    staff.force_password_change = False
    staff.failed_login_attempts = 0
    staff.locked_until = None
    await db.commit()
    return {"ok": True, "detail": "Password updated. Please log in."}


@router.post("/api/auth/change-password")
async def admin_change_password(
    req: ChangePasswordReq,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    if not _verify_pw(req.current_password, staff.hashed_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect.")
    if len(req.new_password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")
    staff.hashed_password = _hash_pw(req.new_password)
    staff.last_password_change_at = _utcnow()
    staff.force_password_change = False
    await db.commit()
    return {"ok": True}


@router.get("/api/auth/profile")
async def get_my_profile(staff: StaffMember = Depends(get_current_admin)):
    return _staff_dict(staff)


@router.put("/api/auth/profile")
async def update_my_profile(
    data: dict,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    allowed = {"first_name", "last_name", "phone", "language", "timezone", "email_signature", "profile_photo"}
    for k, v in data.items():
        if k in allowed:
            setattr(staff, k, v)
    staff.updated_at = _utcnow()
    await db.commit()
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
    description: Optional[str] = None
    permissions: Optional[dict] = None


@router.get("/api/roles/capabilities")
async def get_capability_matrix(staff: StaffMember = Depends(get_current_admin)):
    """Returns the full capability matrix used for role editing."""
    return {"matrix": CAPABILITY_MATRIX, "labels": MODULE_LABELS}


@router.get("/api/roles")
async def list_roles(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    roles = (await db.execute(select(CRMRole).order_by(CRMRole.name))).scalars().all()
    # Count staff per role
    counts_r = await db.execute(
        select(StaffMember.role_id, func.count().label("n"))
        .where(StaffMember.role_id != None)
        .group_by(StaffMember.role_id)
    )
    counts = {row.role_id: row.n for row in counts_r}
    return [
        {
            "id": ro.id, "name": ro.name, "description": ro.description,
            "permissions": ro.permissions,
            "staff_count": counts.get(ro.id, 0),
            "created_at": ro.created_at.isoformat(),
        }
        for ro in roles
    ]


@router.post("/api/roles")
async def create_role(req: RoleReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "roles", "create"):
        raise HTTPException(403, "No permission")
    ro = CRMRole(name=req.name, description=req.description, permissions=req.permissions or {})
    db.add(ro)
    await db.commit()
    await db.refresh(ro)
    return {"id": ro.id, "name": ro.name}


@router.put("/api/roles/{role_id}")
async def update_role(role_id: int, req: RoleReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "roles", "edit"):
        raise HTTPException(403, "No permission")
    r = await db.execute(select(CRMRole).where(CRMRole.id == role_id))
    ro = r.scalar_one_or_none()
    if not ro:
        raise HTTPException(404)
    ro.name = req.name
    if req.description is not None:
        ro.description = req.description
    if req.permissions is not None:
        ro.permissions = req.permissions
    await db.commit()
    return {"ok": True}


@router.delete("/api/roles/{role_id}")
async def delete_role(role_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "roles", "delete"):
        raise HTTPException(403, "No permission")
    # Don't delete if staff assigned to it
    count_r = await db.execute(select(func.count()).select_from(StaffMember).where(StaffMember.role_id == role_id))
    if (count_r.scalar() or 0) > 0:
        raise HTTPException(400, "Cannot delete role: staff members are still assigned to it.")
    await db.execute(delete(CRMRole).where(CRMRole.id == role_id))
    await db.commit()
    return {"ok": True}


# ── Apps ──────────────────────────────────────────────────────────────────────

@router.get("/api/apps")
async def list_apps(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    apps = (await db.execute(select(CRMApp).order_by(CRMApp.name))).scalars().all()
    return [{"id": a.id, "key": a.key, "name": a.name, "description": a.description,
             "icon": a.icon, "base_url": a.base_url, "is_active": a.is_active} for a in apps]


@router.get("/api/apps/my-access")
async def my_app_access(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Returns apps the current user can access (for the app launcher)."""
    if staff.is_admin:
        apps = (await db.execute(select(CRMApp).where(CRMApp.is_active == True))).scalars().all()
        return [{"id": a.id, "key": a.key, "name": a.name, "icon": a.icon, "base_url": a.base_url} for a in apps]
    rows = await db.execute(
        select(CRMApp).join(CRMUserAppAccess, CRMUserAppAccess.app_id == CRMApp.id)
        .where(CRMUserAppAccess.staff_id == staff.id, CRMApp.is_active == True)
    )
    apps = rows.scalars().all()
    return [{"id": a.id, "key": a.key, "name": a.name, "icon": a.icon, "base_url": a.base_url} for a in apps]


@router.get("/api/staff/{staff_id}/app-access")
async def get_staff_app_access(
    staff_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)
):
    if not staff.is_admin and staff.id != staff_id:
        raise HTTPException(403)
    apps = (await db.execute(select(CRMApp).order_by(CRMApp.name))).scalars().all()
    access_rows = (await db.execute(
        select(CRMUserAppAccess).where(CRMUserAppAccess.staff_id == staff_id)
    )).scalars().all()
    access_by_app = {row.app_id: row for row in access_rows}
    client_rows = (await db.execute(
        select(CRMUserAppClientAccess).where(CRMUserAppClientAccess.staff_id == staff_id)
    )).scalars().all()
    clients_by_app: dict[int, list[int]] = {}
    for cr in client_rows:
        clients_by_app.setdefault(cr.app_id, []).append(cr.client_id)
    return [
        {
            "app_id": a.id, "key": a.key, "name": a.name, "icon": a.icon,
            "is_active": a.is_active,
            "has_access": a.id in access_by_app,
            "client_ids": clients_by_app.get(a.id, []),
        }
        for a in apps
    ]


class AppAccessReq(BaseModel):
    app_id: int
    grant: bool
    client_ids: Optional[list[int]] = None  # None = don't change; [] = all removed


@router.put("/api/staff/{staff_id}/app-access")
async def set_staff_app_access(
    staff_id: int, req: AppAccessReq,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)
):
    if not staff.is_admin:
        raise HTTPException(403, "Admin only")
    if req.grant:
        existing = (await db.execute(
            select(CRMUserAppAccess).where(
                CRMUserAppAccess.staff_id == staff_id, CRMUserAppAccess.app_id == req.app_id
            )
        )).scalar_one_or_none()
        if not existing:
            db.add(CRMUserAppAccess(staff_id=staff_id, app_id=req.app_id, granted_by=staff.id))
    else:
        await db.execute(delete(CRMUserAppAccess).where(
            CRMUserAppAccess.staff_id == staff_id, CRMUserAppAccess.app_id == req.app_id
        ))
        await db.execute(delete(CRMUserAppClientAccess).where(
            CRMUserAppClientAccess.staff_id == staff_id, CRMUserAppClientAccess.app_id == req.app_id
        ))
    if req.grant and req.client_ids is not None:
        await db.execute(delete(CRMUserAppClientAccess).where(
            CRMUserAppClientAccess.staff_id == staff_id, CRMUserAppClientAccess.app_id == req.app_id
        ))
        for cid in req.client_ids:
            db.add(CRMUserAppClientAccess(staff_id=staff_id, app_id=req.app_id, client_id=cid))
    await db.commit()
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
    billing_address: Optional[str] = None
    billing_city: Optional[str] = None
    billing_state: Optional[str] = None
    billing_zip: Optional[str] = None
    billing_country: Optional[str] = None
    shipping_address: Optional[str] = None
    shipping_city: Optional[str] = None
    shipping_state: Optional[str] = None
    shipping_zip: Optional[str] = None
    shipping_country: Optional[str] = None
    group_ids: Optional[list] = None
    tags: Optional[list] = None
    allow_portal_login: bool = False
    is_active: bool = True
    # Contact included in create form
    contact_first_name: Optional[str] = None
    contact_last_name: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None


def _contact_dict(ct: "CRMContact") -> dict:
    return {
        "id": ct.id, "customer_id": ct.customer_id,
        "full_name": ct.full_name, "first_name": ct.first_name, "last_name": ct.last_name,
        "email": ct.email, "phone": ct.phone, "title": ct.title,
        "is_primary": ct.is_primary, "can_login": ct.can_login,
        "allow_portal": ct.allow_portal, "is_active": ct.is_active,
        "email_opt_ins": ct.email_opt_ins or {},
        "last_login": ct.last_login.isoformat() if ct.last_login else None,
        "created_at": ct.created_at.isoformat(),
    }


@router.get("/api/customers")
async def list_customers(
    q: Optional[str] = None,
    is_active: Optional[bool] = None,
    country: Optional[str] = None,
    tag: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    if not _perm(staff, "customers", "view"):
        raise HTTPException(403)
    query = select(CRMCustomer).options(selectinload(CRMCustomer.contacts))
    if q:
        query = query.where(CRMCustomer.company_name.ilike(f"%{q}%"))
    if is_active is not None:
        query = query.where(CRMCustomer.is_active == is_active)
    if country:
        query = query.where(CRMCustomer.country == country)
    query = query.order_by(CRMCustomer.company_name)
    r = await db.execute(query)
    customers = r.scalars().all()
    result = []
    for c in customers:
        if tag and tag not in (c.tags or []):
            continue
        d = _customer_dict(c)
        primary = next((ct for ct in c.contacts if ct.is_primary), None) or (c.contacts[0] if c.contacts else None)
        d["primary_contact"] = {"id": primary.id, "name": primary.full_name, "email": primary.email, "phone": primary.phone} if primary else None
        result.append(d)
    return result


@router.post("/api/customers")
async def create_customer(req: CustomerReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "customers", "create"):
        raise HTTPException(403)
    data = req.model_dump()
    contact_first = data.pop("contact_first_name", None)
    contact_last = data.pop("contact_last_name", None)
    contact_email = data.pop("contact_email", None)
    contact_phone = data.pop("contact_phone", None)
    c = CRMCustomer(**data, created_by=staff.id)
    db.add(c)
    await db.flush()
    if contact_first or contact_last:
        ct = CRMContact(
            customer_id=c.id,
            first_name=contact_first or "Contact",
            last_name=contact_last or "",
            email=contact_email,
            phone=contact_phone,
            is_primary=True,
        )
        db.add(ct)
    await _log(db, staff, "customers", "created", c.id, c.company_name)
    await db.commit()
    return {"id": c.id}


@router.get("/api/customers/{cid}")
async def get_customer(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "customers", "view"):
        raise HTTPException(403)
    r = await db.execute(
        select(CRMCustomer).where(CRMCustomer.id == cid)
        .options(selectinload(CRMCustomer.contacts), selectinload(CRMCustomer.notes))
    )
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    d = _customer_dict(c)
    d["contacts"] = [_contact_dict(ct) for ct in c.contacts]
    d["notes"] = [{"id": n.id, "content": n.content,
                   "author": n.author_id, "created_at": n.created_at.isoformat()} for n in c.notes]
    return d


@router.put("/api/customers/{cid}")
async def update_customer(cid: int, req: CustomerReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "customers", "edit"):
        raise HTTPException(403)
    r = await db.execute(select(CRMCustomer).where(CRMCustomer.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    data = req.model_dump(exclude_unset=True)
    data.pop("contact_first_name", None); data.pop("contact_last_name", None)
    data.pop("contact_email", None); data.pop("contact_phone", None)
    for k, v in data.items():
        setattr(c, k, v)
    c.updated_at = _utcnow()
    await _log(db, staff, "customers", "updated", c.id, c.company_name)
    await db.commit()
    return {"ok": True}


@router.delete("/api/customers/{cid}")
async def delete_customer(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "customers", "delete"):
        raise HTTPException(403)
    r = await db.execute(select(CRMCustomer).where(CRMCustomer.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    await _log(db, staff, "customers", "deleted", c.id, c.company_name)
    await db.execute(delete(CRMCustomer).where(CRMCustomer.id == cid))
    await db.commit()
    return {"ok": True}


@router.get("/api/customers/{cid}/financial-summary")
async def customer_financial_summary(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "customers", "view_financial_summary"):
        return {"total_invoiced": 0, "total_paid": 0, "outstanding": 0, "overdue": 0}
    now = _utcnow()
    invoices = (await db.execute(
        select(CRMInvoice).where(CRMInvoice.customer_id == cid)
    )).scalars().all()
    total_invoiced = sum(float(i.total or 0) for i in invoices)
    total_paid = sum(float(i.amount_paid or 0) for i in invoices)
    outstanding = sum(float((i.total or 0) - (i.amount_paid or 0)) for i in invoices if i.status not in ("paid", "cancelled"))
    overdue = sum(float((i.total or 0) - (i.amount_paid or 0)) for i in invoices
                  if i.status not in ("paid", "cancelled") and i.due_date and i.due_date < now)
    return {"total_invoiced": total_invoiced, "total_paid": total_paid, "outstanding": outstanding, "overdue": overdue}


@router.get("/api/customers/{cid}/statement")
async def customer_statement(
    cid: int,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    from datetime import date as _date
    if not _perm(staff, "customers", "view_statement"):
        raise HTTPException(403)
    r = await db.execute(select(CRMCustomer).where(CRMCustomer.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    try:
        dt_from = datetime.fromisoformat(date_from) if date_from else None
        dt_to = datetime.fromisoformat(date_to) if date_to else None
    except ValueError:
        dt_from = dt_to = None

    inv_q = select(CRMInvoice).where(CRMInvoice.customer_id == cid)
    if dt_from:
        inv_q = inv_q.where(CRMInvoice.created_at >= dt_from)
    if dt_to:
        inv_q = inv_q.where(CRMInvoice.created_at <= dt_to)
    invoices = (await db.execute(inv_q.order_by(CRMInvoice.created_at))).scalars().all()

    pay_q = select(CRMPayment).join(CRMInvoice, CRMPayment.invoice_id == CRMInvoice.id).where(CRMInvoice.customer_id == cid)
    if dt_from:
        pay_q = pay_q.where(CRMPayment.date >= dt_from)
    if dt_to:
        pay_q = pay_q.where(CRMPayment.date <= dt_to)
    payments = (await db.execute(pay_q.order_by(CRMPayment.date))).scalars().all()

    # Build chronological rows
    rows = []
    for inv in invoices:
        rows.append({
            "date": inv.created_at.date().isoformat(),
            "type": "Invoice",
            "ref": inv.invoice_number or f"INV-{inv.id}",
            "amount_in": float(inv.total or 0),
            "amount_out": 0,
        })
    for pay in payments:
        rows.append({
            "date": (pay.date or pay.created_at).date().isoformat() if pay.date or pay.created_at else "",
            "type": "Payment",
            "ref": pay.transaction_id or f"PAY-{pay.id}",
            "amount_in": 0,
            "amount_out": float(pay.amount or 0),
        })
    rows.sort(key=lambda x: x["date"])

    balance = 0.0
    for row in rows:
        balance += row["amount_in"] - row["amount_out"]
        row["balance"] = round(balance, 2)

    total_invoiced = sum(r["amount_in"] for r in rows)
    total_paid = sum(r["amount_out"] for r in rows)
    return {
        "customer": _customer_dict(c),
        "period_from": date_from, "period_to": date_to,
        "rows": rows,
        "totals": {
            "invoiced": round(total_invoiced, 2),
            "paid": round(total_paid, 2),
            "balance": round(balance, 2),
        }
    }


# Contacts CRUD
class ContactReq(BaseModel):
    first_name: str
    last_name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    title: Optional[str] = None
    is_primary: bool = False
    can_login: bool = False
    allow_portal: bool = False
    email_opt_ins: Optional[dict] = None


@router.post("/api/customers/{cid}/contacts")
async def add_contact(cid: int, req: ContactReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "customers", "manage_contacts"):
        raise HTTPException(403)
    data = req.model_dump()
    ct = CRMContact(customer_id=cid, **data)
    if ct.is_primary:
        await db.execute(update(CRMContact).where(CRMContact.customer_id == cid).values(is_primary=False))
    db.add(ct)
    await db.commit()
    await db.refresh(ct)
    return _contact_dict(ct)


@router.put("/api/contacts/{ct_id}")
async def update_contact(ct_id: int, req: ContactReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "customers", "manage_contacts"):
        raise HTTPException(403)
    r = await db.execute(select(CRMContact).where(CRMContact.id == ct_id))
    ct = r.scalar_one_or_none()
    if not ct:
        raise HTTPException(404)
    if req.is_primary:
        await db.execute(update(CRMContact).where(CRMContact.customer_id == ct.customer_id).values(is_primary=False))
    for k, v in req.model_dump(exclude_unset=True).items():
        setattr(ct, k, v)
    await db.commit()
    return {"ok": True}


@router.delete("/api/contacts/{ct_id}")
async def delete_contact(ct_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "customers", "manage_contacts"):
        raise HTTPException(403)
    await db.execute(delete(CRMContact).where(CRMContact.id == ct_id))
    await db.commit()
    return {"ok": True}


# Customer Notes
class NoteReq(BaseModel):
    content: str


@router.post("/api/customers/{cid}/notes")
async def add_customer_note(cid: int, req: NoteReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    n = CRMNote(customer_id=cid, author_id=staff.id, content=req.content)
    db.add(n)
    await db.commit()
    await db.refresh(n)
    return {"id": n.id, "content": n.content, "created_at": n.created_at.isoformat()}


@router.delete("/api/notes/{note_id}")
async def delete_note(note_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMNote).where(CRMNote.id == note_id))
    await db.commit()
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
    rate_per_hour: Optional[float] = None
    project_cost: Optional[float] = None
    estimated_hours: Optional[float] = None
    calculate_progress_from_tasks: bool = True
    progress: int = 0
    start_date: Optional[str] = None
    deadline: Optional[str] = None
    date_finished: Optional[str] = None
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
    data = req.model_dump(exclude={"member_ids", "start_date", "deadline", "date_finished"}, exclude_unset=True)
    if req.start_date:
        data["start_date"] = datetime.fromisoformat(req.start_date)
    if req.deadline:
        data["deadline"] = datetime.fromisoformat(req.deadline)
    if req.date_finished:
        data["date_finished"] = datetime.fromisoformat(req.date_finished)
    for k, v in data.items():
        setattr(p, k, v)
    if req.member_ids is not None:
        await db.execute(delete(CRMProjectMember).where(CRMProjectMember.project_id == pid))
        for mid in req.member_ids:
            db.add(CRMProjectMember(project_id=pid, staff_id=mid))
    await _log(db, staff, "projects", "updated", p.id, p.name)
    return {"ok": True}


@router.post("/api/projects/{pid}/pin")
async def pin_project(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    existing = (await db.execute(select(CRMPinnedProject).where(CRMPinnedProject.project_id == pid, CRMPinnedProject.staff_id == staff.id))).scalar_one_or_none()
    if not existing:
        db.add(CRMPinnedProject(project_id=pid, staff_id=staff.id))
    return {"ok": True}


@router.delete("/api/projects/{pid}/pin")
async def unpin_project(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMPinnedProject).where(CRMPinnedProject.project_id == pid, CRMPinnedProject.staff_id == staff.id))
    return {"ok": True}


@router.get("/api/projects/{pid}/milestones")
async def list_milestones(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMMilestone).where(CRMMilestone.project_id == pid).order_by(CRMMilestone.order, CRMMilestone.id))
    return [{"id": m.id, "project_id": m.project_id, "name": m.name, "description": m.description,
             "start_date": m.start_date.isoformat() if m.start_date else None,
             "due_date": m.due_date.isoformat() if m.due_date else None,
             "color": m.color, "order": m.order, "created_at": m.created_at.isoformat()}
            for m in r.scalars().all()]


@router.post("/api/projects/{pid}/milestones")
async def create_milestone(pid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    m = CRMMilestone(
        project_id=pid, name=req["name"],
        description=req.get("description"),
        color=req.get("color", "#6366f1"),
        order=req.get("order", 0),
        start_date=datetime.fromisoformat(req["start_date"]) if req.get("start_date") else None,
        due_date=datetime.fromisoformat(req["due_date"]) if req.get("due_date") else None,
    )
    db.add(m)
    await db.flush()
    return {"id": m.id}


@router.put("/api/projects/{pid}/milestones/{mid}")
async def update_milestone(pid: int, mid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMMilestone).where(CRMMilestone.id == mid, CRMMilestone.project_id == pid))
    m = r.scalar_one_or_none()
    if not m:
        raise HTTPException(404)
    for field in ["name", "description", "color", "order"]:
        if field in req:
            setattr(m, field, req[field])
    if req.get("start_date"):
        m.start_date = datetime.fromisoformat(req["start_date"])
    if req.get("due_date"):
        m.due_date = datetime.fromisoformat(req["due_date"])
    return {"ok": True}


@router.delete("/api/projects/{pid}/milestones/{mid}")
async def delete_milestone(pid: int, mid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMMilestone).where(CRMMilestone.id == mid, CRMMilestone.project_id == pid))
    return {"ok": True}


@router.get("/api/projects/{pid}/discussions")
async def list_discussions(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProjectDiscussion).options(selectinload(CRMProjectDiscussion.creator), selectinload(CRMProjectDiscussion.comments)).where(CRMProjectDiscussion.project_id == pid).order_by(desc(CRMProjectDiscussion.created_at)))
    result = []
    for d in r.scalars().all():
        result.append({"id": d.id, "project_id": d.project_id, "subject": d.subject,
                       "description": d.description, "visible_to_customer": d.visible_to_customer,
                       "created_by": d.created_by, "creator_name": f"{d.creator.first_name} {d.creator.last_name}" if d.creator else None,
                       "created_at": d.created_at.isoformat(),
                       "comment_count": len(d.comments)})
    return result


@router.post("/api/projects/{pid}/discussions")
async def create_discussion(pid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    d = CRMProjectDiscussion(
        project_id=pid, subject=req["subject"],
        description=req.get("description"),
        visible_to_customer=req.get("visible_to_customer", False),
        created_by=staff.id,
    )
    db.add(d)
    await db.flush()
    return {"id": d.id}


@router.get("/api/projects/{pid}/discussions/{did}/comments")
async def list_discussion_comments(pid: int, did: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMDiscussionComment).options(selectinload(CRMDiscussionComment.creator)).where(CRMDiscussionComment.discussion_id == did).order_by(CRMDiscussionComment.created_at))
    return [{"id": c.id, "discussion_id": c.discussion_id, "content": c.content,
             "created_by": c.created_by, "creator_name": f"{c.creator.first_name} {c.creator.last_name}" if c.creator else None,
             "created_at": c.created_at.isoformat()} for c in r.scalars().all()]


@router.post("/api/projects/{pid}/discussions/{did}/comments")
async def add_discussion_comment(pid: int, did: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    c = CRMDiscussionComment(discussion_id=did, content=req["content"], created_by=staff.id)
    db.add(c)
    await db.flush()
    return {"id": c.id}


@router.delete("/api/projects/{pid}/discussions/{did}")
async def delete_discussion(pid: int, did: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMProjectDiscussion).where(CRMProjectDiscussion.id == did, CRMProjectDiscussion.project_id == pid))
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
    sale_agent_id: Optional[int] = None
    invoice_number: Optional[str] = None
    prefix: str = "INV"
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
    billing_address: Optional[dict] = None
    shipping_address: Optional[dict] = None
    order_number: Optional[str] = None
    allowed_payment_modes: Optional[list] = None
    is_recurring: bool = False
    recurring_config: Optional[dict] = None
    items: Optional[list] = None


def _compute_inv_totals(items: list, discount_type: str, discount_value: float, adjustment: float) -> dict:
    subtotal = sum(it.get("qty", 1) * it.get("rate", 0) for it in items)
    tax_total = 0.0
    for it in items:
        rate = it.get("rate", 0)
        qty = it.get("qty", 1)
        disc = it.get("discount", 0)
        line_sub = qty * rate * (1 - disc / 100)
        tax_ids = it.get("tax_ids", [])
        if isinstance(tax_ids, list):
            for tid in tax_ids:
                if isinstance(tid, dict):
                    tax_total += line_sub * tid.get("rate", 0) / 100
    discount_total = (subtotal * discount_value / 100) if discount_type == "percentage" else discount_value
    total = subtotal - discount_total + tax_total + adjustment
    for it in items:
        it["amount"] = round(it.get("qty", 1) * it.get("rate", 0) * (1 - it.get("discount", 0) / 100), 4)
    return {"subtotal": round(subtotal, 4), "tax_total": round(tax_total, 4),
            "discount_total": round(discount_total, 4), "total": round(total, 4)}


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


async def _next_inv_number(db: AsyncSession, prefix: str = "INV") -> tuple[str, int, str]:
    r = await db.execute(select(func.count()).select_from(CRMInvoice))
    n = (r.scalar() or 0) + 1
    formatted = f"{prefix}-{n:04d}"
    return formatted, n, formatted


@router.post("/api/invoices")
async def create_invoice(req: InvoiceReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    prefix = (req.prefix or "INV").upper()
    inv_num_str, num_int, formatted = await _next_inv_number(db, prefix)
    inv_number = req.invoice_number or inv_num_str
    items = req.items or []
    totals = _compute_inv_totals(items, req.discount_type, req.discount_value, req.adjustment)
    inv = CRMInvoice(
        invoice_number=inv_number, number=num_int, prefix=prefix, formatted_number=formatted,
        customer_id=req.customer_id, project_id=req.project_id, sale_agent_id=req.sale_agent_id,
        status=req.status, currency=req.currency, discount_type=req.discount_type,
        discount_value=req.discount_value, adjustment=req.adjustment,
        billing_address=req.billing_address, shipping_address=req.shipping_address,
        order_number=req.order_number, allowed_payment_modes=req.allowed_payment_modes,
        is_recurring=req.is_recurring, recurring_config=req.recurring_config,
        **totals,
        client_note=req.client_note, terms=req.terms, admin_note=req.admin_note,
        tags=req.tags or [], assigned_to=req.assigned_to,
        date=datetime.fromisoformat(req.date) if req.date else _utcnow(),
        due_date=datetime.fromisoformat(req.due_date) if req.due_date else None,
    )
    db.add(inv)
    await db.flush()
    for so, it in enumerate(items):
        db.add(CRMLineItem(invoice_id=inv.id, description=it.get("description", ""),
                           long_description=it.get("long_description"), qty=it.get("qty", 1),
                           rate=it.get("rate", 0), discount=it.get("discount", 0),
                           tax_ids=it.get("tax_ids", []), amount=it.get("amount", 0), sort_order=so))
    await _log(db, staff, "invoices", "created", inv.id, inv.invoice_number)
    return {"id": inv.id, "invoice_number": inv.invoice_number, "formatted_number": formatted}


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
    d["payments"] = [{"id": p.id, "amount": p.amount,
                       "date": p.date.isoformat() if p.date else None,
                       "transaction_id": p.transaction_id, "note": p.note} for p in inv.payments]
    d["billing_address"] = getattr(inv, "billing_address", None)
    d["shipping_address"] = getattr(inv, "shipping_address", None)
    d["bill_to"] = inv.bill_to
    d["client_note"] = inv.client_note
    d["terms"] = inv.terms
    d["recurring_config"] = inv.recurring_config
    d["allowed_payment_modes"] = getattr(inv, "allowed_payment_modes", None)
    return d


@router.put("/api/invoices/{inv_id}")
async def update_invoice(inv_id: int, req: InvoiceReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMInvoice).where(CRMInvoice.id == inv_id))
    inv = r.scalar_one_or_none()
    if not inv:
        raise HTTPException(404)
    fields = req.model_dump(exclude={"items", "date", "due_date", "invoice_number", "prefix"}, exclude_unset=True)
    for k, v in fields.items():
        if hasattr(inv, k):
            setattr(inv, k, v)
    if req.date:
        inv.date = datetime.fromisoformat(req.date)
    if req.due_date:
        inv.due_date = datetime.fromisoformat(req.due_date)
    if req.items is not None:
        items = req.items
        totals = _compute_inv_totals(items, req.discount_type, req.discount_value, req.adjustment)
        for k, v in totals.items():
            setattr(inv, k, v)
        await db.execute(delete(CRMLineItem).where(CRMLineItem.invoice_id == inv_id))
        for so, it in enumerate(items):
            db.add(CRMLineItem(invoice_id=inv_id, description=it.get("description", ""),
                               long_description=it.get("long_description"), qty=it.get("qty", 1),
                               rate=it.get("rate", 0), discount=it.get("discount", 0),
                               tax_ids=it.get("tax_ids", []), amount=it.get("amount", 0), sort_order=so))
    inv.updated_at = _utcnow()
    await _log(db, staff, "invoices", "updated", inv.id, inv.invoice_number)
    return {"ok": True}


@router.delete("/api/invoices/{inv_id}")
async def delete_invoice(inv_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMInvoice).where(CRMInvoice.id == inv_id))
    return {"ok": True}


@router.post("/api/invoices/{inv_id}/send")
async def send_invoice(inv_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMInvoice).where(CRMInvoice.id == inv_id)
                         .options(selectinload(CRMInvoice.customer)))
    inv = r.scalar_one_or_none()
    if not inv:
        raise HTTPException(404)
    inv.sent_at = _utcnow()
    if inv.status == "draft":
        inv.status = "not_sent"
    from config import settings as _s
    public_url = f"{_s.BASE_URL.rstrip('/')}/admin/invoice/{inv.id}/{getattr(inv, 'hash', '')}"
    if inv.customer and inv.customer.email:
        html = (f"<p>Dear {inv.customer.company_name},</p>"
                f"<p>Please find your invoice <strong>{inv.invoice_number}</strong> at the link below:</p>"
                f"<p><a href='{public_url}'>{public_url}</a></p>")
        await _send_email(inv.customer.email, f"Invoice {inv.invoice_number}", html)
    inv.status = "not_sent"
    inv.sent_at = _utcnow()
    await _log(db, staff, "invoices", "sent", inv.id, inv.invoice_number)
    return {"ok": True, "public_url": public_url}


@router.post("/api/invoices/{inv_id}/mark-sent")
async def mark_invoice_sent(inv_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMInvoice).where(CRMInvoice.id == inv_id))
    inv = r.scalar_one_or_none()
    if not inv:
        raise HTTPException(404)
    inv.sent_at = _utcnow()
    inv.status = "not_sent"
    await _log(db, staff, "invoices", "mark_sent", inv.id, inv.invoice_number)
    return {"ok": True}


@router.get("/invoice/{inv_id}/{hash_val}", response_class=HTMLResponse)
async def public_invoice_page(inv_id: int, hash_val: str, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMInvoice).where(CRMInvoice.id == inv_id)
                         .options(selectinload(CRMInvoice.customer), selectinload(CRMInvoice.items),
                                  selectinload(CRMInvoice.payments)))
    inv = r.scalar_one_or_none()
    if not inv or getattr(inv, "hash", "") != hash_val:
        raise HTTPException(404)
    items_html = "".join(
        f"<tr><td>{i.description}</td><td style='text-align:right'>{i.qty}</td>"
        f"<td style='text-align:right'>${i.rate:,.2f}</td>"
        f"<td style='text-align:right'>${i.amount:,.2f}</td></tr>" for i in inv.items
    )
    payments_html = ""
    for p in inv.payments:
        payments_html += f"<tr><td>{p.date.strftime('%Y-%m-%d') if p.date else ''}</td><td>${p.amount:,.2f}</td><td>{p.transaction_id or ''}</td></tr>"
    amount_due = inv.total - inv.amount_paid
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Invoice {inv.invoice_number}</title>
<style>
  body{{font-family:sans-serif;max-width:800px;margin:40px auto;padding:0 20px;color:#222}}
  h1{{color:#6366f1}}
  table{{width:100%;border-collapse:collapse;margin:16px 0}}
  th,td{{padding:10px;border-bottom:1px solid #e5e7eb;text-align:left}}
  th{{background:#f9fafb;font-weight:600}}
  .totals-row{{font-weight:600}}
  .badge{{display:inline-block;padding:4px 10px;border-radius:9999px;font-size:.8rem;font-weight:600;
    background:{'#10b981' if inv.status=='paid' else '#f59e0b' if inv.status in ('unpaid','not_sent') else '#6b7280'};color:#fff}}
  .due-box{{background:#fef3c7;border:1px solid #fbbf24;border-radius:8px;padding:16px;margin:24px 0}}
</style>
</head><body>
<h1>Invoice #{inv.invoice_number}</h1>
<p>Status: <span class="badge">{inv.status.replace('_',' ').title()}</span></p>
{'<p>To: '+inv.customer.company_name+'</p>' if inv.customer else ''}
<p>Date: {inv.date.strftime('%B %d, %Y') if inv.date else 'N/A'} &nbsp;|&nbsp; Due: {inv.due_date.strftime('%B %d, %Y') if inv.due_date else 'N/A'}</p>
<table>
  <thead><tr><th>Description</th><th style="text-align:right">Qty</th><th style="text-align:right">Rate</th><th style="text-align:right">Amount</th></tr></thead>
  <tbody>{items_html}</tbody>
</table>
<table style="max-width:360px;margin-left:auto">
  <tr><td>Subtotal</td><td style="text-align:right">${inv.subtotal:,.2f}</td></tr>
  <tr><td>Discount</td><td style="text-align:right">-${getattr(inv,'discount_total',0):,.2f}</td></tr>
  <tr><td>Tax</td><td style="text-align:right">${inv.tax_total:,.2f}</td></tr>
  <tr><td>Adjustment</td><td style="text-align:right">${inv.adjustment:,.2f}</td></tr>
  <tr class="totals-row"><td>Total</td><td style="text-align:right">${inv.total:,.2f}</td></tr>
  <tr><td>Amount Paid</td><td style="text-align:right">${inv.amount_paid:,.2f}</td></tr>
  <tr class="totals-row"><td>Amount Due</td><td style="text-align:right">${amount_due:,.2f}</td></tr>
</table>
{f'<div class="due-box"><strong>Amount Due: ${amount_due:,.2f} {inv.currency}</strong></div>' if amount_due > 0 else '<p style="color:#10b981;font-weight:600">✓ This invoice is fully paid.</p>'}
{f'<h3>Payment History</h3><table><thead><tr><th>Date</th><th>Amount</th><th>Reference</th></tr></thead><tbody>{payments_html}</tbody></table>' if inv.payments else ''}
{f'<h3>Note</h3><p>{inv.client_note}</p>' if inv.client_note else ''}
{f'<h3>Terms</h3><p>{inv.terms}</p>' if inv.terms else ''}
</body></html>"""
    return HTMLResponse(html)


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
    sale_agent_id: Optional[int] = None
    status: str = "draft"
    prefix: str = "PROP"
    date: Optional[str] = None
    open_till: Optional[str] = None
    currency: str = "USD"
    discount_type: str = "before_tax"
    discount_value: float = 0.0
    adjustment: float = 0.0
    content: Optional[str] = None
    allow_comments: bool = False
    client_note: Optional[str] = None
    terms: Optional[str] = None
    admin_note: Optional[str] = None
    tags: Optional[list] = None
    assigned_to: Optional[int] = None
    billing_address: Optional[dict] = None
    shipping_address: Optional[dict] = None
    proposal_to: Optional[dict] = None
    items: Optional[list] = None


# ── Estimates ────────────────────────────────────────────────────────────────

def _estimate_dict(e: CRMEstimate, include_items: bool = False) -> dict:
    d: dict = {
        "id": e.id, "number": e.number, "prefix": e.prefix,
        "formatted_number": e.formatted_number,
        "customer_id": e.customer_id,
        "customer_name": e.customer.company_name if e.customer else None,
        "lead_id": e.lead_id,
        "sale_agent_id": e.sale_agent_id,
        "project_id": e.project_id,
        "billing_address": e.billing_address or {},
        "shipping_address": e.shipping_address or {},
        "date": e.date.isoformat() if e.date else None,
        "expiry_date": e.expiry_date.isoformat() if e.expiry_date else None,
        "currency": e.currency,
        "discount_type": e.discount_type, "discount_value": e.discount_value,
        "subtotal": e.subtotal, "tax_total": e.tax_total,
        "discount_total": e.discount_total, "adjustment": e.adjustment,
        "total": e.total,
        "status": e.status, "pipeline_order": e.pipeline_order,
        "client_note": e.client_note, "terms": e.terms,
        "hash": e.hash,
        "acceptance_first_name": e.acceptance_first_name,
        "acceptance_last_name": e.acceptance_last_name,
        "acceptance_email": e.acceptance_email,
        "acceptance_date": e.acceptance_date.isoformat() if e.acceptance_date else None,
        "converted_to_invoice_id": e.converted_to_invoice_id,
        "converted_at": e.converted_at.isoformat() if e.converted_at else None,
        "sent_at": e.sent_at.isoformat() if e.sent_at else None,
        "created_at": e.created_at.isoformat(),
    }
    if include_items:
        d["items"] = [_line_item_dict(li) for li in (e.items or [])]
        d["admin_note"] = e.admin_note
    return d


def _line_item_dict(li: CRMLineItem) -> dict:
    return {
        "id": li.id, "description": li.description, "long_description": li.long_description,
        "qty": li.qty, "rate": li.rate, "discount": li.discount,
        "tax_ids": li.tax_ids or [], "amount": li.amount, "sort_order": li.sort_order,
    }


def _next_estimate_number(existing_numbers: list[int]) -> int:
    return max(existing_numbers, default=0) + 1


class EstimateReq(BaseModel):
    customer_id: Optional[int] = None
    lead_id: Optional[int] = None
    sale_agent_id: Optional[int] = None
    project_id: Optional[int] = None
    billing_address: Optional[dict] = None
    shipping_address: Optional[dict] = None
    date: Optional[str] = None
    expiry_date: Optional[str] = None
    currency: str = "USD"
    discount_type: str = "before_tax"
    discount_value: float = 0.0
    subtotal: float = 0.0
    tax_total: float = 0.0
    discount_total: float = 0.0
    adjustment: float = 0.0
    total: float = 0.0
    status: str = "draft"
    client_note: Optional[str] = None
    terms: Optional[str] = None
    admin_note: Optional[str] = None
    items: Optional[list] = None


@router.get("/api/estimates")
async def list_estimates(
    status: Optional[str] = None,
    customer_id: Optional[int] = None,
    q: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    if not _perm(staff, "estimates", "view"):
        raise HTTPException(403)
    query = (
        select(CRMEstimate)
        .options(selectinload(CRMEstimate.customer))
        .order_by(desc(CRMEstimate.created_at))
    )
    if status and status != "all":
        query = query.where(CRMEstimate.status == status)
    if customer_id:
        query = query.where(CRMEstimate.customer_id == customer_id)
    if not _perm(staff, "estimates", "view_all"):
        query = query.where(CRMEstimate.sale_agent_id == staff.id)
    r = await db.execute(query)
    estimates = r.scalars().all()
    if q:
        ql = q.lower()
        estimates = [e for e in estimates if ql in (e.formatted_number or "").lower()
                     or ql in (e.customer.company_name if e.customer else "").lower()]
    return [_estimate_dict(e) for e in estimates]


@router.post("/api/estimates")
async def create_estimate(req: EstimateReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimates", "create"):
        raise HTTPException(403)
    # Generate number
    r = await db.execute(select(func.max(CRMEstimate.number)))
    max_num = r.scalar() or 0
    num = max_num + 1
    formatted = f"EST-{num:06d}"
    data = req.model_dump()
    items_data = data.pop("items", None) or []
    date_str = data.pop("date", None)
    expiry_str = data.pop("expiry_date", None)
    e = CRMEstimate(
        **data,
        number=num,
        formatted_number=formatted,
        date=datetime.fromisoformat(date_str) if date_str else _utcnow(),
        expiry_date=datetime.fromisoformat(expiry_str) if expiry_str else _utcnow() + timedelta(days=7),
        sale_agent_id=data.get("sale_agent_id") or staff.id,
    )
    db.add(e)
    await db.flush()
    for i, it in enumerate(items_data):
        db.add(CRMLineItem(
            estimate_id=e.id,
            description=it.get("description", ""),
            long_description=it.get("long_description"),
            qty=float(it.get("qty", 1)),
            rate=float(it.get("rate", 0)),
            discount=float(it.get("discount", 0)),
            tax_ids=it.get("tax_ids", []),
            amount=float(it.get("amount", 0)),
            sort_order=i,
        ))
    await _log(db, staff, "estimates", "created", e.id, e.formatted_number)
    await db.commit()
    return {"id": e.id, "formatted_number": e.formatted_number}


@router.get("/api/estimates/{eid}")
async def get_estimate(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimates", "view"):
        raise HTTPException(403)
    r = await db.execute(
        select(CRMEstimate).where(CRMEstimate.id == eid)
        .options(selectinload(CRMEstimate.customer), selectinload(CRMEstimate.items))
    )
    e = r.scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    return _estimate_dict(e, include_items=True)


@router.put("/api/estimates/{eid}")
async def update_estimate(eid: int, req: EstimateReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimates", "edit"):
        raise HTTPException(403)
    r = await db.execute(select(CRMEstimate).where(CRMEstimate.id == eid))
    e = r.scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    data = req.model_dump(exclude_unset=True)
    items_data = data.pop("items", None)
    date_str = data.pop("date", None)
    expiry_str = data.pop("expiry_date", None)
    for k, v in data.items():
        setattr(e, k, v)
    if date_str:
        e.date = datetime.fromisoformat(date_str)
    if expiry_str:
        e.expiry_date = datetime.fromisoformat(expiry_str)
    e.updated_at = _utcnow()
    if items_data is not None:
        await db.execute(delete(CRMLineItem).where(CRMLineItem.estimate_id == eid))
        for i, it in enumerate(items_data):
            db.add(CRMLineItem(
                estimate_id=eid,
                description=it.get("description", ""),
                long_description=it.get("long_description"),
                qty=float(it.get("qty", 1)),
                rate=float(it.get("rate", 0)),
                discount=float(it.get("discount", 0)),
                tax_ids=it.get("tax_ids", []),
                amount=float(it.get("amount", 0)),
                sort_order=i,
            ))
    await _log(db, staff, "estimates", "updated", e.id, e.formatted_number)
    await db.commit()
    return {"ok": True}


@router.delete("/api/estimates/{eid}")
async def delete_estimate(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimates", "delete"):
        raise HTTPException(403)
    r = await db.execute(select(CRMEstimate).where(CRMEstimate.id == eid))
    e = r.scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    await _log(db, staff, "estimates", "deleted", e.id, e.formatted_number)
    await db.execute(delete(CRMEstimate).where(CRMEstimate.id == eid))
    await db.commit()
    return {"ok": True}


@router.post("/api/estimates/{eid}/send")
async def send_estimate(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimates", "send"):
        raise HTTPException(403)
    r = await db.execute(
        select(CRMEstimate).where(CRMEstimate.id == eid)
        .options(selectinload(CRMEstimate.customer), selectinload(CRMEstimate.items))
    )
    e = r.scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    from config import settings as _s
    base = _s.BASE_URL.rstrip("/")
    public_url = f"{base}/estimate/{e.id}/{e.hash}"
    # Get recipient email
    to_email = None
    if e.customer_id:
        contact_r = await db.execute(
            select(CRMContact).where(CRMContact.customer_id == e.customer_id, CRMContact.is_primary == True).limit(1)
        )
        ct = contact_r.scalar_one_or_none()
        if ct:
            to_email = ct.email
    if not to_email and e.billing_address:
        to_email = (e.billing_address or {}).get("email")
    if to_email:
        html = f"""
        <p>Please find your estimate <strong>{e.formatted_number}</strong> from Uplinx CRM.</p>
        <p><a href="{public_url}" style="background:#6366f1;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;display:inline-block">View Estimate</a></p>
        <p>Total: <strong>{e.currency} {e.total:,.2f}</strong></p>
        {f'<p>{e.client_note}</p>' if e.client_note else ''}
        """
        await _send_email(to_email, f"Estimate {e.formatted_number}", html)
    e.status = "sent"
    e.sent_at = _utcnow()
    await db.commit()
    return {"ok": True, "public_url": public_url}


@router.post("/api/estimates/{eid}/mark-sent")
async def mark_estimate_sent(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimates", "mark_sent"):
        raise HTTPException(403)
    r = await db.execute(select(CRMEstimate).where(CRMEstimate.id == eid))
    e = r.scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    e.status = "sent"
    e.sent_at = e.sent_at or _utcnow()
    await db.commit()
    return {"ok": True}


@router.post("/api/estimates/{eid}/convert-to-invoice")
async def convert_estimate_to_invoice(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimates", "convert_to_invoice"):
        raise HTTPException(403)
    r = await db.execute(
        select(CRMEstimate).where(CRMEstimate.id == eid)
        .options(selectinload(CRMEstimate.items))
    )
    e = r.scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    if e.converted_to_invoice_id:
        raise HTTPException(400, detail="Already converted to invoice")
    # Generate invoice number
    inv_r = await db.execute(select(func.count()).select_from(CRMInvoice))
    inv_count = (inv_r.scalar() or 0) + 1
    inv = CRMInvoice(
        invoice_number=f"INV-{inv_count:06d}",
        customer_id=e.customer_id,
        project_id=e.project_id,
        currency=e.currency,
        date=_utcnow(),
        due_date=_utcnow() + timedelta(days=30),
        status="not_sent",
        discount_type=e.discount_type,
        discount_value=e.discount_value,
        adjustment=e.adjustment,
        subtotal=e.subtotal,
        tax_total=e.tax_total,
        total=e.total,
        client_note=e.client_note,
        terms=e.terms,
        admin_note=e.admin_note,
        assigned_to=e.sale_agent_id,
    )
    db.add(inv)
    await db.flush()
    for li in (e.items or []):
        db.add(CRMLineItem(
            invoice_id=inv.id,
            description=li.description,
            long_description=li.long_description,
            qty=li.qty, rate=li.rate, discount=li.discount,
            tax_ids=li.tax_ids, amount=li.amount, sort_order=li.sort_order,
        ))
    e.converted_to_invoice_id = inv.id
    e.converted_at = _utcnow()
    e.status = "accepted"
    await _log(db, staff, "estimates", "converted_to_invoice", e.id, e.formatted_number)
    await db.commit()
    return {"ok": True, "invoice_id": inv.id}


# Public estimate view (no auth)
@router.get("/estimate/{eid}/{hash_val}", response_class=HTMLResponse)
async def public_estimate_view(eid: int, hash_val: str, db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(CRMEstimate).where(CRMEstimate.id == eid)
        .options(selectinload(CRMEstimate.customer), selectinload(CRMEstimate.items))
    )
    e = r.scalar_one_or_none()
    if not e or e.hash != hash_val:
        return HTMLResponse("<h2 style='font-family:sans-serif;text-align:center;margin-top:10vh'>Estimate not found or link expired.</h2>", status_code=404)
    # Update status to open if sent
    if e.status == "sent":
        e.status = "open"
        await db.commit()
    items_html = "".join(f"""
        <tr><td style='padding:10px 8px;border-bottom:1px solid #f3f4f6'>{li.description}{'<br><small style=color:#9ca3af>' + (li.long_description or '') + '</small>' if li.long_description else ''}</td>
        <td style='padding:10px 8px;border-bottom:1px solid #f3f4f6;text-align:right'>{li.qty}</td>
        <td style='padding:10px 8px;border-bottom:1px solid #f3f4f6;text-align:right'>{e.currency} {li.rate:,.2f}</td>
        <td style='padding:10px 8px;border-bottom:1px solid #f3f4f6;text-align:right'>{li.discount}%</td>
        <td style='padding:10px 8px;border-bottom:1px solid #f3f4f6;text-align:right;font-weight:600'>{e.currency} {li.amount:,.2f}</td></tr>
    """ for li in (e.items or []))
    can_act = e.status in ("open", "sent", "draft") and not e.acceptance_date
    acceptance_block = ""
    if e.acceptance_date:
        acceptance_block = f"<div style='background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:20px;margin-top:24px;text-align:center'><span style='color:#16a34a;font-weight:600'>✓ Accepted</span> by {e.acceptance_first_name or ''} {e.acceptance_last_name or ''} on {e.acceptance_date.strftime('%b %d, %Y')}</div>"
    declined_block = ""
    if e.status == "declined":
        declined_block = "<div style='background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:20px;margin-top:24px;text-align:center'><span style='color:#dc2626;font-weight:600'>✗ Declined</span></div>"
    action_buttons = ""
    if can_act:
        action_buttons = f"""
        <div style='display:flex;gap:12px;justify-content:center;margin-top:32px'>
          <button onclick="document.getElementById('esign-modal').style.display='flex'"
            style='background:#6366f1;color:#fff;border:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer'>
            ✓ Accept Estimate
          </button>
          <button onclick="declineEstimate()"
            style='background:#fff;color:#dc2626;border:2px solid #dc2626;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer'>
            ✗ Decline
          </button>
        </div>
        <div id="esign-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:1000;align-items:center;justify-content:center">
          <div style="background:#fff;border-radius:12px;padding:32px;max-width:480px;width:90%;max-height:90vh;overflow-y:auto">
            <h3 style="margin:0 0 20px;font-size:18px">Accept Estimate {e.formatted_number}</h3>
            <p style="color:#6b7280;font-size:13px;margin-bottom:20px">By signing below, you agree to the terms of this estimate.</p>
            <div style="margin-bottom:14px"><label style="font-size:13px;font-weight:500;display:block;margin-bottom:4px">First Name *</label>
              <input id="sig-fn" style="width:100%;box-sizing:border-box;border:1.5px solid #e5e7eb;border-radius:6px;padding:9px 12px;font-size:14px"></div>
            <div style="margin-bottom:14px"><label style="font-size:13px;font-weight:500;display:block;margin-bottom:4px">Last Name *</label>
              <input id="sig-ln" style="width:100%;box-sizing:border-box;border:1.5px solid #e5e7eb;border-radius:6px;padding:9px 12px;font-size:14px"></div>
            <div style="margin-bottom:14px"><label style="font-size:13px;font-weight:500;display:block;margin-bottom:4px">Email *</label>
              <input id="sig-em" type="email" style="width:100%;box-sizing:border-box;border:1.5px solid #e5e7eb;border-radius:6px;padding:9px 12px;font-size:14px"></div>
            <div style="margin-bottom:20px"><label style="font-size:13px;font-weight:500;display:block;margin-bottom:8px">Signature *</label>
              <canvas id="sig-pad" width="416" height="120" style="border:1.5px solid #e5e7eb;border-radius:6px;background:#fafafa;touch-action:none;cursor:crosshair;max-width:100%"></canvas>
              <button onclick="clearSig()" style="margin-top:6px;background:none;border:none;color:#6366f1;font-size:12px;cursor:pointer">Clear</button></div>
            <p style="font-size:11px;color:#9ca3af;margin-bottom:20px">By clicking Accept, you confirm your acceptance of this estimate and all terms contained herein.</p>
            <div style="display:flex;gap:10px">
              <button onclick="submitAccept({e.id},'{e.hash}')" style="flex:1;background:#6366f1;color:#fff;border:none;padding:12px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer">Accept</button>
              <button onclick="document.getElementById('esign-modal').style.display='none'" style="flex:1;background:#f3f4f6;color:#374151;border:none;padding:12px;border-radius:6px;font-size:14px;cursor:pointer">Cancel</button>
            </div>
          </div>
        </div>"""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Estimate {e.formatted_number}</title>
<style>*{{box-sizing:border-box}}body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;color:#111827}}
.card{{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:40px;max-width:800px;margin:40px auto}}</style>
</head>
<body>
<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px;flex-wrap:wrap;gap:16px">
    <div><h1 style="margin:0;font-size:26px;font-weight:700;color:#6366f1">ESTIMATE</h1>
    <div style="font-size:20px;font-weight:600;margin-top:4px">{e.formatted_number}</div></div>
    <div style="text-align:right">
      <div style="font-size:13px;color:#6b7280">Date: <strong>{e.date.strftime('%b %d, %Y') if e.date else 'N/A'}</strong></div>
      <div style="font-size:13px;color:#6b7280">Expires: <strong>{e.expiry_date.strftime('%b %d, %Y') if e.expiry_date else 'N/A'}</strong></div>
      <div style="margin-top:8px"><span style="background:{'#f0fdf4' if e.status=='accepted' else '#fef3c7' if e.status in ('sent','open') else '#f3f4f6'};color:{'#16a34a' if e.status=='accepted' else '#d97706' if e.status in ('sent','open') else '#6b7280'};padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;text-transform:capitalize">{e.status}</span></div>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:32px">
    <div><div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;margin-bottom:6px">Bill To</div>
    <div style="font-size:14px;line-height:1.6">{(e.billing_address or {}).get('name', e.customer.company_name if e.customer else '')}<br>
    {(e.billing_address or {}).get('address', '')}<br>
    {(e.billing_address or {}).get('city', '')} {(e.billing_address or {}).get('state', '')} {(e.billing_address or {}).get('zip', '')}<br>
    {(e.billing_address or {}).get('country', '')}</div></div>
  </div>
  <table style="width:100%;border-collapse:collapse;margin-bottom:24px">
    <thead><tr style="background:#f9fafb">
      <th style="padding:10px 8px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;border-bottom:2px solid #e5e7eb">DESCRIPTION</th>
      <th style="padding:10px 8px;text-align:right;font-size:12px;font-weight:600;color:#6b7280;border-bottom:2px solid #e5e7eb">QTY</th>
      <th style="padding:10px 8px;text-align:right;font-size:12px;font-weight:600;color:#6b7280;border-bottom:2px solid #e5e7eb">RATE</th>
      <th style="padding:10px 8px;text-align:right;font-size:12px;font-weight:600;color:#6b7280;border-bottom:2px solid #e5e7eb">DISC%</th>
      <th style="padding:10px 8px;text-align:right;font-size:12px;font-weight:600;color:#6b7280;border-bottom:2px solid #e5e7eb">AMOUNT</th>
    </tr></thead>
    <tbody>{items_html}</tbody>
  </table>
  <div style="display:flex;justify-content:flex-end;margin-bottom:24px">
    <div style="min-width:260px">
      <div style="display:flex;justify-content:space-between;padding:6px 0;font-size:14px"><span style="color:#6b7280">Subtotal</span><span>{e.currency} {e.subtotal:,.2f}</span></div>
      {f'<div style="display:flex;justify-content:space-between;padding:6px 0;font-size:14px"><span style=color:#6b7280>Tax</span><span>{e.currency} {e.tax_total:,.2f}</span></div>' if e.tax_total else ''}
      {f'<div style="display:flex;justify-content:space-between;padding:6px 0;font-size:14px"><span style=color:#6b7280>Discount</span><span>-{e.currency} {e.discount_total:,.2f}</span></div>' if e.discount_total else ''}
      {f'<div style="display:flex;justify-content:space-between;padding:6px 0;font-size:14px"><span style=color:#6b7280>Adjustment</span><span>{e.currency} {e.adjustment:,.2f}</span></div>' if e.adjustment else ''}
      <div style="display:flex;justify-content:space-between;padding:10px 0;font-size:18px;font-weight:700;border-top:2px solid #e5e7eb;margin-top:4px"><span>Total</span><span style="color:#6366f1">{e.currency} {e.total:,.2f}</span></div>
    </div>
  </div>
  {f'<div style="margin-bottom:24px"><div style="font-size:12px;font-weight:700;text-transform:uppercase;color:#9ca3af;margin-bottom:8px">Note</div><div style="font-size:14px;color:#374151;line-height:1.6">{e.client_note}</div></div>' if e.client_note else ''}
  {f'<div style="margin-bottom:24px;padding:20px;background:#f9fafb;border-radius:8px"><div style="font-size:12px;font-weight:700;text-transform:uppercase;color:#9ca3af;margin-bottom:8px">Terms & Conditions</div><div style="font-size:13px;color:#374151;line-height:1.6;white-space:pre-wrap">{e.terms}</div></div>' if e.terms else ''}
  {acceptance_block}
  {declined_block}
  {action_buttons}
</div>
<script>
// Signature pad
let _drawing=false,_lx=0,_ly=0;
const pad=document.getElementById('sig-pad');
const ctx=pad?.getContext('2d');
function getPos(e,el){{const r=el.getBoundingClientRect();const t=e.touches?e.touches[0]:e;return{{x:(t.clientX-r.left)*(el.width/r.width),y:(t.clientY-r.top)*(el.height/r.height)}};}}
if(pad){{
  pad.addEventListener('mousedown',e=>{{_drawing=true;const p=getPos(e,pad);_lx=p.x;_ly=p.y;ctx.beginPath();}});
  pad.addEventListener('mousemove',e=>{{if(!_drawing)return;const p=getPos(e,pad);ctx.lineWidth=2;ctx.lineCap='round';ctx.strokeStyle='#111';ctx.beginPath();ctx.moveTo(_lx,_ly);ctx.lineTo(p.x,p.y);ctx.stroke();_lx=p.x;_ly=p.y;}});
  pad.addEventListener('mouseup',()=>_drawing=false);
  pad.addEventListener('mouseleave',()=>_drawing=false);
  pad.addEventListener('touchstart',e=>{{e.preventDefault();_drawing=true;const p=getPos(e,pad);_lx=p.x;_ly=p.y;}},{{passive:false}});
  pad.addEventListener('touchmove',e=>{{e.preventDefault();if(!_drawing)return;const p=getPos(e,pad);ctx.lineWidth=2;ctx.lineCap='round';ctx.strokeStyle='#111';ctx.beginPath();ctx.moveTo(_lx,_ly);ctx.lineTo(p.x,p.y);ctx.stroke();_lx=p.x;_ly=p.y;}},{{passive:false}});
  pad.addEventListener('touchend',()=>_drawing=false);
}}
function clearSig(){{ctx?.clearRect(0,0,pad.width,pad.height);}}
function isBlank(){{const d=ctx?.getImageData(0,0,pad.width,pad.height).data;return!d||!d.some(v=>v!==0);}}
async function submitAccept(id,hash){{
  const fn=document.getElementById('sig-fn').value.trim();
  const ln=document.getElementById('sig-ln').value.trim();
  const em=document.getElementById('sig-em').value.trim();
  if(!fn||!ln||!em){{alert('Please fill in all fields.');return;}}
  if(isBlank()){{alert('Please provide your signature.');return;}}
  const sig=pad.toDataURL('image/png');
  const r=await fetch(`/admin/api/estimates/${{id}}/accept`,{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{first_name:fn,last_name:ln,email:em,signature_image:sig,hash:hash}})}});
  const d=await r.json();
  if(r.ok){{document.getElementById('esign-modal').style.display='none';location.reload();}}
  else{{alert(d.detail||'Error accepting estimate');}}
}}
async function declineEstimate(){{
  if(!confirm('Are you sure you want to decline this estimate?'))return;
  const r=await fetch(`/admin/api/estimates/{e.id}/decline`,{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{hash:'{e.hash}'}})}});
  if(r.ok)location.reload();
}}
</script>
</body></html>"""
    return HTMLResponse(html)


class AcceptEstimateReq(BaseModel):
    first_name: str
    last_name: str
    email: str
    signature_image: Optional[str] = None
    hash: str


@router.post("/api/estimates/{eid}/accept")
async def accept_estimate(eid: int, req: AcceptEstimateReq, request: Request, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEstimate).where(CRMEstimate.id == eid))
    e = r.scalar_one_or_none()
    if not e or e.hash != req.hash:
        raise HTTPException(404)
    if e.status == "declined":
        raise HTTPException(400, detail="Estimate already declined")
    e.status = "accepted"
    e.acceptance_first_name = req.first_name
    e.acceptance_last_name = req.last_name
    e.acceptance_email = req.email
    e.acceptance_date = _utcnow()
    e.acceptance_ip = _client_ip(request)
    e.signature_image = req.signature_image
    await db.commit()
    return {"ok": True}


class DeclineEstimateReq(BaseModel):
    hash: str


@router.post("/api/estimates/{eid}/decline")
async def decline_estimate(eid: int, req: DeclineEstimateReq, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEstimate).where(CRMEstimate.id == eid))
    e = r.scalar_one_or_none()
    if not e or e.hash != req.hash:
        raise HTTPException(404)
    e.status = "declined"
    await db.commit()
    return {"ok": True}


# ── Estimate Request Statuses ─────────────────────────────────────────────────

@router.get("/api/estimate-request-statuses")
async def list_er_statuses(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEstimateRequestStatus).order_by(CRMEstimateRequestStatus.statusorder))
    return [{"id": s.id, "name": s.name, "color": s.color, "statusorder": s.statusorder, "flag": s.flag}
            for s in r.scalars().all()]


class ERStatusReq(BaseModel):
    name: str
    color: str = "#6366f1"
    statusorder: int = 0
    flag: str = ""


@router.post("/api/estimate-request-statuses")
async def create_er_status(req: ERStatusReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "manage_statuses"):
        raise HTTPException(403)
    s = CRMEstimateRequestStatus(**req.model_dump())
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return {"id": s.id}


@router.put("/api/estimate-request-statuses/{sid}")
async def update_er_status(sid: int, req: ERStatusReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "manage_statuses"):
        raise HTTPException(403)
    r = await db.execute(select(CRMEstimateRequestStatus).where(CRMEstimateRequestStatus.id == sid))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    for k, v in req.model_dump().items():
        setattr(s, k, v)
    await db.commit()
    return {"ok": True}


@router.delete("/api/estimate-request-statuses/{sid}")
async def delete_er_status(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "manage_statuses"):
        raise HTTPException(403)
    await db.execute(delete(CRMEstimateRequestStatus).where(CRMEstimateRequestStatus.id == sid))
    await db.commit()
    return {"ok": True}


# ── Estimate Request Forms ────────────────────────────────────────────────────

def _er_form_dict(f: CRMEstimateRequestForm, submission_count: int = 0) -> dict:
    return {
        "id": f.id, "form_key": f.form_key, "type": f.type, "name": f.name,
        "language": f.language, "form_data": f.form_data or [],
        "submit_btn_label": f.submit_btn_label,
        "submit_btn_bg_color": f.submit_btn_bg_color,
        "submit_btn_text_color": f.submit_btn_text_color,
        "success_message": f.success_message, "redirect_url": f.redirect_url,
        "recaptcha_enabled": f.recaptcha_enabled, "honeypot_enabled": f.honeypot_enabled,
        "notify_type": f.notify_type, "notify_user_ids": f.notify_user_ids or [],
        "default_assignee_id": f.default_assignee_id,
        "is_active": f.is_active, "created_at": f.created_at.isoformat(),
        "submission_count": submission_count,
    }


class ERFormReq(BaseModel):
    name: str
    type: Optional[str] = None
    language: str = "en"
    form_data: Optional[list] = None
    submit_btn_label: str = "Submit Request"
    submit_btn_bg_color: str = "#6366f1"
    submit_btn_text_color: str = "#ffffff"
    success_message: Optional[str] = "Thank you! We'll be in touch shortly."
    redirect_url: Optional[str] = None
    recaptcha_enabled: bool = False
    honeypot_enabled: bool = True
    notify_type: str = "assigned"
    notify_user_ids: Optional[list] = None
    default_assignee_id: Optional[int] = None
    is_active: bool = True


@router.get("/api/estimate-request-forms")
async def list_er_forms(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "manage_forms"):
        raise HTTPException(403)
    r = await db.execute(select(CRMEstimateRequestForm).order_by(desc(CRMEstimateRequestForm.created_at)))
    forms = r.scalars().all()
    result = []
    for f in forms:
        cnt_r = await db.execute(select(func.count()).select_from(CRMEstimateRequest).where(CRMEstimateRequest.form_id == f.id))
        cnt = cnt_r.scalar() or 0
        result.append(_er_form_dict(f, cnt))
    return result


@router.post("/api/estimate-request-forms")
async def create_er_form(req: ERFormReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "manage_forms"):
        raise HTTPException(403)
    f = CRMEstimateRequestForm(**req.model_dump())
    db.add(f)
    await db.commit()
    await db.refresh(f)
    return {"id": f.id, "form_key": f.form_key}


@router.get("/api/estimate-request-forms/{fid}")
async def get_er_form(fid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "manage_forms"):
        raise HTTPException(403)
    r = await db.execute(select(CRMEstimateRequestForm).where(CRMEstimateRequestForm.id == fid))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404)
    return _er_form_dict(f)


@router.put("/api/estimate-request-forms/{fid}")
async def update_er_form(fid: int, req: ERFormReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "manage_forms"):
        raise HTTPException(403)
    r = await db.execute(select(CRMEstimateRequestForm).where(CRMEstimateRequestForm.id == fid))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404)
    for k, v in req.model_dump(exclude_unset=True).items():
        setattr(f, k, v)
    await db.commit()
    return {"ok": True}


@router.delete("/api/estimate-request-forms/{fid}")
async def delete_er_form(fid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "manage_forms"):
        raise HTTPException(403)
    await db.execute(delete(CRMEstimateRequestForm).where(CRMEstimateRequestForm.id == fid))
    await db.commit()
    return {"ok": True}


# Public form render + submit (no auth)
@router.get("/form/{form_key}", response_class=HTMLResponse)
async def public_er_form(form_key: str, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEstimateRequestForm).where(
        CRMEstimateRequestForm.form_key == form_key,
        CRMEstimateRequestForm.is_active == True,
    ))
    f = r.scalar_one_or_none()
    if not f:
        return HTMLResponse("<h2 style='font-family:sans-serif;text-align:center;margin-top:10vh'>Form not found or inactive.</h2>", status_code=404)

    fields_html = ""
    for field in (f.form_data or []):
        ftype = field.get("type", "text")
        fname = field.get("name", "")
        flabel = field.get("label", fname)
        freq = field.get("required", False)
        opts = field.get("options", [])
        req_attr = "required" if freq else ""
        star = "<span style='color:#ef4444'>*</span>" if freq else ""
        label_html = f"<label style='font-size:13px;font-weight:500;display:block;margin-bottom:5px'>{flabel} {star}</label>"
        inp_style = "width:100%;box-sizing:border-box;border:1.5px solid #e5e7eb;border-radius:6px;padding:9px 12px;font-size:14px;font-family:inherit"

        if ftype == "heading":
            fields_html += f"<h3 style='font-size:16px;font-weight:700;margin:20px 0 8px'>{flabel}</h3>"
        elif ftype == "paragraph":
            fields_html += f"<p style='font-size:13px;color:#6b7280;margin:0 0 12px'>{flabel}</p>"
        elif ftype == "textarea":
            fields_html += f"<div style='margin-bottom:14px'>{label_html}<textarea name='{fname}' rows='4' {req_attr} style='{inp_style};resize:vertical'></textarea></div>"
        elif ftype == "select":
            opts_html = "".join(f"<option value='{o}'>{o}</option>" for o in opts)
            fields_html += f"<div style='margin-bottom:14px'>{label_html}<select name='{fname}' {req_attr} style='{inp_style};background:#fff'><option value=''>— Select —</option>{opts_html}</select></div>"
        elif ftype in ("checkbox", "radio"):
            opts_html = "".join(f"<label style='display:flex;align-items:center;gap:6px;font-size:14px;margin-bottom:6px'><input type='{ftype}' name='{fname}' value='{o}'> {o}</label>" for o in opts)
            fields_html += f"<div style='margin-bottom:14px'>{label_html}{opts_html}</div>"
        elif ftype == "date":
            fields_html += f"<div style='margin-bottom:14px'>{label_html}<input type='date' name='{fname}' {req_attr} style='{inp_style}'></div>"
        else:
            itype = "email" if ftype == "email" else "tel" if ftype == "phone" else "text"
            fields_html += f"<div style='margin-bottom:14px'>{label_html}<input type='{itype}' name='{fname}' {req_attr} style='{inp_style}'></div>"

    honeypot = '<input name="_hp_website" style="display:none" tabindex="-1" autocomplete="off">' if f.honeypot_enabled else ''

    html = f"""<!DOCTYPE html>
<html lang="{f.language}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{f.name}</title>
<style>*{{box-sizing:border-box}}body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;color:#111827}}
.card{{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:36px;max-width:620px;margin:40px auto}}</style>
</head>
<body>
<div class="card">
  <h2 style="margin:0 0 6px;font-size:22px;font-weight:700">{f.name}</h2>
  <p style="color:#6b7280;font-size:13px;margin:0 0 24px">Fill in the form below and we'll get back to you.</p>
  <div id="success-msg" style="display:none;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:20px;text-align:center;font-weight:600;color:#16a34a">{f.success_message or 'Thank you!'}</div>
  <form id="er-form">
    {honeypot}
    {fields_html}
    <button type="submit" style="background:{f.submit_btn_bg_color};color:{f.submit_btn_text_color};border:none;padding:12px 28px;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;width:100%;margin-top:8px">
      {f.submit_btn_label}
    </button>
    <div id="form-err" style="display:none;color:#ef4444;font-size:13px;margin-top:10px;text-align:center"></div>
  </form>
</div>
<script>
document.getElementById('er-form').addEventListener('submit', async function(e) {{
  e.preventDefault();
  const hp = this.querySelector('[name=_hp_website]');
  if (hp && hp.value) return; // honeypot triggered
  const data = {{}};
  new FormData(this).forEach((v,k) => {{ if(k!=='_hp_website') data[k]=v; }});
  const btn = this.querySelector('button[type=submit]');
  btn.disabled = true; btn.textContent = 'Sending…';
  try {{
    const r = await fetch('/admin/api/form/{form_key}/submit', {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(data)}});
    const d = await r.json();
    if (r.ok) {{
      this.style.display = 'none';
      document.getElementById('success-msg').style.display = 'block';
      {f"window.location='{f.redirect_url}';" if f.redirect_url else ''}
    }} else {{
      document.getElementById('form-err').style.display = 'block';
      document.getElementById('form-err').textContent = d.detail || 'Submission failed. Please try again.';
      btn.disabled = false; btn.textContent = '{f.submit_btn_label}';
    }}
  }} catch(err) {{
    document.getElementById('form-err').style.display = 'block';
    document.getElementById('form-err').textContent = 'Network error. Please try again.';
    btn.disabled = false; btn.textContent = '{f.submit_btn_label}';
  }}
}});
</script>
</body></html>"""
    return HTMLResponse(html)


@router.post("/api/form/{form_key}/submit")
async def submit_er_form(form_key: str, request: Request, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEstimateRequestForm).where(
        CRMEstimateRequestForm.form_key == form_key,
        CRMEstimateRequestForm.is_active == True,
    ))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404, detail="Form not found")
    body = await request.json()
    # Get default "processing" status
    stat_r = await db.execute(select(CRMEstimateRequestStatus).where(CRMEstimateRequestStatus.flag == "processing").limit(1))
    default_status = stat_r.scalar_one_or_none()
    email = body.get("email") or body.get("Email") or body.get("EMAIL")
    req_obj = CRMEstimateRequest(
        form_id=f.id,
        email=email,
        submission=body,
        status_id=default_status.id if default_status else None,
        assigned_user_id=f.default_assignee_id,
    )
    db.add(req_obj)
    await db.commit()
    await db.refresh(req_obj)
    # Send notification email if configured
    if f.notify_type == "assigned" and f.default_assignee_id:
        agent_r = await db.execute(select(StaffMember).where(StaffMember.id == f.default_assignee_id))
        agent = agent_r.scalar_one_or_none()
        if agent and agent.email:
            from config import settings as _s
            await _send_email(agent.email, f"New Estimate Request — {f.name}",
                              f"<p>A new estimate request was submitted via <strong>{f.name}</strong>.</p>"
                              f"<p>From: {email or 'unknown'}</p>"
                              f"<p><a href='{_s.BASE_URL}/admin#estimate-requests'>View in CRM</a></p>")
    return {"ok": True, "id": req_obj.id}


# ── Estimate Requests (Submissions) ──────────────────────────────────────────

def _er_dict(req: CRMEstimateRequest) -> dict:
    return {
        "id": req.id,
        "form_id": req.form_id,
        "form_name": req.form.name if req.form else None,
        "email": req.email,
        "submission": req.submission or {},
        "status_id": req.status_id,
        "status_name": req.status.name if req.status else None,
        "status_color": req.status.color if req.status else "#6b7280",
        "status_flag": req.status.flag if req.status else "",
        "assigned_user_id": req.assigned_user_id,
        "assigned_name": req.assignee.full_name if req.assignee else None,
        "last_status_change_at": req.last_status_change_at.isoformat() if req.last_status_change_at else None,
        "date_estimated": req.date_estimated.isoformat() if req.date_estimated else None,
        "converted_estimate_id": req.converted_estimate_id,
        "notes": req.notes,
        "created_at": req.created_at.isoformat(),
    }


@router.get("/api/estimate-requests")
async def list_er_requests(
    form_id: Optional[int] = None,
    status_id: Optional[int] = None,
    assigned_user_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    if not _perm(staff, "estimate_requests", "view"):
        raise HTTPException(403)
    q = (select(CRMEstimateRequest)
         .options(selectinload(CRMEstimateRequest.form),
                  selectinload(CRMEstimateRequest.status),
                  selectinload(CRMEstimateRequest.assignee))
         .order_by(desc(CRMEstimateRequest.created_at)))
    if form_id:
        q = q.where(CRMEstimateRequest.form_id == form_id)
    if status_id:
        q = q.where(CRMEstimateRequest.status_id == status_id)
    if assigned_user_id:
        q = q.where(CRMEstimateRequest.assigned_user_id == assigned_user_id)
    r = await db.execute(q)
    return [_er_dict(req) for req in r.scalars().all()]


@router.get("/api/estimate-requests/{rid}")
async def get_er_request(rid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "view"):
        raise HTTPException(403)
    r = await db.execute(
        select(CRMEstimateRequest).where(CRMEstimateRequest.id == rid)
        .options(selectinload(CRMEstimateRequest.form),
                 selectinload(CRMEstimateRequest.status),
                 selectinload(CRMEstimateRequest.assignee))
    )
    req = r.scalar_one_or_none()
    if not req:
        raise HTTPException(404)
    return _er_dict(req)


class ERRequestUpdateReq(BaseModel):
    status_id: Optional[int] = None
    assigned_user_id: Optional[int] = None
    notes: Optional[str] = None


@router.put("/api/estimate-requests/{rid}")
async def update_er_request(rid: int, body: ERRequestUpdateReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "edit"):
        raise HTTPException(403)
    r = await db.execute(select(CRMEstimateRequest).where(CRMEstimateRequest.id == rid))
    req = r.scalar_one_or_none()
    if not req:
        raise HTTPException(404)
    data = body.model_dump(exclude_unset=True)
    if "status_id" in data and data["status_id"] != req.status_id:
        req.last_status_change_at = _utcnow()
    for k, v in data.items():
        setattr(req, k, v)
    await db.commit()
    return {"ok": True}


@router.delete("/api/estimate-requests/{rid}")
async def delete_er_request(rid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "delete"):
        raise HTTPException(403)
    await db.execute(delete(CRMEstimateRequest).where(CRMEstimateRequest.id == rid))
    await db.commit()
    return {"ok": True}


@router.post("/api/estimate-requests/{rid}/convert-to-estimate")
async def convert_er_to_estimate(rid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _perm(staff, "estimate_requests", "convert_to_estimate"):
        raise HTTPException(403)
    r = await db.execute(
        select(CRMEstimateRequest).where(CRMEstimateRequest.id == rid)
        .options(selectinload(CRMEstimateRequest.status))
    )
    req = r.scalar_one_or_none()
    if not req:
        raise HTTPException(404)
    if req.converted_estimate_id:
        raise HTTPException(400, detail="Already converted to estimate")
    # Auto-create or find customer by email
    customer_id = None
    if req.email:
        cont_r = await db.execute(select(CRMContact).where(CRMContact.email == req.email).limit(1))
        existing_contact = cont_r.scalar_one_or_none()
        if existing_contact:
            customer_id = existing_contact.customer_id
        else:
            sub = req.submission or {}
            first = sub.get("first_name") or sub.get("name", "").split()[0] if sub.get("name") else "Guest"
            last = " ".join(sub.get("name", "").split()[1:]) or sub.get("last_name", "")
            company = sub.get("company") or sub.get("company_name") or (req.email.split("@")[1] if req.email else "New Client")
            new_cust = CRMCustomer(company_name=company, is_active=True)
            db.add(new_cust)
            await db.flush()
            db.add(CRMContact(customer_id=new_cust.id, first_name=first, last_name=last,
                               email=req.email, is_primary=True))
            customer_id = new_cust.id
    # Generate estimate number
    max_r = await db.execute(select(func.max(CRMEstimate.number)))
    num = (max_r.scalar() or 0) + 1
    formatted = f"EST-{num:06d}"
    sub = req.submission or {}
    est = CRMEstimate(
        number=num, formatted_number=formatted,
        customer_id=customer_id,
        sale_agent_id=staff.id,
        date=_utcnow(),
        expiry_date=_utcnow() + timedelta(days=7),
        status="draft",
        admin_note=f"Converted from estimate request #{rid} (form submission)",
        client_note=sub.get("project_description") or sub.get("description") or "",
    )
    db.add(est)
    await db.flush()
    # Mark request converted
    req.converted_estimate_id = est.id
    req.date_estimated = _utcnow()
    # Mark completed status
    comp_r = await db.execute(select(CRMEstimateRequestStatus).where(CRMEstimateRequestStatus.flag == "completed").limit(1))
    comp_status = comp_r.scalar_one_or_none()
    if comp_status:
        req.status_id = comp_status.id
        req.last_status_change_at = _utcnow()
    await db.commit()
    return {"ok": True, "estimate_id": est.id, "formatted_number": formatted}


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


async def _next_prop_number(db: AsyncSession, prefix: str = "PROP") -> tuple[str, int, str]:
    r = await db.execute(select(func.count()).select_from(CRMProposal))
    n = (r.scalar() or 0) + 1
    formatted = f"{prefix}-{n:04d}"
    return formatted, n, formatted


def _compute_prop_totals(items: list, discount_type: str, discount_value: float, adjustment: float) -> dict:
    subtotal = sum(it.get("qty", 1) * it.get("rate", 0) for it in items)
    tax_total = 0.0
    for it in items:
        rate = it.get("rate", 0)
        qty = it.get("qty", 1)
        disc = it.get("discount", 0)
        line_sub = qty * rate * (1 - disc / 100)
        tax_ids = it.get("tax_ids", [])
        if isinstance(tax_ids, list):
            for tid in tax_ids:
                if isinstance(tid, dict):
                    tax_total += line_sub * tid.get("rate", 0) / 100
    discount_total = (subtotal * discount_value / 100) if discount_type == "percentage" else discount_value
    total = subtotal - discount_total + tax_total + adjustment
    for it in items:
        it["amount"] = round(it.get("qty", 1) * it.get("rate", 0) * (1 - it.get("discount", 0) / 100), 4)
    return {"subtotal": round(subtotal, 4), "tax_total": round(tax_total, 4),
            "discount_total": round(discount_total, 4), "total": round(total, 4)}


@router.post("/api/proposals")
async def create_proposal(req: ProposalReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    prefix = (req.prefix or "PROP").upper()
    prop_num_str, num_int, formatted = await _next_prop_number(db, prefix)
    items = req.items or []
    totals = _compute_prop_totals(items, req.discount_type, req.discount_value, req.adjustment)
    prop = CRMProposal(
        proposal_number=prop_num_str, number=num_int, prefix=prefix, formatted_number=formatted,
        subject=req.subject, customer_id=req.customer_id, lead_id=req.lead_id,
        sale_agent_id=req.sale_agent_id, status=req.status,
        currency=req.currency, discount_type=req.discount_type, discount_value=req.discount_value,
        adjustment=req.adjustment, **totals,
        content=req.content, allow_comments=req.allow_comments,
        client_note=req.client_note, terms=req.terms, admin_note=req.admin_note,
        tags=req.tags or [], assigned_to=req.assigned_to,
        billing_address=req.billing_address, shipping_address=req.shipping_address,
        proposal_to=req.proposal_to,
        date=datetime.fromisoformat(req.date) if req.date else _utcnow(),
        open_till=datetime.fromisoformat(req.open_till) if req.open_till else None,
    )
    db.add(prop)
    await db.flush()
    for so, it in enumerate(items):
        db.add(CRMLineItem(proposal_id=prop.id, description=it.get("description", ""),
                           long_description=it.get("long_description"), qty=it.get("qty", 1),
                           rate=it.get("rate", 0), discount=it.get("discount", 0),
                           tax_ids=it.get("tax_ids", []), amount=it.get("amount", 0), sort_order=so))
    await _log(db, staff, "proposals", "created", prop.id, prop.subject)
    return {"id": prop.id, "proposal_number": prop.proposal_number, "formatted_number": formatted}


@router.get("/api/proposals/{pid}")
async def get_proposal(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid)
                         .options(selectinload(CRMProposal.customer), selectinload(CRMProposal.items)))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    d = _proposal_dict(p)
    d["items"] = [{"id": i.id, "description": i.description, "long_description": i.long_description,
                    "qty": i.qty, "rate": i.rate, "discount": i.discount,
                    "tax_ids": i.tax_ids or [], "amount": i.amount} for i in p.items]
    d["content"] = getattr(p, "content", None)
    d["client_note"] = p.client_note
    d["terms"] = p.terms
    d["billing_address"] = getattr(p, "billing_address", None)
    d["shipping_address"] = getattr(p, "shipping_address", None)
    d["proposal_to"] = getattr(p, "proposal_to", None)
    return d


@router.put("/api/proposals/{pid}")
async def update_proposal(pid: int, req: ProposalReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    fields = req.model_dump(exclude={"items", "date", "open_till", "prefix"}, exclude_unset=True)
    for k, v in fields.items():
        if hasattr(p, k):
            setattr(p, k, v)
    if req.date:
        p.date = datetime.fromisoformat(req.date)
    if req.open_till:
        p.open_till = datetime.fromisoformat(req.open_till)
    if req.items is not None:
        items = req.items
        totals = _compute_prop_totals(items, req.discount_type, req.discount_value, req.adjustment)
        for k, v in totals.items():
            setattr(p, k, v)
        await db.execute(delete(CRMLineItem).where(CRMLineItem.proposal_id == pid))
        for so, it in enumerate(items):
            db.add(CRMLineItem(proposal_id=pid, description=it.get("description", ""),
                               long_description=it.get("long_description"), qty=it.get("qty", 1),
                               rate=it.get("rate", 0), discount=it.get("discount", 0),
                               tax_ids=it.get("tax_ids", []), amount=it.get("amount", 0), sort_order=so))
    p.updated_at = _utcnow()
    await _log(db, staff, "proposals", "updated", p.id, p.subject)
    return {"ok": True}


@router.delete("/api/proposals/{pid}")
async def delete_proposal(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMProposal).where(CRMProposal.id == pid))
    return {"ok": True}


@router.post("/api/proposals/{pid}/send")
async def send_proposal(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid)
                         .options(selectinload(CRMProposal.customer)))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    from config import settings as _s
    public_url = f"{_s.BASE_URL.rstrip('/')}/admin/proposal/{p.id}/{getattr(p, 'hash', '')}"
    if p.customer and p.customer.email:
        html = (f"<p>Dear {p.customer.company_name},</p>"
                f"<p>Please review your proposal <strong>{p.proposal_number}</strong>:</p>"
                f"<p><a href='{public_url}'>{public_url}</a></p>")
        await _send_email(p.customer.email, f"Proposal {p.proposal_number}", html)
    p.status = "sent"
    p.sent_at = _utcnow()
    await _log(db, staff, "proposals", "sent", p.id, p.subject)
    return {"ok": True, "public_url": public_url}


@router.post("/api/proposals/{pid}/mark-sent")
async def mark_proposal_sent(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    p.status = "sent"
    p.sent_at = _utcnow()
    await _log(db, staff, "proposals", "mark_sent", p.id, p.subject)
    return {"ok": True}


@router.post("/api/proposals/{pid}/convert-to-invoice")
async def convert_proposal_to_invoice(pid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid)
                         .options(selectinload(CRMProposal.items)))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    if getattr(p, "converted_to_invoice_id", None):
        raise HTTPException(400, "Proposal already converted")
    prefix = "INV"
    inv_num_str, num_int, formatted = await _next_inv_number(db, prefix)
    inv = CRMInvoice(
        invoice_number=inv_num_str, number=num_int, prefix=prefix, formatted_number=formatted,
        customer_id=p.customer_id, status="draft", currency=p.currency,
        discount_type=p.discount_type, discount_value=p.discount_value,
        adjustment=p.adjustment, subtotal=p.subtotal, tax_total=p.tax_total,
        discount_total=getattr(p, "discount_total", 0.0), total=p.total,
        client_note=p.client_note, terms=p.terms, admin_note=getattr(p, "admin_note", None),
        date=_utcnow(),
    )
    db.add(inv)
    await db.flush()
    for so, it in enumerate(p.items):
        db.add(CRMLineItem(invoice_id=inv.id, description=it.description,
                           long_description=it.long_description, qty=it.qty, rate=it.rate,
                           discount=it.discount, tax_ids=it.tax_ids, amount=it.amount, sort_order=so))
    p.converted_to_invoice_id = inv.id
    p.converted_at = _utcnow()
    p.status = "accepted"
    await db.commit()
    return {"ok": True, "invoice_id": inv.id, "formatted_number": formatted}


@router.post("/api/proposals/{pid}/accept")
async def accept_proposal(pid: int, request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid))
    p = r.scalar_one_or_none()
    if not p or getattr(p, "hash", "") != body.get("hash", ""):
        raise HTTPException(404)
    p.status = "accepted"
    p.acceptance_first_name = body.get("first_name")
    p.acceptance_last_name = body.get("last_name")
    p.acceptance_email = body.get("email")
    p.acceptance_date = _utcnow()
    p.acceptance_ip = _client_ip(request)
    p.signature_image = body.get("signature_image")
    await db.commit()
    return {"ok": True}


@router.post("/api/proposals/{pid}/decline")
async def decline_proposal(pid: int, request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid))
    p = r.scalar_one_or_none()
    if not p or getattr(p, "hash", "") != body.get("hash", ""):
        raise HTTPException(404)
    p.status = "declined"
    await db.commit()
    return {"ok": True}


@router.get("/proposal/{pid}/{hash_val}", response_class=HTMLResponse)
async def public_proposal_page(pid: int, hash_val: str, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMProposal).where(CRMProposal.id == pid)
                         .options(selectinload(CRMProposal.customer), selectinload(CRMProposal.items)))
    p = r.scalar_one_or_none()
    if not p or getattr(p, "hash", "") != hash_val:
        raise HTTPException(404)
    items_html = "".join(
        f"<tr><td>{i.description}</td><td style='text-align:right'>{i.qty}</td>"
        f"<td style='text-align:right'>${i.rate:,.2f}</td>"
        f"<td style='text-align:right'>${i.amount:,.2f}</td></tr>" for i in p.items
    )
    already = p.status in ("accepted", "declined")
    accept_block = ""
    if not already:
        accept_block = f"""
<div id="esign-section" style="margin-top:48px;padding:24px;border:1px solid #e5e7eb;border-radius:12px;background:#f9fafb">
  <h2 style="margin-top:0">Accept This Proposal</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
    <input id="fn" placeholder="First Name" style="padding:8px;border:1px solid #d1d5db;border-radius:6px">
    <input id="ln" placeholder="Last Name" style="padding:8px;border:1px solid #d1d5db;border-radius:6px">
  </div>
  <input id="em" placeholder="Email" style="padding:8px;border:1px solid #d1d5db;border-radius:6px;width:100%;box-sizing:border-box;margin-bottom:16px">
  <p style="margin:0 0 8px;font-weight:600">Signature:</p>
  <canvas id="sig" width="600" height="150" style="border:1px solid #d1d5db;border-radius:6px;background:#fff;max-width:100%"></canvas>
  <br><button onclick="clearSig()" style="margin-top:4px;padding:4px 10px;font-size:.8rem">Clear</button>
  <div style="display:flex;gap:12px;margin-top:20px">
    <button onclick="doAccept()" style="background:#10b981;color:#fff;border:none;padding:12px 24px;border-radius:8px;cursor:pointer;font-weight:600;font-size:1rem">✓ Accept Proposal</button>
    <button onclick="doDecline()" style="background:#ef4444;color:#fff;border:none;padding:12px 24px;border-radius:8px;cursor:pointer;font-weight:600;font-size:1rem">✗ Decline</button>
  </div>
</div>
<script>
const canvas=document.getElementById('sig');const ctx=canvas.getContext('2d');let drawing=false;
canvas.onmousedown=e=>{{drawing=true;ctx.beginPath();ctx.moveTo(e.offsetX,e.offsetY)}};
canvas.onmousemove=e=>{{if(!drawing)return;ctx.lineTo(e.offsetX,e.offsetY);ctx.stroke()}};
canvas.onmouseup=()=>drawing=false;canvas.onmouseleave=()=>drawing=false;
canvas.ontouchstart=e=>{{e.preventDefault();const t=e.touches[0];const r=canvas.getBoundingClientRect();drawing=true;ctx.beginPath();ctx.moveTo(t.clientX-r.left,t.clientY-r.top)}};
canvas.ontouchmove=e=>{{e.preventDefault();const t=e.touches[0];const r=canvas.getBoundingClientRect();ctx.lineTo(t.clientX-r.left,t.clientY-r.top);ctx.stroke()}};
canvas.ontouchend=()=>drawing=false;
function clearSig(){{ctx.clearRect(0,0,canvas.width,canvas.height)}}
async function doAccept(){{
  const fn=document.getElementById('fn').value.trim(),ln=document.getElementById('ln').value.trim(),em=document.getElementById('em').value.trim();
  if(!fn||!ln||!em){{alert('Please fill in all fields');return}}
  const sig=canvas.toDataURL();
  const res=await fetch('/admin/api/proposals/{pid}/accept',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{hash:'{hash_val}',first_name:fn,last_name:ln,email:em,signature_image:sig}})}});
  if(res.ok){{document.getElementById('esign-section').innerHTML='<p style="color:#10b981;font-size:1.2rem;font-weight:600">✓ Proposal accepted. Thank you!</p>'}}
  else alert('Error accepting proposal')
}}
async function doDecline(){{
  if(!confirm('Are you sure you want to decline this proposal?'))return;
  const res=await fetch('/admin/api/proposals/{pid}/decline',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{hash:'{hash_val}'}})}});
  if(res.ok){{document.getElementById('esign-section').innerHTML='<p style="color:#ef4444;font-weight:600">Proposal declined.</p>'}}
}}
</script>"""
    status_color = {"accepted": "#10b981", "declined": "#ef4444", "sent": "#3b82f6", "draft": "#6b7280", "open": "#f59e0b"}.get(p.status, "#6b7280")
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proposal {p.proposal_number}</title>
<style>
  body{{font-family:sans-serif;max-width:860px;margin:40px auto;padding:0 20px;color:#222}}
  h1{{color:#6366f1}}
  table{{width:100%;border-collapse:collapse;margin:16px 0}}
  th,td{{padding:10px;border-bottom:1px solid #e5e7eb;text-align:left}}
  th{{background:#f9fafb;font-weight:600}}
  .badge{{display:inline-block;padding:4px 10px;border-radius:9999px;font-size:.8rem;font-weight:600;background:{status_color};color:#fff}}
  .totals-row{{font-weight:600}}
</style>
</head><body>
<h1>{p.subject}</h1>
<p>Proposal #: <strong>{p.proposal_number}</strong> &nbsp; Status: <span class="badge">{p.status.title()}</span></p>
{'<p>To: '+p.customer.company_name+'</p>' if p.customer else ''}
<p>Date: {p.date.strftime('%B %d, %Y') if p.date else 'N/A'} &nbsp;|&nbsp; Valid till: {p.open_till.strftime('%B %d, %Y') if p.open_till else 'N/A'}</p>
{f'<div style="margin:24px 0;padding:20px;background:#f9fafb;border-radius:8px">{p.content}</div>' if getattr(p,'content',None) else ''}
<table>
  <thead><tr><th>Description</th><th style="text-align:right">Qty</th><th style="text-align:right">Rate</th><th style="text-align:right">Amount</th></tr></thead>
  <tbody>{items_html}</tbody>
</table>
<table style="max-width:360px;margin-left:auto">
  <tr><td>Subtotal</td><td style="text-align:right">${p.subtotal:,.2f}</td></tr>
  <tr><td>Discount</td><td style="text-align:right">-${getattr(p,'discount_total',0):,.2f}</td></tr>
  <tr><td>Tax</td><td style="text-align:right">${p.tax_total:,.2f}</td></tr>
  <tr><td>Adjustment</td><td style="text-align:right">${p.adjustment:,.2f}</td></tr>
  <tr class="totals-row"><td>Total</td><td style="text-align:right">${p.total:,.2f}</td></tr>
</table>
{f'<h3>Note</h3><p>{p.client_note}</p>' if p.client_note else ''}
{f'<h3>Terms</h3><p>{p.terms}</p>' if p.terms else ''}
{accept_block}
</body></html>"""
    return HTMLResponse(html)


# ── Payment Modes Setup ───────────────────────────────────────────────────────

class PaymentModeReq(BaseModel):
    name: str
    description: Optional[str] = None
    active: bool = True
    show_on_pdf: bool = False
    selected_by_default: bool = False
    invoices_only: bool = False
    expenses_only: bool = False


def _pm_dict(pm: CRMPaymentMode) -> dict:
    return {
        "id": pm.id, "name": pm.name, "description": pm.description,
        "active": pm.active, "show_on_pdf": pm.show_on_pdf,
        "selected_by_default": pm.selected_by_default,
        "invoices_only": pm.invoices_only, "expenses_only": pm.expenses_only,
    }


@router.get("/api/payment-modes")
async def list_payment_modes(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMPaymentMode).order_by(CRMPaymentMode.name))
    return [_pm_dict(pm) for pm in r.scalars().all()]


@router.post("/api/payment-modes")
async def create_payment_mode(req: PaymentModeReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    pm = CRMPaymentMode(**req.model_dump())
    db.add(pm)
    await db.flush()
    return {"id": pm.id, "name": pm.name}


@router.put("/api/payment-modes/{pmid}")
async def update_payment_mode(pmid: int, req: PaymentModeReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMPaymentMode).where(CRMPaymentMode.id == pmid))
    pm = r.scalar_one_or_none()
    if not pm:
        raise HTTPException(404)
    for k, v in req.model_dump().items():
        setattr(pm, k, v)
    return {"ok": True}


@router.delete("/api/payment-modes/{pmid}")
async def delete_payment_mode(pmid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMPaymentMode).where(CRMPaymentMode.id == pmid))
    return {"ok": True}


# ── Module 16: Payments ────────────────────────────────────────────────────────

def _payment_dict(p: CRMPayment) -> dict:
    return {
        "id": p.id, "invoice_id": p.invoice_id,
        "invoice_number": p.invoice.invoice_number if p.invoice else None,
        "customer_id": p.invoice.customer_id if p.invoice else None,
        "customer_name": p.invoice.customer.company_name if p.invoice and p.invoice.customer else None,
        "amount": p.amount,
        "date": p.date.isoformat() if p.date else None,
        "payment_mode_id": p.payment_mode_id,
        "payment_mode_name": p.payment_mode.name if p.payment_mode else None,
        "payment_method": p.payment_method,
        "transaction_id": p.transaction_id,
        "note": p.note,
        "created_at": p.created_at.isoformat(),
    }


@router.get("/api/payments")
async def list_payments(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    customer_id: Optional[int] = None,
    payment_mode_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = (select(CRMPayment)
         .options(selectinload(CRMPayment.invoice).selectinload(CRMInvoice.customer),
                  selectinload(CRMPayment.payment_mode))
         .order_by(desc(CRMPayment.date)))
    if date_from:
        q = q.where(CRMPayment.date >= datetime.fromisoformat(date_from))
    if date_to:
        q = q.where(CRMPayment.date <= datetime.fromisoformat(date_to))
    if payment_mode_id:
        q = q.where(CRMPayment.payment_mode_id == payment_mode_id)
    if customer_id:
        q = q.join(CRMInvoice, CRMPayment.invoice_id == CRMInvoice.id).where(CRMInvoice.customer_id == customer_id)
    r = await db.execute(q)
    return [_payment_dict(p) for p in r.scalars().all()]


@router.get("/api/payments/{pay_id}")
async def get_payment(pay_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMPayment).where(CRMPayment.id == pay_id)
                         .options(selectinload(CRMPayment.invoice).selectinload(CRMInvoice.customer),
                                  selectinload(CRMPayment.payment_mode)))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    return _payment_dict(p)


class EditPaymentReq(BaseModel):
    amount: Optional[float] = None
    date: Optional[str] = None
    payment_mode_id: Optional[int] = None
    payment_method: Optional[str] = None
    transaction_id: Optional[str] = None
    note: Optional[str] = None


@router.put("/api/payments/{pay_id}")
async def update_payment(pay_id: int, req: EditPaymentReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMPayment).where(CRMPayment.id == pay_id)
                         .options(selectinload(CRMPayment.invoice)))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    old_amount = p.amount
    fields = req.model_dump(exclude={"date"}, exclude_unset=True)
    for k, v in fields.items():
        setattr(p, k, v)
    if req.date:
        p.date = datetime.fromisoformat(req.date)
    # Recalculate invoice amount_paid
    if req.amount is not None and p.invoice:
        inv = p.invoice
        inv.amount_paid = inv.amount_paid - old_amount + req.amount
        if inv.amount_paid >= inv.total:
            inv.status = "paid"
        elif inv.amount_paid > 0:
            inv.status = "partially_paid"
        else:
            inv.status = "unpaid"
    return {"ok": True}


@router.delete("/api/payments/{pay_id}")
async def delete_payment(pay_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMPayment).where(CRMPayment.id == pay_id)
                         .options(selectinload(CRMPayment.invoice)))
    p = r.scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    if p.invoice:
        p.invoice.amount_paid = max(0, p.invoice.amount_paid - p.amount)
        if p.invoice.amount_paid == 0:
            p.invoice.status = "unpaid"
        elif p.invoice.amount_paid < p.invoice.total:
            p.invoice.status = "partially_paid"
    await db.execute(delete(CRMPayment).where(CRMPayment.id == pay_id))
    return {"ok": True}


class BatchPaymentReq(BaseModel):
    invoice_ids: list[int]
    amount: float
    date: Optional[str] = None
    payment_mode_id: Optional[int] = None
    payment_method: Optional[str] = None
    transaction_id: Optional[str] = None
    note: Optional[str] = None


@router.post("/api/payments/batch")
async def batch_payment(req: BatchPaymentReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    remaining = req.amount
    paid_date = datetime.fromisoformat(req.date) if req.date else _utcnow()
    results = []
    for inv_id in req.invoice_ids:
        if remaining <= 0:
            break
        r = await db.execute(select(CRMInvoice).where(CRMInvoice.id == inv_id))
        inv = r.scalar_one_or_none()
        if not inv:
            continue
        amount_due = inv.total - inv.amount_paid
        if amount_due <= 0:
            continue
        apply = min(remaining, amount_due)
        p = CRMPayment(invoice_id=inv_id, amount=apply, date=paid_date,
                       payment_mode_id=req.payment_mode_id, payment_method=req.payment_method,
                       transaction_id=req.transaction_id, note=req.note,
                       created_by_user_id=staff.id)
        db.add(p)
        inv.amount_paid += apply
        if inv.amount_paid >= inv.total:
            inv.status = "paid"
        else:
            inv.status = "partially_paid"
        remaining -= apply
        results.append({"invoice_id": inv_id, "applied": apply})
    await db.commit()
    return {"ok": True, "applied": results, "unallocated": max(0, remaining)}


# ── Module 17: Credit Notes ───────────────────────────────────────────────────

def _cn_dict(cn: CRMCreditNote, include_items: bool = False) -> dict:
    d: dict = {
        "id": cn.id, "formatted_number": cn.formatted_number,
        "number": cn.number, "prefix": cn.prefix,
        "reference_no": cn.reference_no,
        "customer_id": cn.customer_id,
        "customer_name": cn.customer.company_name if cn.customer else None,
        "status": cn.status,
        "date": cn.date.isoformat() if cn.date else None,
        "currency": cn.currency,
        "subtotal": cn.subtotal, "tax_total": cn.tax_total,
        "discount_total": cn.discount_total, "adjustment": cn.adjustment,
        "total": cn.total, "remaining": cn.remaining,
        "admin_note": cn.admin_note,
        "sent_at": cn.sent_at.isoformat() if cn.sent_at else None,
        "created_at": cn.created_at.isoformat(),
    }
    if include_items:
        d["items"] = [{"id": i.id, "description": i.description, "long_description": i.long_description,
                        "qty": i.qty, "rate": i.rate, "discount": i.discount,
                        "tax_ids": i.tax_ids or [], "amount": i.amount} for i in cn.items]
        d["client_note"] = cn.client_note
        d["terms"] = cn.terms
        d["billing_address"] = cn.billing_address
        d["shipping_address"] = cn.shipping_address
        d["applications"] = [{"id": a.id, "invoice_id": a.invoice_id,
                               "invoice_number": a.invoice.invoice_number if a.invoice else None,
                               "amount": a.amount, "applied_at": a.applied_at.isoformat()} for a in cn.applications]
        d["refunds"] = [{"id": rf.id, "amount": rf.amount,
                          "refunded_on": rf.refunded_on.isoformat(),
                          "payment_mode_id": rf.payment_mode_id,
                          "note": rf.note} for rf in cn.refunds]
    return d


async def _next_cn_number(db: AsyncSession, prefix: str = "CN") -> tuple[str, int]:
    r = await db.execute(select(func.count()).select_from(CRMCreditNote))
    n = (r.scalar() or 0) + 1
    return f"{prefix}-{n:04d}", n


class CreditNoteReq(BaseModel):
    customer_id: Optional[int] = None
    prefix: str = "CN"
    reference_no: Optional[str] = None
    status: str = "Open"
    date: Optional[str] = None
    currency: str = "USD"
    discount_type: str = "before_tax"
    discount_value: float = 0.0
    adjustment: float = 0.0
    client_note: Optional[str] = None
    terms: Optional[str] = None
    admin_note: Optional[str] = None
    assigned_to: Optional[int] = None
    billing_address: Optional[dict] = None
    shipping_address: Optional[dict] = None
    items: Optional[list] = None


@router.get("/api/credit-notes")
async def list_credit_notes(
    status: Optional[str] = None, customer_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    q = (select(CRMCreditNote)
         .options(selectinload(CRMCreditNote.customer))
         .order_by(desc(CRMCreditNote.created_at)))
    if status:
        q = q.where(CRMCreditNote.status == status)
    if customer_id:
        q = q.where(CRMCreditNote.customer_id == customer_id)
    r = await db.execute(q)
    return [_cn_dict(cn) for cn in r.scalars().all()]


@router.post("/api/credit-notes")
async def create_credit_note(req: CreditNoteReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    prefix = (req.prefix or "CN").upper()
    formatted, num = await _next_cn_number(db, prefix)
    items = req.items or []
    subtotal = sum(it.get("qty", 1) * it.get("rate", 0) for it in items)
    disc_total = (subtotal * req.discount_value / 100) if req.discount_type == "percentage" else req.discount_value
    total = round(subtotal - disc_total + req.adjustment, 4)
    cn = CRMCreditNote(
        formatted_number=formatted, number=num, prefix=prefix,
        reference_no=req.reference_no, customer_id=req.customer_id,
        assigned_to=req.assigned_to, status=req.status,
        date=datetime.fromisoformat(req.date) if req.date else _utcnow(),
        currency=req.currency, discount_type=req.discount_type,
        discount_value=req.discount_value, discount_total=round(disc_total, 4),
        adjustment=req.adjustment, subtotal=round(subtotal, 4), total=total, remaining=total,
        billing_address=req.billing_address, shipping_address=req.shipping_address,
        client_note=req.client_note, terms=req.terms, admin_note=req.admin_note,
    )
    db.add(cn)
    await db.flush()
    for so, it in enumerate(items):
        amt = round(it.get("qty", 1) * it.get("rate", 0) * (1 - it.get("discount", 0) / 100), 4)
        db.add(CRMLineItem(credit_note_id=cn.id, description=it.get("description", ""),
                           long_description=it.get("long_description"),
                           qty=it.get("qty", 1), rate=it.get("rate", 0),
                           discount=it.get("discount", 0), tax_ids=it.get("tax_ids", []),
                           amount=amt, sort_order=so))
    await _log(db, staff, "credit_notes", "created", cn.id, formatted)
    return {"id": cn.id, "formatted_number": formatted}


@router.get("/api/credit-notes/{cnid}")
async def get_credit_note(cnid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMCreditNote).where(CRMCreditNote.id == cnid)
                         .options(selectinload(CRMCreditNote.customer),
                                  selectinload(CRMCreditNote.items),
                                  selectinload(CRMCreditNote.applications).selectinload(CRMCreditApplication.invoice),
                                  selectinload(CRMCreditNote.refunds)))
    cn = r.scalar_one_or_none()
    if not cn:
        raise HTTPException(404)
    return _cn_dict(cn, include_items=True)


@router.put("/api/credit-notes/{cnid}")
async def update_credit_note(cnid: int, req: CreditNoteReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMCreditNote).where(CRMCreditNote.id == cnid))
    cn = r.scalar_one_or_none()
    if not cn:
        raise HTTPException(404)
    fields = req.model_dump(exclude={"items", "date", "prefix"}, exclude_unset=True)
    for k, v in fields.items():
        if hasattr(cn, k):
            setattr(cn, k, v)
    if req.date:
        cn.date = datetime.fromisoformat(req.date)
    if req.items is not None:
        items = req.items
        subtotal = sum(it.get("qty", 1) * it.get("rate", 0) for it in items)
        disc_total = (subtotal * req.discount_value / 100) if req.discount_type == "percentage" else req.discount_value
        total = round(subtotal - disc_total + req.adjustment, 4)
        cn.subtotal = round(subtotal, 4)
        cn.discount_total = round(disc_total, 4)
        cn.total = total
        cn.remaining = total - sum(a.amount for a in []) - sum(rf.amount for rf in [])
        await db.execute(delete(CRMLineItem).where(CRMLineItem.credit_note_id == cnid))
        for so, it in enumerate(items):
            amt = round(it.get("qty", 1) * it.get("rate", 0) * (1 - it.get("discount", 0) / 100), 4)
            db.add(CRMLineItem(credit_note_id=cnid, description=it.get("description", ""),
                               long_description=it.get("long_description"),
                               qty=it.get("qty", 1), rate=it.get("rate", 0),
                               discount=it.get("discount", 0), tax_ids=it.get("tax_ids", []),
                               amount=amt, sort_order=so))
    cn.updated_at = _utcnow()
    return {"ok": True}


@router.delete("/api/credit-notes/{cnid}")
async def delete_credit_note(cnid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMCreditNote).where(CRMCreditNote.id == cnid))
    return {"ok": True}


class ApplyCreditReq(BaseModel):
    invoice_id: int
    amount: float


@router.post("/api/credit-notes/{cnid}/apply")
async def apply_credit_note(cnid: int, req: ApplyCreditReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMCreditNote).where(CRMCreditNote.id == cnid))
    cn = r.scalar_one_or_none()
    if not cn:
        raise HTTPException(404)
    if cn.remaining <= 0:
        raise HTTPException(400, "No remaining credit")
    ir = await db.execute(select(CRMInvoice).where(CRMInvoice.id == req.invoice_id))
    inv = ir.scalar_one_or_none()
    if not inv:
        raise HTTPException(404, "Invoice not found")
    amount_due = inv.total - inv.amount_paid
    apply = min(req.amount, cn.remaining, amount_due)
    if apply <= 0:
        raise HTTPException(400, "Nothing to apply")
    # Create application record
    app = CRMCreditApplication(credit_note_id=cnid, invoice_id=req.invoice_id,
                               amount=apply, applied_by_user_id=staff.id)
    db.add(app)
    # Reduce invoice
    inv.amount_paid += apply
    if inv.amount_paid >= inv.total:
        inv.status = "paid"
    elif inv.amount_paid > 0:
        inv.status = "partially_paid"
    # Reduce credit note
    cn.remaining -= apply
    if cn.remaining <= 0:
        cn.status = "Closed"
    await db.commit()
    return {"ok": True, "applied": apply, "remaining": cn.remaining}


class CreditRefundReq(BaseModel):
    amount: float
    refunded_on: Optional[str] = None
    payment_mode_id: Optional[int] = None
    note: Optional[str] = None


@router.post("/api/credit-notes/{cnid}/refund")
async def record_credit_refund(cnid: int, req: CreditRefundReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMCreditNote).where(CRMCreditNote.id == cnid))
    cn = r.scalar_one_or_none()
    if not cn:
        raise HTTPException(404)
    if req.amount > cn.remaining:
        raise HTTPException(400, "Refund exceeds remaining credit")
    rf = CRMCreditRefund(credit_note_id=cnid, amount=req.amount,
                         refunded_on=datetime.fromisoformat(req.refunded_on) if req.refunded_on else _utcnow(),
                         payment_mode_id=req.payment_mode_id, note=req.note,
                         recorded_by_user_id=staff.id)
    db.add(rf)
    cn.remaining -= req.amount
    if cn.remaining <= 0:
        cn.status = "Closed"
    await db.commit()
    return {"ok": True, "remaining": cn.remaining}


# ── Module 18: Subscriptions ──────────────────────────────────────────────────

SUB_STATUSES = ["Draft", "Not Subscribed", "Active", "Past Due", "Unpaid", "Canceled", "Incomplete"]
SUB_INTERVALS = ["day", "week", "month", "year"]


def _sub_dict(s: CRMSubscription) -> dict:
    return {
        "id": s.id, "name": s.name, "description": s.description,
        "description_in_invoice_item": s.description_in_invoice_item,
        "customer_id": s.customer_id,
        "customer_name": s.customer.company_name if s.customer else None,
        "project_id": s.project_id,
        "currency": s.currency, "amount": s.amount, "quantity": s.quantity,
        "interval": s.interval, "interval_count": s.interval_count,
        "trial_days": s.trial_days,
        "ends_at": s.ends_at.isoformat() if s.ends_at else None,
        "status": s.status,
        "next_billing_at": s.next_billing_at.isoformat() if s.next_billing_at else None,
        "stripe_plan_id": s.stripe_plan_id,
        "stripe_subscription_id": s.stripe_subscription_id,
        "hash": s.hash, "is_test_mode": s.is_test_mode,
        "terms": s.terms,
        "created_at": s.created_at.isoformat(),
    }


class SubscriptionReq(BaseModel):
    name: str
    description: Optional[str] = None
    description_in_invoice_item: bool = False
    customer_id: Optional[int] = None
    project_id: Optional[int] = None
    currency: str = "USD"
    amount: float = 0.0
    quantity: int = 1
    interval: str = "month"
    interval_count: int = 1
    trial_days: Optional[int] = None
    ends_at: Optional[str] = None
    tax_id: Optional[int] = None
    tax_id_2: Optional[int] = None
    terms: Optional[str] = None
    is_test_mode: bool = False
    status: str = "Draft"


@router.get("/api/subscriptions")
async def list_subscriptions(
    status: Optional[str] = None,
    customer_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = (select(CRMSubscription)
         .options(selectinload(CRMSubscription.customer))
         .order_by(desc(CRMSubscription.created_at)))
    if status:
        q = q.where(CRMSubscription.status == status)
    if customer_id:
        q = q.where(CRMSubscription.customer_id == customer_id)
    r = await db.execute(q)
    return [_sub_dict(s) for s in r.scalars().all()]


@router.post("/api/subscriptions")
async def create_subscription(req: SubscriptionReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    sub = CRMSubscription(
        name=req.name, description=req.description,
        description_in_invoice_item=req.description_in_invoice_item,
        customer_id=req.customer_id, project_id=req.project_id,
        currency=req.currency, amount=req.amount, quantity=req.quantity,
        interval=req.interval, interval_count=req.interval_count,
        trial_days=req.trial_days,
        ends_at=datetime.fromisoformat(req.ends_at) if req.ends_at else None,
        tax_id=req.tax_id, tax_id_2=req.tax_id_2,
        terms=req.terms, is_test_mode=req.is_test_mode, status=req.status,
        created_by_user_id=staff.id,
    )
    db.add(sub)
    await db.flush()
    await _log(db, staff, "subscriptions", "created", sub.id, sub.name)
    return {"id": sub.id, "hash": sub.hash}


@router.get("/api/subscriptions/{sid}")
async def get_subscription(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMSubscription).where(CRMSubscription.id == sid)
                         .options(selectinload(CRMSubscription.customer)))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    return _sub_dict(s)


@router.put("/api/subscriptions/{sid}")
async def update_subscription(sid: int, req: SubscriptionReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMSubscription).where(CRMSubscription.id == sid))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    fields = req.model_dump(exclude={"ends_at"}, exclude_unset=True)
    for k, v in fields.items():
        if hasattr(s, k):
            setattr(s, k, v)
    if req.ends_at:
        s.ends_at = datetime.fromisoformat(req.ends_at)
    s.updated_at = _utcnow()
    return {"ok": True}


@router.delete("/api/subscriptions/{sid}")
async def delete_subscription(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMSubscription).where(CRMSubscription.id == sid))
    return {"ok": True}


@router.post("/api/subscriptions/{sid}/send")
async def send_subscription(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMSubscription).where(CRMSubscription.id == sid)
                         .options(selectinload(CRMSubscription.customer)))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    from config import settings as _s
    public_url = f"{_s.BASE_URL.rstrip('/')}/admin/subscription/{s.id}/{s.hash}"
    if s.customer and s.customer.email:
        html = (f"<p>Dear {s.customer.company_name},</p>"
                f"<p>You have been invited to subscribe to <strong>{s.name}</strong>.</p>"
                f"<p>Click the link below to view details and subscribe:</p>"
                f"<p><a href='{public_url}'>{public_url}</a></p>")
        await _send_email(s.customer.email, f"Subscription: {s.name}", html)
    s.status = "Not Subscribed"
    s.updated_at = _utcnow()
    await _log(db, staff, "subscriptions", "sent", s.id, s.name)
    return {"ok": True, "public_url": public_url}


@router.post("/api/subscriptions/{sid}/cancel")
async def cancel_subscription(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMSubscription).where(CRMSubscription.id == sid))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    s.status = "Canceled"
    s.updated_at = _utcnow()
    await _log(db, staff, "subscriptions", "canceled", s.id, s.name)
    return {"ok": True}


@router.get("/subscription/{sid}/{hash_val}", response_class=HTMLResponse)
async def public_subscription_page(sid: int, hash_val: str, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMSubscription).where(CRMSubscription.id == sid)
                         .options(selectinload(CRMSubscription.customer)))
    s = r.scalar_one_or_none()
    if not s or s.hash != hash_val:
        raise HTTPException(404)
    interval_label = f"every {s.interval_count} {s.interval}{'s' if s.interval_count > 1 else ''}"
    status_color = {"Active": "#10b981", "Canceled": "#ef4444", "Draft": "#6b7280",
                    "Not Subscribed": "#6366f1", "Past Due": "#f59e0b"}.get(s.status, "#6b7280")
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Subscribe: {s.name}</title>
<style>body{{font-family:sans-serif;max-width:600px;margin:60px auto;padding:0 20px;color:#222}}
  h1{{color:#6366f1}}.card{{background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;padding:24px;margin:24px 0}}
  .price{{font-size:2rem;font-weight:700;color:#6366f1}}.badge{{display:inline-block;padding:4px 10px;border-radius:9999px;font-size:.8rem;font-weight:600;background:{status_color};color:#fff}}
  .notice{{background:#fef3c7;border:1px solid #fbbf24;border-radius:8px;padding:16px;margin:20px 0}}</style>
</head><body>
<h1>{esc(s.name)}</h1>
{'<p>For: '+esc(s.customer.company_name)+'</p>' if s.customer else ''}
<p>Status: <span class="badge">{s.status}</span></p>
<div class="card">
  <div class="price">{s.currency} {s.amount:,.2f}</div>
  <div style="color:#6b7280;margin-top:4px">{interval_label}{f" · {s.quantity}× quantity" if s.quantity > 1 else ""}</div>
  {f'<div style="margin-top:8px;color:#6b7280">Trial: {s.trial_days} days free</div>' if s.trial_days else ''}
  {f'<div style="margin-top:8px;color:#6b7280">Ends: {s.ends_at.strftime("%B %d, %Y")}</div>' if s.ends_at else ''}
</div>
{f'<div style="margin-bottom:20px"><p>{esc(s.description)}</p></div>' if s.description else ''}
<div class="notice">
  <strong>Online payment not yet configured.</strong><br>
  To activate Stripe subscriptions, configure your Stripe API keys in Settings → Integrations.
  Your administrator will contact you with payment details.
</div>
{f'<div style="margin-top:20px"><h3>Terms</h3><p>{esc(s.terms)}</p></div>' if s.terms else ''}
</body></html>"""
    return HTMLResponse(html)


# ── Module 19: Expenses ────────────────────────────────────────────────────────

def _expense_dict(e: CRMExpense) -> dict:
    return {
        "id": e.id, "name": e.name,
        "category_id": e.category_id,
        "category": e.category.name if e.category else None,
        "customer_id": e.customer_id,
        "customer_name": e.customer.company_name if e.customer else None,
        "project_id": e.project_id,
        "amount": e.amount, "currency": e.currency,
        "reference": e.reference, "note": e.note,
        "expense_date": e.expense_date.isoformat() if e.expense_date else None,
        "payment_mode_id": e.payment_mode_id,
        "tax_id": e.tax_id,
        "is_billable": e.is_billable, "is_billed": e.is_billed,
        "invoice_id": getattr(e, "invoice_id", None),
        "is_recurring": e.is_recurring,
        "created_at": e.created_at.isoformat(),
    }


class ExpenseReq(BaseModel):
    name: Optional[str] = None
    category_id: Optional[int] = None
    customer_id: Optional[int] = None
    project_id: Optional[int] = None
    amount: float
    currency: str = "USD"
    tax_id: Optional[int] = None
    tax_id_2: Optional[int] = None
    payment_mode_id: Optional[int] = None
    reference: Optional[str] = None
    note: Optional[str] = None
    expense_date: Optional[str] = None
    is_billable: bool = False
    is_recurring: bool = False
    recurring_config: Optional[dict] = None


@router.get("/api/expenses")
async def list_expenses(
    category_id: Optional[int] = None,
    customer_id: Optional[int] = None,
    project_id: Optional[int] = None,
    is_billable: Optional[bool] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = (select(CRMExpense)
         .options(selectinload(CRMExpense.category), selectinload(CRMExpense.customer))
         .order_by(desc(CRMExpense.expense_date)))
    if category_id:
        q = q.where(CRMExpense.category_id == category_id)
    if customer_id:
        q = q.where(CRMExpense.customer_id == customer_id)
    if project_id:
        q = q.where(CRMExpense.project_id == project_id)
    if is_billable is not None:
        q = q.where(CRMExpense.is_billable == is_billable)
    if date_from:
        q = q.where(CRMExpense.expense_date >= datetime.fromisoformat(date_from))
    if date_to:
        q = q.where(CRMExpense.expense_date <= datetime.fromisoformat(date_to))
    r = await db.execute(q)
    return [_expense_dict(e) for e in r.scalars().all()]


@router.get("/api/expenses/{eid}")
async def get_expense(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMExpense).where(CRMExpense.id == eid)
                         .options(selectinload(CRMExpense.category), selectinload(CRMExpense.customer)))
    e = r.scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    return _expense_dict(e)


@router.post("/api/expenses")
async def create_expense(req: ExpenseReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    e = CRMExpense(
        name=req.name, category_id=req.category_id, customer_id=req.customer_id,
        project_id=req.project_id, amount=req.amount, currency=req.currency,
        tax_id=req.tax_id, payment_mode_id=req.payment_mode_id,
        reference=req.reference, note=req.note,
        expense_date=datetime.fromisoformat(req.expense_date) if req.expense_date else _utcnow(),
        is_billable=req.is_billable, is_recurring=req.is_recurring,
        recurring_config=req.recurring_config,
        created_by=staff.id,
    )
    db.add(e)
    await db.flush()
    await _log(db, staff, "expenses", "created", e.id, e.name or str(e.amount))
    return {"id": e.id}


@router.put("/api/expenses/{eid}")
async def update_expense(eid: int, req: ExpenseReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMExpense).where(CRMExpense.id == eid))
    e = r.scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    fields = req.model_dump(exclude={"expense_date"}, exclude_unset=True)
    for k, v in fields.items():
        if hasattr(e, k):
            setattr(e, k, v)
    if req.expense_date:
        e.expense_date = datetime.fromisoformat(req.expense_date)
    return {"ok": True}


@router.delete("/api/expenses/{eid}")
async def delete_expense(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMExpense).where(CRMExpense.id == eid))
    return {"ok": True}


@router.post("/api/expenses/{eid}/bill")
async def bill_expense(eid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Convert a billable expense into an invoice line item on a new draft invoice."""
    r = await db.execute(select(CRMExpense).where(CRMExpense.id == eid)
                         .options(selectinload(CRMExpense.customer)))
    e = r.scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    if not e.is_billable:
        raise HTTPException(400, "Expense is not marked billable")
    if e.is_billed:
        raise HTTPException(400, "Expense already billed")
    # Create draft invoice for the customer
    prefix = "INV"
    inv_num_str, num_int, formatted = await _next_inv_number(db, prefix)
    inv = CRMInvoice(
        invoice_number=inv_num_str, number=num_int, prefix=prefix, formatted_number=formatted,
        customer_id=e.customer_id, status="draft", currency=e.currency,
        subtotal=e.amount, total=e.amount, date=_utcnow(),
    )
    db.add(inv)
    await db.flush()
    db.add(CRMLineItem(invoice_id=inv.id, description=e.name or "Expense",
                       qty=1, rate=e.amount, amount=e.amount, sort_order=0))
    e.is_billed = True
    e.invoice_id = inv.id
    await db.commit()
    return {"ok": True, "invoice_id": inv.id, "formatted_number": formatted}


@router.post("/api/expenses/bulk-bill")
async def bulk_bill_expenses(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Combine multiple billable expenses for one client into one draft invoice."""
    ids: list[int] = req.get("ids", [])
    if not ids:
        raise HTTPException(400, "No expense IDs provided")
    r = await db.execute(select(CRMExpense).where(CRMExpense.id.in_(ids))
                         .options(selectinload(CRMExpense.customer)))
    expenses = r.scalars().all()
    unbillable = [e.id for e in expenses if not e.is_billable]
    if unbillable:
        raise HTTPException(400, f"Expenses not billable: {unbillable}")
    already_billed = [e.id for e in expenses if e.is_billed]
    if already_billed:
        raise HTTPException(400, f"Already billed: {already_billed}")
    customer_ids = {e.customer_id for e in expenses}
    if len(customer_ids) > 1:
        raise HTTPException(400, "All expenses must belong to the same client")
    total = sum(e.amount for e in expenses)
    prefix = "INV"
    inv_num_str, num_int, formatted = await _next_inv_number(db, prefix)
    customer_id = next(iter(customer_ids))
    currency = expenses[0].currency if expenses else "USD"
    inv = CRMInvoice(
        invoice_number=inv_num_str, number=num_int, prefix=prefix, formatted_number=formatted,
        customer_id=customer_id, status="draft", currency=currency,
        subtotal=total, total=total, date=_utcnow(),
    )
    db.add(inv)
    await db.flush()
    for so, e in enumerate(expenses):
        db.add(CRMLineItem(invoice_id=inv.id, description=e.name or "Expense",
                           qty=1, rate=e.amount, amount=e.amount, sort_order=so))
        e.is_billed = True
        e.invoice_id = inv.id
    await db.commit()
    return {"ok": True, "invoice_id": inv.id, "formatted_number": formatted, "count": len(expenses)}


@router.get("/api/expense-categories")
async def list_expense_cats(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMExpenseCategory).order_by(CRMExpenseCategory.name))
    return [{"id": c.id, "name": c.name, "description": c.description} for c in r.scalars().all()]


@router.post("/api/expense-categories")
async def create_expense_cat(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    c = CRMExpenseCategory(name=req["name"], description=req.get("description"))
    db.add(c)
    await db.flush()
    return {"id": c.id}


@router.put("/api/expense-categories/{cid}")
async def update_expense_cat(cid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMExpenseCategory).where(CRMExpenseCategory.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    c.name = req.get("name", c.name)
    c.description = req.get("description", c.description)
    return {"ok": True}


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
    content: Optional[str] = None
    allow_esign: bool = False
    not_visible_to_client: bool = False
    tags: Optional[list] = None


@router.get("/api/contracts")
async def list_contracts(
    status: Optional[str] = None, customer_id: Optional[int] = None,
    trashed: bool = False,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    q = (select(CRMContract)
         .options(selectinload(CRMContract.customer), selectinload(CRMContract.contract_type))
         .where(CRMContract.trashed == trashed)
         .order_by(desc(CRMContract.created_at)))
    if status:
        q = q.where(CRMContract.status == status)
    if customer_id:
        q = q.where(CRMContract.customer_id == customer_id)
    r = await db.execute(q)
    return [_contract_dict(c) for c in r.scalars().all()]


@router.get("/api/contracts/{cid}")
async def get_contract(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContract).where(CRMContract.id == cid)
                         .options(selectinload(CRMContract.customer), selectinload(CRMContract.contract_type),
                                  selectinload(CRMContract.renewals)))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    d = _contract_dict(c)
    d["renewals"] = [{"id": rn.id, "old_start": rn.old_start.isoformat() if rn.old_start else None,
                      "new_start": rn.new_start.isoformat() if rn.new_start else None,
                      "old_end": rn.old_end.isoformat() if rn.old_end else None,
                      "new_end": rn.new_end.isoformat() if rn.new_end else None,
                      "old_value": rn.old_value, "new_value": rn.new_value,
                      "renewed_at": rn.renewed_at.isoformat()} for rn in c.renewals]
    return d


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
    return {"id": c.id, "contract_number": c.contract_number, "hash": c.hash}


@router.put("/api/contracts/{cid}")
async def update_contract(cid: int, req: ContractReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContract).where(CRMContract.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    data = req.model_dump(exclude={"start_date", "end_date"}, exclude_unset=True)
    if req.start_date:
        data["start_date"] = datetime.fromisoformat(req.start_date)
    if req.end_date:
        data["end_date"] = datetime.fromisoformat(req.end_date)
    data["updated_at"] = datetime.utcnow()
    for k, v in data.items():
        setattr(c, k, v)
    await _log(db, staff, "contracts", "updated", c.id, c.subject)
    return {"ok": True}


@router.post("/api/contracts/{cid}/send")
async def send_contract(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContract).where(CRMContract.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    c.last_sent_at = datetime.utcnow()
    if c.status == "draft":
        c.status = "active"
    await _log(db, staff, "contracts", "sent", c.id, c.subject)
    return {"ok": True}


@router.post("/api/contracts/{cid}/mark-signed")
async def mark_contract_signed(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContract).where(CRMContract.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    c.signed = True
    c.marked_as_signed = True
    c.signed_at = datetime.utcnow()
    await _log(db, staff, "contracts", "marked_signed", c.id, c.subject)
    return {"ok": True}


@router.post("/api/contracts/{cid}/renew")
async def renew_contract(cid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContract).where(CRMContract.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    renewal = CRMContractRenewal(
        contract_id=cid,
        old_start=c.start_date, old_end=c.end_date, old_value=c.value,
        new_start=datetime.fromisoformat(req["new_start"]) if req.get("new_start") else None,
        new_end=datetime.fromisoformat(req["new_end"]) if req.get("new_end") else None,
        new_value=req.get("new_value"),
        renewed_by_user_id=staff.id,
    )
    db.add(renewal)
    if req.get("new_start"):
        c.start_date = datetime.fromisoformat(req["new_start"])
    if req.get("new_end"):
        c.end_date = datetime.fromisoformat(req["new_end"])
    if req.get("new_value") is not None:
        c.value = req["new_value"]
    c.status = "active"
    c.updated_at = datetime.utcnow()
    await _log(db, staff, "contracts", "renewed", c.id, c.subject)
    return {"ok": True}


@router.post("/api/contracts/{cid}/trash")
async def trash_contract(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContract).where(CRMContract.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    c.trashed = True
    return {"ok": True}


@router.post("/api/contracts/{cid}/restore")
async def restore_contract(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContract).where(CRMContract.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    c.trashed = False
    return {"ok": True}


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


# ── Public contract sign page ─────────────────────────────────────────────────

@router.get("/contract/{cid}/{chash}")
async def contract_public_page(cid: int, chash: str, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContract).where(CRMContract.id == cid, CRMContract.hash == chash)
                         .options(selectinload(CRMContract.customer), selectinload(CRMContract.contract_type)))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    from fastapi.responses import HTMLResponse
    signed_block = ""
    if c.signed or c.marked_as_signed:
        signed_block = f"""<div class="signed-banner"><span>✓ Signed by {c.acceptance_first_name or ''} {c.acceptance_last_name or ''}</span><span>on {c.acceptance_date.strftime('%B %d, %Y') if c.acceptance_date else (c.signed_at.strftime('%B %d, %Y') if c.signed_at else '')}</span></div>"""
    esign_block = ""
    if c.allow_esign and not c.signed and not c.marked_as_signed:
        esign_block = f"""
<div id="esign-section">
  <h2>Sign this Contract</h2>
  <div class="form-row"><label>First Name *</label><input id="sign-fn" type="text" placeholder="First name"/></div>
  <div class="form-row"><label>Last Name *</label><input id="sign-ln" type="text" placeholder="Last name"/></div>
  <div class="form-row"><label>Email *</label><input id="sign-email" type="email" placeholder="Email address"/></div>
  <div class="form-row"><label>Signature *</label>
    <canvas id="sign-canvas" width="500" height="150" style="border:1px solid #ccc;border-radius:6px;background:#fff;touch-action:none;"></canvas>
    <button type="button" onclick="clearSig()" style="margin-top:6px;font-size:12px;">Clear</button>
  </div>
  <button class="btn-primary" onclick="submitSign({c.id}, '{chash}')">Sign Contract</button>
</div>
<script>
const cv=document.getElementById('sign-canvas');const ctx=cv.getContext('2d');let drawing=false,lastX=0,lastY=0;
function pos(e){{const r=cv.getBoundingClientRect();if(e.touches){{return{{x:e.touches[0].clientX-r.left,y:e.touches[0].clientY-r.top}};}}return{{x:e.clientX-r.left,y:e.clientY-r.top}};}}
cv.addEventListener('mousedown',e=>{{drawing=true;const p=pos(e);lastX=p.x;lastY=p.y;}});
cv.addEventListener('mousemove',e=>{{if(!drawing)return;const p=pos(e);ctx.beginPath();ctx.moveTo(lastX,lastY);ctx.lineTo(p.x,p.y);ctx.strokeStyle='#1a1a2e';ctx.lineWidth=2;ctx.stroke();lastX=p.x;lastY=p.y;}});
cv.addEventListener('mouseup',()=>drawing=false);cv.addEventListener('mouseleave',()=>drawing=false);
cv.addEventListener('touchstart',e=>{{e.preventDefault();drawing=true;const p=pos(e);lastX=p.x;lastY=p.y;}},{{passive:false}});
cv.addEventListener('touchmove',e=>{{e.preventDefault();if(!drawing)return;const p=pos(e);ctx.beginPath();ctx.moveTo(lastX,lastY);ctx.lineTo(p.x,p.y);ctx.strokeStyle='#1a1a2e';ctx.lineWidth=2;ctx.stroke();lastX=p.x;lastY=p.y;}},{{passive:false}});
cv.addEventListener('touchend',()=>drawing=false);
function clearSig(){{ctx.clearRect(0,0,cv.width,cv.height);}}
async function submitSign(id,hash){{
  const fn=document.getElementById('sign-fn').value.trim();
  const ln=document.getElementById('sign-ln').value.trim();
  const em=document.getElementById('sign-email').value.trim();
  if(!fn||!ln||!em){{alert('Please fill in all fields.');return;}}
  const sig=cv.toDataURL('image/png');
  const res=await fetch('/admin/contract/'+id+'/'+hash+'/sign',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{first_name:fn,last_name:ln,email:em,signature:sig}})}});
  if(res.ok){{document.getElementById('esign-section').innerHTML='<div class="signed-banner">✓ Contract signed successfully. Thank you!</div>';}}
  else{{alert('Error signing contract.');}}
}}
</script>"""
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Contract – {c.subject}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#f8fafc;color:#1e293b;margin:0;padding:0}}
.container{{max-width:860px;margin:0 auto;padding:32px 24px}}
.header{{background:#1a1a2e;color:#fff;padding:24px 32px;border-radius:12px;margin-bottom:32px}}
.header h1{{margin:0 0 8px;font-size:24px}}
.meta{{display:grid;grid-template-columns:1fr 1fr;gap:12px;background:#fff;padding:20px;border-radius:10px;margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.07)}}
.meta-item span{{display:block;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}}
.content-body{{background:#fff;padding:24px;border-radius:10px;margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.07);line-height:1.7}}
#esign-section{{background:#fff;padding:24px;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.07);margin-bottom:24px}}
#esign-section h2{{margin:0 0 20px;font-size:18px}}
.form-row{{margin-bottom:14px}}
.form-row label{{display:block;font-size:13px;font-weight:600;margin-bottom:4px}}
.form-row input{{width:100%;padding:8px 10px;border:1px solid #e2e8f0;border-radius:6px;font-size:14px;box-sizing:border-box}}
.btn-primary{{background:#6366f1;color:#fff;border:none;padding:10px 24px;border-radius:8px;font-size:15px;cursor:pointer;margin-top:8px}}
.signed-banner{{background:#dcfce7;border:1px solid #86efac;border-radius:8px;padding:16px 20px;display:flex;gap:16px;align-items:center;font-weight:600;color:#166534;margin-bottom:16px}}
</style></head><body>
<div class="container">
  <div class="header">
    <h1>{c.subject}</h1>
    <div style="font-size:13px;opacity:.8">Contract #{c.contract_number}</div>
  </div>
  {signed_block}
  <div class="meta">
    <div class="meta-item"><span>Client</span>{c.customer.company_name if c.customer else '—'}</div>
    <div class="meta-item"><span>Contract Type</span>{c.contract_type.name if c.contract_type else '—'}</div>
    <div class="meta-item"><span>Value</span>{c.currency} {c.value:,.2f if c.value else '—'}</div>
    <div class="meta-item"><span>Status</span>{c.status.title()}</div>
    <div class="meta-item"><span>Start Date</span>{c.start_date.strftime('%B %d, %Y') if c.start_date else '—'}</div>
    <div class="meta-item"><span>End Date</span>{c.end_date.strftime('%B %d, %Y') if c.end_date else '—'}</div>
  </div>
  <div class="content-body">{c.content or c.description or '<p><em>No contract body provided.</em></p>'}</div>
  {esign_block}
</div></body></html>"""
    return HTMLResponse(html)


@router.post("/contract/{cid}/{chash}/sign")
async def sign_contract_public(cid: int, chash: str, req: dict, request: Request, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMContract).where(CRMContract.id == cid, CRMContract.hash == chash))
    c = r.scalar_one_or_none()
    if not c or not c.allow_esign:
        raise HTTPException(404)
    if c.signed or c.marked_as_signed:
        raise HTTPException(400, "Already signed")
    c.acceptance_first_name = req.get("first_name")
    c.acceptance_last_name = req.get("last_name")
    c.acceptance_email = req.get("email")
    c.acceptance_signature = req.get("signature")
    c.acceptance_date = datetime.utcnow()
    c.acceptance_ip = request.client.host if request.client else None
    c.signed = True
    c.signed_at = datetime.utcnow()
    c.signed_ip = request.client.host if request.client else None
    c.status = "active"
    return {"ok": True}


# ── MODULE 23: Tickets ────────────────────────────────────────────────────────

def _ticket_dict(t: CRMTicket) -> dict:
    return {
        "id": t.id, "ticket_key": t.ticket_key,
        "subject": t.subject, "message": t.message,
        "customer_id": t.customer_id,
        "customer_name": t.customer.company_name if t.customer else None,
        "contact_id": t.contact_id,
        "name": t.name, "email": t.email,
        "department_id": t.department_id,
        "department_name": t.department.name if t.department else None,
        "priority_id": t.priority_id,
        "priority_name": t.priority_obj.name if t.priority_obj else None,
        "priority_color": t.priority_obj.color if t.priority_obj else None,
        "status_id": t.status_id,
        "status_name": t.status_obj.name if t.status_obj else None,
        "status_color": t.status_obj.color if t.status_obj else None,
        "service_id": t.service_id,
        "service_name": t.service.name if t.service else None,
        "project_id": t.project_id,
        "assigned_user_id": t.assigned_user_id,
        "assigned_user_name": f"{t.assigned_user.first_name} {t.assigned_user.last_name}" if t.assigned_user else None,
        "cc": t.cc, "tags": t.tags or [],
        "last_reply_at": t.last_reply_at.isoformat() if t.last_reply_at else None,
        "client_read": t.client_read, "admin_read": t.admin_read,
        "merged_into_ticket_id": t.merged_into_ticket_id,
        "created_at": t.created_at.isoformat(),
    }


def _reply_dict(r: CRMTicketReply) -> dict:
    return {
        "id": r.id, "ticket_id": r.ticket_id,
        "user_id": r.user_id,
        "author_name": f"{r.user.first_name} {r.user.last_name}" if r.user else (r.contact.first_name + " " + r.contact.last_name if r.contact else "Customer"),
        "is_staff": r.user_id is not None,
        "content": r.content,
        "is_internal_note": r.is_internal_note,
        "attachments": r.attachments or [],
        "created_at": r.created_at.isoformat(),
    }


class TicketReq(BaseModel):
    subject: str
    message: Optional[str] = None
    customer_id: Optional[int] = None
    contact_id: Optional[int] = None
    name: Optional[str] = None
    email: Optional[str] = None
    department_id: Optional[int] = None
    priority_id: Optional[int] = None
    status_id: Optional[int] = None
    service_id: Optional[int] = None
    project_id: Optional[int] = None
    assigned_user_id: Optional[int] = None
    cc: Optional[str] = None
    tags: Optional[list] = None


class TicketReplyReq(BaseModel):
    content: str
    is_internal_note: bool = False
    new_status_id: Optional[int] = None


@router.get("/api/tickets")
async def list_tickets(
    status_id: Optional[int] = None,
    department_id: Optional[int] = None,
    priority_id: Optional[int] = None,
    assigned_user_id: Optional[int] = None,
    customer_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = (select(CRMTicket)
         .options(
             selectinload(CRMTicket.customer),
             selectinload(CRMTicket.department),
             selectinload(CRMTicket.priority_obj),
             selectinload(CRMTicket.status_obj),
             selectinload(CRMTicket.service),
             selectinload(CRMTicket.assigned_user),
         )
         .where(CRMTicket.merged_into_ticket_id == None)
         .order_by(desc(CRMTicket.last_reply_at), desc(CRMTicket.created_at)))
    if status_id is not None:
        q = q.where(CRMTicket.status_id == status_id)
    if department_id:
        q = q.where(CRMTicket.department_id == department_id)
    if priority_id:
        q = q.where(CRMTicket.priority_id == priority_id)
    if assigned_user_id:
        q = q.where(CRMTicket.assigned_user_id == assigned_user_id)
    if customer_id:
        q = q.where(CRMTicket.customer_id == customer_id)
    r = await db.execute(q)
    return [_ticket_dict(t) for t in r.scalars().all()]


@router.get("/api/tickets/{tid}")
async def get_ticket(tid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(CRMTicket).where(CRMTicket.id == tid)
        .options(
            selectinload(CRMTicket.customer),
            selectinload(CRMTicket.department),
            selectinload(CRMTicket.priority_obj),
            selectinload(CRMTicket.status_obj),
            selectinload(CRMTicket.service),
            selectinload(CRMTicket.assigned_user),
            selectinload(CRMTicket.replies).selectinload(CRMTicketReply.user),
            selectinload(CRMTicket.replies).selectinload(CRMTicketReply.contact),
        )
    )
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    t.admin_read = True
    d = _ticket_dict(t)
    d["replies"] = [_reply_dict(rp) for rp in t.replies]
    return d


@router.post("/api/tickets")
async def create_ticket(req: TicketReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    # Auto-assign default status (first "Open" status or lowest sort order)
    status_id = req.status_id
    if not status_id:
        def_r = await db.execute(select(CRMTicketStatus).order_by(CRMTicketStatus.is_default.desc(), CRMTicketStatus.sort_order).limit(1))
        def_s = def_r.scalar_one_or_none()
        if def_s:
            status_id = def_s.id
    t = CRMTicket(
        subject=req.subject, message=req.message,
        customer_id=req.customer_id, contact_id=req.contact_id,
        name=req.name, email=req.email,
        department_id=req.department_id, priority_id=req.priority_id,
        status_id=status_id, service_id=req.service_id,
        project_id=req.project_id,
        assigned_user_id=req.assigned_user_id or staff.id,
        cc=req.cc, tags=req.tags or [],
        last_reply_at=datetime.utcnow(),
        admin_read=True,
    )
    db.add(t)
    await db.flush()
    await _log(db, staff, "tickets", "created", t.id, t.subject)
    return {"id": t.id, "ticket_key": t.ticket_key}


@router.put("/api/tickets/{tid}")
async def update_ticket(tid: int, req: TicketReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTicket).where(CRMTicket.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    for field in ["subject", "customer_id", "contact_id", "name", "email", "department_id",
                  "priority_id", "status_id", "service_id", "project_id", "assigned_user_id", "cc", "tags"]:
        val = getattr(req, field, None)
        if val is not None:
            setattr(t, field, val)
    await _log(db, staff, "tickets", "updated", t.id, t.subject)
    return {"ok": True}


@router.post("/api/tickets/{tid}/reply")
async def reply_ticket(tid: int, req: TicketReplyReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTicket).where(CRMTicket.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    reply = CRMTicketReply(ticket_id=tid, user_id=staff.id, content=req.content, is_internal_note=req.is_internal_note)
    db.add(reply)
    t.last_reply_at = datetime.utcnow()
    t.admin_read = True
    t.client_read = False
    if req.new_status_id:
        t.status_id = req.new_status_id
    elif not req.is_internal_note:
        # Auto-move to "Answered" status if one exists
        answered = await db.execute(select(CRMTicketStatus).where(func.lower(CRMTicketStatus.name) == "answered"))
        ans = answered.scalar_one_or_none()
        if ans:
            t.status_id = ans.id
    await db.flush()
    await _log(db, staff, "tickets", "replied", t.id, t.subject)
    return {"id": reply.id}


@router.post("/api/tickets/{tid}/merge")
async def merge_ticket(tid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTicket).where(CRMTicket.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    target_id = req.get("target_id")
    if not target_id or target_id == tid:
        raise HTTPException(400, "Invalid target ticket")
    t.merged_into_ticket_id = target_id
    await _log(db, staff, "tickets", "merged", t.id, t.subject)
    return {"ok": True}


@router.delete("/api/tickets/{tid}/replies/{rid}")
async def delete_reply(tid: int, rid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMTicketReply).where(CRMTicketReply.id == rid, CRMTicketReply.ticket_id == tid))
    return {"ok": True}


@router.delete("/api/tickets/{tid}")
async def delete_ticket(tid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMTicket).where(CRMTicket.id == tid))
    return {"ok": True}


# ── Ticket lookups ────────────────────────────────────────────────────────────

@router.get("/api/ticket-departments")
async def list_ticket_departments(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTicketDepartment).order_by(CRMTicketDepartment.name))
    return [{"id": d.id, "name": d.name, "email": d.email} for d in r.scalars().all()]


@router.post("/api/ticket-departments")
async def create_ticket_department(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    d = CRMTicketDepartment(name=req["name"], email=req.get("email"))
    db.add(d)
    await db.flush()
    return {"id": d.id}


@router.delete("/api/ticket-departments/{did}")
async def delete_ticket_department(did: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMTicketDepartment).where(CRMTicketDepartment.id == did))
    return {"ok": True}


@router.get("/api/ticket-priorities")
async def list_ticket_priorities(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTicketPriority).order_by(CRMTicketPriority.sort_order))
    return [{"id": p.id, "name": p.name, "color": p.color} for p in r.scalars().all()]


@router.get("/api/ticket-statuses")
async def list_ticket_statuses(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTicketStatus).order_by(CRMTicketStatus.sort_order))
    return [{"id": s.id, "name": s.name, "color": s.color, "is_default": s.is_default} for s in r.scalars().all()]


@router.post("/api/ticket-statuses")
async def create_ticket_status(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    s = CRMTicketStatus(name=req["name"], color=req.get("color", "#6366f1"))
    db.add(s)
    await db.flush()
    return {"id": s.id}


@router.delete("/api/ticket-statuses/{sid}")
async def delete_ticket_status(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMTicketStatus).where(CRMTicketStatus.id == sid))
    return {"ok": True}


@router.get("/api/ticket-services")
async def list_ticket_services(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTicketService).order_by(CRMTicketService.name))
    return [{"id": s.id, "name": s.name} for s in r.scalars().all()]


@router.post("/api/ticket-services")
async def create_ticket_service(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    s = CRMTicketService(name=req["name"])
    db.add(s)
    await db.flush()
    return {"id": s.id}


@router.delete("/api/ticket-services/{sid}")
async def delete_ticket_service(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMTicketService).where(CRMTicketService.id == sid))
    return {"ok": True}


@router.get("/api/predefined-replies")
async def list_predefined_replies(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMPredefinedReply).order_by(CRMPredefinedReply.name))
    return [{"id": pr.id, "name": pr.name, "message": pr.message} for pr in r.scalars().all()]


@router.post("/api/predefined-replies")
async def create_predefined_reply(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    pr = CRMPredefinedReply(name=req["name"], message=req["message"], created_by=staff.id)
    db.add(pr)
    await db.flush()
    return {"id": pr.id}


@router.put("/api/predefined-replies/{prid}")
async def update_predefined_reply(prid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMPredefinedReply).where(CRMPredefinedReply.id == prid))
    pr = r.scalar_one_or_none()
    if not pr:
        raise HTTPException(404)
    if "name" in req:
        pr.name = req["name"]
    if "message" in req:
        pr.message = req["message"]
    return {"ok": True}


@router.delete("/api/predefined-replies/{prid}")
async def delete_predefined_reply(prid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMPredefinedReply).where(CRMPredefinedReply.id == prid))
    return {"ok": True}


# ── Knowledge Base ────────────────────────────────────────────────────────────

def _kb_slug(text: str) -> str:
    import re
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or secrets.token_hex(6)


def _article_dict(a: CRMKBArticle) -> dict:
    helpful = sum(1 for f in (a.feedback or []) if f.vote == "helpful")
    not_helpful = sum(1 for f in (a.feedback or []) if f.vote == "not_helpful")
    return {
        "id": a.id, "group_id": a.group_id,
        "group_name": a.group.name if a.group else None,
        "subject": a.subject, "slug": a.slug,
        "description": a.description,
        "active": a.active, "staff_only": a.staff_only,
        "sort_order": a.sort_order,
        "created_by": a.created_by,
        "creator_name": a.creator.full_name if a.creator else None,
        "created_at": a.created_at.isoformat(),
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        "helpful": helpful, "not_helpful": not_helpful,
    }


@router.get("/api/kb/groups")
async def list_kb_groups(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMKBGroup).order_by(CRMKBGroup.sort_order, CRMKBGroup.name))
    groups = r.scalars().all()
    result = []
    for g in groups:
        cnt_r = await db.execute(select(func.count()).select_from(CRMKBArticle).where(CRMKBArticle.group_id == g.id))
        result.append({
            "id": g.id, "name": g.name, "slug": g.slug, "description": g.description,
            "color": g.color, "active": g.active, "sort_order": g.sort_order,
            "article_count": cnt_r.scalar() or 0,
            "created_at": g.created_at.isoformat(),
        })
    return result


@router.post("/api/kb/groups")
async def create_kb_group(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    name = req.get("name", "").strip()
    if not name:
        raise HTTPException(400, "Name required")
    slug = _kb_slug(name)
    existing = await db.execute(select(CRMKBGroup).where(CRMKBGroup.slug == slug))
    if existing.scalar_one_or_none():
        slug = f"{slug}-{secrets.token_hex(3)}"
    g = CRMKBGroup(
        name=name, slug=slug,
        description=req.get("description"),
        color=req.get("color", "#6366f1"),
        active=req.get("active", True),
        sort_order=req.get("sort_order", 0),
    )
    db.add(g)
    await db.flush()
    return {"id": g.id, "slug": g.slug}


@router.put("/api/kb/groups/{gid}")
async def update_kb_group(gid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMKBGroup).where(CRMKBGroup.id == gid))
    g = r.scalar_one_or_none()
    if not g:
        raise HTTPException(404)
    for f in ("name", "description", "color", "active", "sort_order"):
        if f in req:
            setattr(g, f, req[f])
    return {"ok": True}


@router.delete("/api/kb/groups/{gid}")
async def delete_kb_group(gid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMKBGroup).where(CRMKBGroup.id == gid))
    return {"ok": True}


@router.get("/api/kb/articles")
async def list_kb_articles(
    group_id: Optional[int] = None, active: Optional[bool] = None,
    staff_only: Optional[bool] = None, q: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    query = (select(CRMKBArticle)
             .options(selectinload(CRMKBArticle.group), selectinload(CRMKBArticle.creator),
                      selectinload(CRMKBArticle.feedback))
             .order_by(CRMKBArticle.group_id, CRMKBArticle.sort_order, CRMKBArticle.subject))
    if group_id is not None:
        query = query.where(CRMKBArticle.group_id == group_id)
    if active is not None:
        query = query.where(CRMKBArticle.active == active)
    if staff_only is not None:
        query = query.where(CRMKBArticle.staff_only == staff_only)
    if q:
        query = query.where(or_(
            CRMKBArticle.subject.ilike(f"%{q}%"),
            CRMKBArticle.description.ilike(f"%{q}%"),
        ))
    r = await db.execute(query)
    return [_article_dict(a) for a in r.scalars().all()]


@router.get("/api/kb/articles/{aid}")
async def get_kb_article(aid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(CRMKBArticle).where(CRMKBArticle.id == aid)
        .options(selectinload(CRMKBArticle.group), selectinload(CRMKBArticle.creator),
                 selectinload(CRMKBArticle.feedback))
    )
    a = r.scalar_one_or_none()
    if not a:
        raise HTTPException(404)
    return _article_dict(a)


@router.post("/api/kb/articles")
async def create_kb_article(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    subject = req.get("subject", "").strip()
    if not subject:
        raise HTTPException(400, "Subject required")
    slug = _kb_slug(subject)
    existing = await db.execute(select(CRMKBArticle).where(CRMKBArticle.slug == slug))
    if existing.scalar_one_or_none():
        slug = f"{slug}-{secrets.token_hex(3)}"
    a = CRMKBArticle(
        subject=subject, slug=slug,
        group_id=req.get("group_id"),
        description=req.get("description"),
        active=req.get("active", True),
        staff_only=req.get("staff_only", False),
        sort_order=req.get("sort_order", 0),
        created_by=staff.id,
        updated_at=_utcnow(),
    )
    db.add(a)
    await db.flush()
    return {"id": a.id, "slug": a.slug}


@router.put("/api/kb/articles/{aid}")
async def update_kb_article(aid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMKBArticle).where(CRMKBArticle.id == aid))
    a = r.scalar_one_or_none()
    if not a:
        raise HTTPException(404)
    for f in ("subject", "group_id", "description", "active", "staff_only", "sort_order"):
        if f in req:
            setattr(a, f, req[f])
    a.updated_at = _utcnow()
    return {"ok": True}


@router.delete("/api/kb/articles/{aid}")
async def delete_kb_article(aid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMKBArticle).where(CRMKBArticle.id == aid))
    return {"ok": True}


@router.post("/api/kb/articles/{aid}/feedback")
async def submit_kb_feedback(aid: int, req: dict, request: Request, db: AsyncSession = Depends(get_db)):
    vote = req.get("vote")
    if vote not in ("helpful", "not_helpful"):
        raise HTTPException(400, "vote must be helpful or not_helpful")
    ip = request.client.host if request.client else None
    fb = CRMKBArticleFeedback(article_id=aid, vote=vote, ip=ip)
    db.add(fb)
    return {"ok": True}


# ── Customer Vault ────────────────────────────────────────────────────────────

def _vault_encrypt(plaintext: str) -> str:
    """XOR-based symmetric encryption using VAULT_KEY env var (base64 key)."""
    key = os.environ.get("VAULT_KEY", "uplinx-vault-default-key-32chars!")
    key_bytes = (key * 10).encode()[:32]
    data = plaintext.encode()
    encrypted = bytes(b ^ key_bytes[i % 32] for i, b in enumerate(data))
    return _b64.b64encode(encrypted).decode()


def _vault_decrypt(ciphertext: str) -> str:
    key = os.environ.get("VAULT_KEY", "uplinx-vault-default-key-32chars!")
    key_bytes = (key * 10).encode()[:32]
    encrypted = _b64.b64decode(ciphertext.encode())
    data = bytes(b ^ key_bytes[i % 32] for i, b in enumerate(encrypted))
    return data.decode()


def _vault_dict(v: CRMVaultEntry, reveal: bool = False) -> dict:
    pw = None
    if reveal and v.password_encrypted:
        try:
            pw = _vault_decrypt(v.password_encrypted)
        except Exception:
            pw = None
    return {
        "id": v.id, "client_id": v.client_id,
        "server_address": v.server_address, "port": v.port,
        "username": v.username,
        "password": pw if reveal else ("••••••••" if v.password_encrypted else None),
        "description": v.description,
        "visibility": v.visibility, "share_in_projects": v.share_in_projects,
        "created_by": v.created_by,
        "creator_name": v.creator.full_name if v.creator else None,
        "last_updated_at": v.last_updated_at.isoformat() if v.last_updated_at else None,
        "last_updated_by_name": v.updater.full_name if v.updater else None,
        "created_at": v.created_at.isoformat(),
        "access_user_ids": [a.user_id for a in (v.access or [])],
    }


@router.get("/api/customers/{cid}/vault")
async def list_vault_entries(cid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(CRMVaultEntry).where(CRMVaultEntry.client_id == cid)
        .options(selectinload(CRMVaultEntry.creator), selectinload(CRMVaultEntry.updater),
                 selectinload(CRMVaultEntry.access))
        .order_by(desc(CRMVaultEntry.created_at))
    )
    return [_vault_dict(v) for v in r.scalars().all()]


@router.post("/api/customers/{cid}/vault")
async def create_vault_entry(cid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    pw_plain = req.get("password")
    v = CRMVaultEntry(
        client_id=cid,
        server_address=req.get("server_address"),
        port=req.get("port"),
        username=req.get("username"),
        password_encrypted=_vault_encrypt(pw_plain) if pw_plain else None,
        description=req.get("description"),
        visibility=req.get("visibility", "team"),
        share_in_projects=req.get("share_in_projects", False),
        created_by=staff.id,
    )
    db.add(v)
    await db.flush()
    await _log(db, staff, "vault", "created", v.id, req.get("description") or req.get("server_address"))
    return {"id": v.id}


@router.put("/api/customers/{cid}/vault/{vid}")
async def update_vault_entry(cid: int, vid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMVaultEntry).where(CRMVaultEntry.id == vid, CRMVaultEntry.client_id == cid))
    v = r.scalar_one_or_none()
    if not v:
        raise HTTPException(404)
    for f in ("server_address", "port", "username", "description", "visibility", "share_in_projects"):
        if f in req:
            setattr(v, f, req[f])
    if "password" in req and req["password"]:
        v.password_encrypted = _vault_encrypt(req["password"])
    v.last_updated_at = _utcnow()
    v.last_updated_by = staff.id
    await _log(db, staff, "vault", "updated", v.id, v.description or v.server_address)
    return {"ok": True}


@router.delete("/api/customers/{cid}/vault/{vid}")
async def delete_vault_entry(cid: int, vid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMVaultEntry).where(CRMVaultEntry.id == vid, CRMVaultEntry.client_id == cid))
    v = r.scalar_one_or_none()
    if not v:
        raise HTTPException(404)
    await _log(db, staff, "vault", "deleted", v.id, v.description or v.server_address)
    await db.execute(delete(CRMVaultEntry).where(CRMVaultEntry.id == vid))
    return {"ok": True}


class VaultRevealReq(BaseModel):
    password: str


@router.post("/api/customers/{cid}/vault/{vid}/reveal")
async def reveal_vault_entry(cid: int, vid: int, req: VaultRevealReq,
                              staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not _verify_pw(req.password, staff.hashed_password or ""):
        raise HTTPException(403, "Invalid password")
    r = await db.execute(
        select(CRMVaultEntry).where(CRMVaultEntry.id == vid, CRMVaultEntry.client_id == cid)
        .options(selectinload(CRMVaultEntry.creator), selectinload(CRMVaultEntry.updater),
                 selectinload(CRMVaultEntry.access))
    )
    v = r.scalar_one_or_none()
    if not v:
        raise HTTPException(404)
    await _log(db, staff, "vault", "revealed", v.id, v.description or v.server_address)
    return _vault_dict(v, reveal=True)


# ── Calendar aggregation ───────────────────────────────────────────────────────

@router.get("/api/calendar/all-events")
async def get_all_calendar_events(
    year: int, month: int,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Return all date-significant items across the CRM for the given month."""
    from_d = datetime(year, month, 1, tzinfo=timezone.utc)
    if month == 12:
        to_d = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        to_d = datetime(year, month + 1, 1, tzinfo=timezone.utc)

    events = []

    # Custom events
    ev_r = await db.execute(
        select(CRMEvent).where(CRMEvent.start_date >= from_d, CRMEvent.start_date < to_d)
    )
    for e in ev_r.scalars().all():
        events.append({
            "id": f"event-{e.id}", "source": "event", "title": e.title,
            "start": e.start_date.isoformat(), "end": e.end_date.isoformat() if e.end_date else None,
            "color": e.color, "description": e.description,
        })

    # Invoice due dates
    inv_r = await db.execute(
        select(CRMInvoice).where(CRMInvoice.due_date >= from_d, CRMInvoice.due_date < to_d,
                                  CRMInvoice.status.notin_(["paid", "cancelled"]))
        .options(selectinload(CRMInvoice.customer))
    )
    for inv in inv_r.scalars().all():
        events.append({
            "id": f"inv-{inv.id}", "source": "invoice", "color": "#ef4444",
            "title": f"Invoice Due: {inv.customer.company_name if inv.customer else inv.formatted_number}",
            "start": inv.due_date.isoformat(), "end": None,
            "description": f"Invoice {inv.formatted_number}",
        })

    # Contract start/end dates
    cont_r = await db.execute(
        select(CRMContract).where(
            or_(
                (CRMContract.start_date >= from_d) & (CRMContract.start_date < to_d),
                (CRMContract.end_date >= from_d) & (CRMContract.end_date < to_d),
            ),
            CRMContract.trashed == False,
        ).options(selectinload(CRMContract.customer))
    )
    for c in cont_r.scalars().all():
        if c.start_date and from_d <= c.start_date < to_d:
            events.append({
                "id": f"cont-start-{c.id}", "source": "contract", "color": "#10b981",
                "title": f"Contract Start: {c.customer.company_name if c.customer else c.subject}",
                "start": c.start_date.isoformat(), "end": None, "description": c.subject,
            })
        if c.end_date and from_d <= c.end_date < to_d:
            events.append({
                "id": f"cont-end-{c.id}", "source": "contract", "color": "#f59e0b",
                "title": f"Contract End: {c.customer.company_name if c.customer else c.subject}",
                "start": c.end_date.isoformat(), "end": None, "description": c.subject,
            })

    # Project deadlines
    proj_r = await db.execute(
        select(CRMProject).where(
            CRMProject.deadline >= from_d, CRMProject.deadline < to_d,
            CRMProject.status != "finished",
        ).options(selectinload(CRMProject.customer))
    )
    for p in proj_r.scalars().all():
        events.append({
            "id": f"proj-{p.id}", "source": "project", "color": "#8b5cf6",
            "title": f"Project Deadline: {p.name}",
            "start": p.deadline.isoformat(), "end": None,
            "description": p.customer.company_name if p.customer else None,
        })

    # Task due dates
    task_r = await db.execute(
        select(CRMTask).where(
            CRMTask.due_date >= from_d, CRMTask.due_date < to_d,
            CRMTask.is_done == False,
        )
    )
    for t in task_r.scalars().all():
        events.append({
            "id": f"task-{t.id}", "source": "task", "color": "#6366f1",
            "title": f"Task Due: {t.name}",
            "start": t.due_date.isoformat(), "end": None, "description": None,
        })

    # Proposal expiry
    prop_r = await db.execute(
        select(CRMProposal).where(
            CRMProposal.open_till >= from_d, CRMProposal.open_till < to_d,
            CRMProposal.status.notin_(["accepted", "declined"]),
        ).options(selectinload(CRMProposal.customer))
    )
    for p in prop_r.scalars().all():
        events.append({
            "id": f"prop-{p.id}", "source": "proposal", "color": "#ec4899",
            "title": f"Proposal Expires: {p.customer.company_name if p.customer else p.formatted_number}",
            "start": p.open_till.isoformat(), "end": None,
            "description": f"Proposal {p.formatted_number}",
        })

    return sorted(events, key=lambda x: x["start"])


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
    items = [
        {"id": a.id, "module": a.module, "action": a.action, "record_id": a.record_id,
         "record_name": a.record_name, "description": a.description,
         "user_name": a.staff.full_name if a.staff else "System",
         "read": True,  # activity log items are not unread
         "created_at": a.created_at.isoformat()}
        for a in r.scalars().all()
    ]
    return {"items": items, "total": len(items)}


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

def _template_dict(t: CRMEmailTemplate, full: bool = False) -> dict:
    d = {"id": t.id, "group": t.group, "name": t.name, "slug": t.slug,
         "subject": t.subject, "is_active": t.is_active,
         "from_name": t.from_name, "from_email": t.from_email,
         "plain_text": t.plain_text,
         "updated_at": t.updated_at.isoformat() if t.updated_at else None}
    if full:
        d["body"] = t.body
    return d


@router.get("/api/email-templates")
async def list_email_templates(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEmailTemplate).order_by(CRMEmailTemplate.group, CRMEmailTemplate.name))
    result: dict = {}
    for t in r.scalars().all():
        result.setdefault(t.group, []).append(_template_dict(t))
    return result


@router.get("/api/email-templates/{tid}")
async def get_email_template(tid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEmailTemplate).where(CRMEmailTemplate.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    return _template_dict(t, full=True)


@router.put("/api/email-templates/{tid}")
async def update_email_template(tid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEmailTemplate).where(CRMEmailTemplate.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    for f in ("subject", "body", "is_active", "from_name", "from_email", "plain_text"):
        if f in req:
            setattr(t, f, req[f])
    t.updated_at = _utcnow()
    return {"ok": True}


@router.post("/api/email-templates/{tid}/restore-default")
async def restore_template_default(tid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMEmailTemplate).where(CRMEmailTemplate.id == tid))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    if t.default_body:
        t.body = t.default_body
    if t.default_subject:
        t.subject = t.default_subject
    t.from_name = None
    t.from_email = None
    t.plain_text = False
    t.is_active = True
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


# ── Tags ──────────────────────────────────────────────────────────────────────

@router.get("/api/tags")
async def list_tags(
    q: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    query = select(CRMTag).order_by(CRMTag.name)
    if q:
        query = query.where(CRMTag.name.ilike(f"%{q}%"))
    r = await db.execute(query)
    tags = r.scalars().all()
    result = []
    for tag in tags:
        cnt = await db.execute(select(func.count()).select_from(CRMTaggable).where(CRMTaggable.tag_id == tag.id))
        result.append({"id": tag.id, "name": tag.name, "color": tag.color, "usage": cnt.scalar() or 0})
    return result


@router.post("/api/tags")
async def create_tag(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(CRMTag).where(CRMTag.name == req["name"]))
    t = existing.scalar_one_or_none()
    if t:
        return {"id": t.id, "name": t.name}
    t = CRMTag(name=req["name"], color=req.get("color", "#6366f1"))
    db.add(t)
    await db.flush()
    return {"id": t.id, "name": t.name}


@router.put("/api/tags/{tag_id}")
async def update_tag(tag_id: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMTag).where(CRMTag.id == tag_id))
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    if "name" in req:
        t.name = req["name"]
    if "color" in req:
        t.color = req["color"]
    return {"ok": True}


@router.delete("/api/tags/{tag_id}")
async def delete_tag(tag_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not staff.is_admin:
        raise HTTPException(403)
    await db.execute(delete(CRMTaggable).where(CRMTaggable.tag_id == tag_id))
    await db.execute(delete(CRMTag).where(CRMTag.id == tag_id))
    return {"ok": True}


@router.post("/api/tags/merge")
async def merge_tags(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Merge source_id into target_id."""
    if not staff.is_admin:
        raise HTTPException(403)
    source_id = req["source_id"]
    target_id = req["target_id"]
    taggables = await db.execute(select(CRMTaggable).where(CRMTaggable.tag_id == source_id))
    for tb in taggables.scalars().all():
        exists = await db.execute(select(CRMTaggable).where(
            CRMTaggable.tag_id == target_id, CRMTaggable.rel_id == tb.rel_id, CRMTaggable.rel_type == tb.rel_type
        ))
        if not exists.scalar_one_or_none():
            db.add(CRMTaggable(tag_id=target_id, rel_id=tb.rel_id, rel_type=tb.rel_type))
    await db.execute(delete(CRMTaggable).where(CRMTaggable.tag_id == source_id))
    await db.execute(delete(CRMTag).where(CRMTag.id == source_id))
    return {"ok": True}


@router.get("/api/taggables")
async def get_taggables(rel_type: str, rel_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(CRMTaggable).where(CRMTaggable.rel_type == rel_type, CRMTaggable.rel_id == rel_id)
        .options(selectinload(CRMTaggable.tag)).order_by(CRMTaggable.tag_order)
    )
    return [{"id": tb.tag.id, "name": tb.tag.name, "color": tb.tag.color} for tb in r.scalars().all()]


@router.post("/api/taggables")
async def set_taggables(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Set tags on an entity (replaces existing). tag_ids: list of ints."""
    rel_type = req["rel_type"]
    rel_id = req["rel_id"]
    tag_ids = req.get("tag_ids", [])
    await db.execute(delete(CRMTaggable).where(CRMTaggable.rel_type == rel_type, CRMTaggable.rel_id == rel_id))
    for i, tid in enumerate(tag_ids):
        db.add(CRMTaggable(tag_id=tid, rel_id=rel_id, rel_type=rel_type, tag_order=i))
    return {"ok": True}


# ── Custom Fields ─────────────────────────────────────────────────────────────

_CF_ENTITIES = [
    "customers", "contacts", "leads", "invoices", "estimates", "proposals",
    "contracts", "projects", "tasks", "tickets", "expenses", "subscriptions",
    "credit_notes", "staff",
]
_CF_TYPES = ["input", "textarea", "select", "multi-select", "checkbox", "date", "datetime", "number", "link", "color"]


class CustomFieldReq(BaseModel):
    field_to: str
    name: str
    slug: Optional[str] = None
    field_type: str = "input"
    options: Optional[str] = None
    default_value: Optional[str] = None
    required: bool = False
    active: bool = True
    display_inline: bool = False
    bs_col_width: int = 12
    show_on_pdf: bool = False
    show_on_ticket_form: bool = False
    only_admin: bool = False
    show_on_table: bool = False
    show_on_client_portal: bool = False
    disallow_client_edit: bool = False
    field_order: int = 0


def _slug(name: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


@router.get("/api/custom-fields")
async def list_custom_fields(
    field_to: Optional[str] = None,
    field_type: Optional[str] = None,
    active: Optional[bool] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(CRMCustomField).order_by(CRMCustomField.field_to, CRMCustomField.field_order, CRMCustomField.name)
    if field_to:
        q = q.where(CRMCustomField.field_to == field_to)
    if field_type:
        q = q.where(CRMCustomField.field_type == field_type)
    if active is not None:
        q = q.where(CRMCustomField.active == active)
    r = await db.execute(q)
    return [_cf_dict(f) for f in r.scalars().all()]


def _cf_dict(f: CRMCustomField) -> dict:
    return {
        "id": f.id, "field_to": f.field_to, "name": f.name, "slug": f.slug,
        "field_type": f.field_type, "options": f.options, "default_value": f.default_value,
        "required": f.required, "active": f.active, "display_inline": f.display_inline,
        "bs_col_width": f.bs_col_width, "show_on_pdf": f.show_on_pdf,
        "show_on_ticket_form": f.show_on_ticket_form, "only_admin": f.only_admin,
        "show_on_table": f.show_on_table, "show_on_client_portal": f.show_on_client_portal,
        "disallow_client_edit": f.disallow_client_edit, "field_order": f.field_order,
        "created_at": f.created_at.isoformat(),
    }


@router.post("/api/custom-fields")
async def create_custom_field(req: CustomFieldReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not staff.is_admin:
        raise HTTPException(403)
    if req.field_to not in _CF_ENTITIES:
        raise HTTPException(400, f"Invalid field_to. Must be one of: {', '.join(_CF_ENTITIES)}")
    if req.field_type not in _CF_TYPES:
        raise HTTPException(400, f"Invalid field_type")
    slug = req.slug or _slug(req.name)
    f = CRMCustomField(
        field_to=req.field_to, name=req.name, slug=slug, field_type=req.field_type,
        options=req.options, default_value=req.default_value, required=req.required,
        active=req.active, display_inline=req.display_inline, bs_col_width=req.bs_col_width,
        show_on_pdf=req.show_on_pdf, show_on_ticket_form=req.show_on_ticket_form,
        only_admin=req.only_admin, show_on_table=req.show_on_table,
        show_on_client_portal=req.show_on_client_portal, disallow_client_edit=req.disallow_client_edit,
        field_order=req.field_order,
    )
    db.add(f)
    await db.flush()
    await _log(db, staff, "custom_fields", "created", f.id, f.name)
    return {"id": f.id}


@router.put("/api/custom-fields/{fid}")
async def update_custom_field(fid: int, req: CustomFieldReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not staff.is_admin:
        raise HTTPException(403)
    r = await db.execute(select(CRMCustomField).where(CRMCustomField.id == fid))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404)
    for k, v in req.model_dump(exclude_unset=True).items():
        if k == "slug" and not v:
            v = _slug(req.name)
        setattr(f, k, v)
    return {"ok": True}


@router.delete("/api/custom-fields/{fid}")
async def delete_custom_field(fid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not staff.is_admin:
        raise HTTPException(403)
    await db.execute(delete(CRMCustomField).where(CRMCustomField.id == fid))
    return {"ok": True}


@router.put("/api/custom-fields/{fid}/order")
async def reorder_custom_field(fid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMCustomField).where(CRMCustomField.id == fid))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404)
    f.field_order = req.get("field_order", 0)
    return {"ok": True}


@router.get("/api/custom-field-values")
async def get_custom_field_values(rel_type: str, rel_id: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(CRMCustomFieldValue).where(CRMCustomFieldValue.rel_type == rel_type, CRMCustomFieldValue.rel_id == rel_id)
        .options(selectinload(CRMCustomFieldValue.field))
    )
    return [{"field_id": v.field_id, "field_name": v.field.name, "value": v.value} for v in r.scalars().all()]


@router.post("/api/custom-field-values")
async def save_custom_field_values(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Save all custom field values for an entity. values: {field_id: value}."""
    rel_type = req["rel_type"]
    rel_id = req["rel_id"]
    values = req.get("values", {})
    for field_id, value in values.items():
        existing = await db.execute(select(CRMCustomFieldValue).where(
            CRMCustomFieldValue.field_id == int(field_id),
            CRMCustomFieldValue.rel_id == rel_id,
            CRMCustomFieldValue.rel_type == rel_type,
        ))
        ev = existing.scalar_one_or_none()
        if ev:
            ev.value = str(value) if value is not None else None
        else:
            db.add(CRMCustomFieldValue(field_id=int(field_id), rel_id=rel_id, rel_type=rel_type,
                                       value=str(value) if value is not None else None))
    return {"ok": True}


# ── Reminders ─────────────────────────────────────────────────────────────────

class ReminderReq(BaseModel):
    description: str
    remind_at: str
    notify_staff: Optional[list] = None
    notify_by_email: bool = True
    rel_id: Optional[int] = None
    rel_type: Optional[str] = None


@router.get("/api/reminders")
async def list_reminders(
    status: Optional[str] = None,  # pending|notified
    rel_type: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = (select(CRMReminder)
         .where(CRMReminder.notify_staff.contains([staff.id]))
         .options(selectinload(CRMReminder.creator))
         .order_by(CRMReminder.remind_at))
    if status == "pending":
        q = q.where(CRMReminder.is_notified == False)
    elif status == "notified":
        q = q.where(CRMReminder.is_notified == True)
    if rel_type:
        q = q.where(CRMReminder.rel_type == rel_type)
    r = await db.execute(q)
    return [_reminder_dict(rem) for rem in r.scalars().all()]


def _reminder_dict(rem: CRMReminder) -> dict:
    return {
        "id": rem.id, "description": rem.description,
        "remind_at": rem.remind_at.isoformat(),
        "rel_id": rem.rel_id, "rel_type": rem.rel_type,
        "notify_staff": rem.notify_staff or [],
        "notify_by_email": rem.notify_by_email,
        "is_notified": rem.is_notified,
        "notified_at": rem.notified_at.isoformat() if rem.notified_at else None,
        "created_by": rem.creator.full_name if rem.creator else None,
        "created_at": rem.created_at.isoformat(),
    }


@router.post("/api/reminders")
async def create_reminder(req: ReminderReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    notify = req.notify_staff if req.notify_staff else [staff.id]
    rem = CRMReminder(
        description=req.description,
        remind_at=datetime.fromisoformat(req.remind_at),
        notify_staff=notify, notify_by_email=req.notify_by_email,
        rel_id=req.rel_id, rel_type=req.rel_type,
        created_by=staff.id,
    )
    db.add(rem)
    await db.flush()
    return {"id": rem.id}


@router.put("/api/reminders/{rid}")
async def update_reminder(rid: int, req: ReminderReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMReminder).where(CRMReminder.id == rid))
    rem = r.scalar_one_or_none()
    if not rem:
        raise HTTPException(404)
    rem.description = req.description
    rem.remind_at = datetime.fromisoformat(req.remind_at)
    rem.notify_staff = req.notify_staff or [staff.id]
    rem.notify_by_email = req.notify_by_email
    rem.is_notified = False
    rem.notified_at = None
    return {"ok": True}


@router.delete("/api/reminders/{rid}")
async def delete_reminder(rid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMReminder).where(CRMReminder.id == rid))
    return {"ok": True}


@router.post("/api/reminders/{rid}/dismiss")
async def dismiss_reminder(rid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMReminder).where(CRMReminder.id == rid))
    rem = r.scalar_one_or_none()
    if not rem:
        raise HTTPException(404)
    rem.is_notified = True
    rem.notified_at = _utcnow()
    return {"ok": True}


# ── Polymorphic Notes ─────────────────────────────────────────────────────────

class PolyNoteReq(BaseModel):
    description: str
    date_contacted: Optional[str] = None
    rel_id: int
    rel_type: str


@router.get("/api/notes")
async def list_poly_notes(
    rel_type: str, rel_id: int,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(
        select(CRMPolyNote)
        .where(CRMPolyNote.rel_type == rel_type, CRMPolyNote.rel_id == rel_id)
        .options(selectinload(CRMPolyNote.author))
        .order_by(desc(CRMPolyNote.dateadded))
    )
    return [
        {
            "id": n.id, "description": n.description,
            "date_contacted": n.date_contacted.isoformat() if n.date_contacted else None,
            "author": n.author.full_name if n.author else "?",
            "dateadded": n.dateadded.isoformat(),
        }
        for n in r.scalars().all()
    ]


@router.post("/api/notes")
async def create_poly_note(req: PolyNoteReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    n = CRMPolyNote(
        rel_id=req.rel_id, rel_type=req.rel_type, description=req.description,
        date_contacted=datetime.fromisoformat(req.date_contacted) if req.date_contacted else None,
        addedfrom=staff.id,
    )
    db.add(n)
    await db.flush()
    return {"id": n.id}


@router.put("/api/notes/{nid}")
async def update_poly_note(nid: int, req: PolyNoteReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMPolyNote).where(CRMPolyNote.id == nid))
    n = r.scalar_one_or_none()
    if not n:
        raise HTTPException(404)
    n.description = req.description
    if req.date_contacted:
        n.date_contacted = datetime.fromisoformat(req.date_contacted)
    return {"ok": True}


@router.delete("/api/notes/{nid}")
async def delete_poly_note(nid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMPolyNote).where(CRMPolyNote.id == nid))
    return {"ok": True}


# ── Files ─────────────────────────────────────────────────────────────────────

@router.get("/api/files")
async def list_files(
    rel_type: str, rel_id: int,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(
        select(CRMFile)
        .where(CRMFile.rel_type == rel_type, CRMFile.rel_id == rel_id)
        .options(selectinload(CRMFile.uploader))
        .order_by(desc(CRMFile.dateadded))
    )
    return [
        {
            "id": f.id, "file_name": f.file_name, "filetype": f.filetype,
            "visible_to_customer": f.visible_to_customer, "external": f.external,
            "external_link": f.external_link, "thumbnail_link": f.thumbnail_link,
            "uploader": f.uploader.full_name if f.uploader else None,
            "dateadded": f.dateadded.isoformat(),
        }
        for f in r.scalars().all()
    ]


@router.post("/api/files/external")
async def add_external_file(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    f = CRMFile(
        rel_id=req["rel_id"], rel_type=req["rel_type"],
        file_name=req["file_name"], filetype=req.get("filetype"),
        external=req.get("external"), external_link=req.get("external_link"),
        visible_to_customer=req.get("visible_to_customer", False),
        staffid=staff.id,
    )
    db.add(f)
    await db.flush()
    return {"id": f.id}


@router.put("/api/files/{fid}/visibility")
async def toggle_file_visibility(fid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMFile).where(CRMFile.id == fid))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404)
    f.visible_to_customer = req.get("visible_to_customer", not f.visible_to_customer)
    return {"visible_to_customer": f.visible_to_customer}


@router.delete("/api/files/{fid}")
async def delete_file(fid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMFile).where(CRMFile.id == fid))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404)
    if f.attachment_key and not f.external:
        import os
        path = Path("uploads") / f.attachment_key
        if path.exists():
            os.unlink(path)
    await db.execute(delete(CRMFile).where(CRMFile.id == fid))
    return {"ok": True}


# ── Saved Filters ─────────────────────────────────────────────────────────────

@router.get("/api/filters")
async def list_filters(
    identifier: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(CRMFilter).where(
        (CRMFilter.staff_id == staff.id) | (CRMFilter.is_shared == True)
    ).order_by(CRMFilter.name)
    if identifier:
        q = q.where(CRMFilter.identifier == identifier)
    r = await db.execute(q)
    return [
        {"id": f.id, "name": f.name, "identifier": f.identifier,
         "builder": f.builder, "is_shared": f.is_shared,
         "is_mine": f.staff_id == staff.id}
        for f in r.scalars().all()
    ]


@router.post("/api/filters")
async def save_filter(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    f = CRMFilter(
        name=req["name"], identifier=req["identifier"],
        builder=req.get("builder"), staff_id=staff.id,
        is_shared=req.get("is_shared", False),
    )
    db.add(f)
    await db.flush()
    return {"id": f.id}


@router.delete("/api/filters/{fid}")
async def delete_filter(fid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMFilter).where(CRMFilter.id == fid))
    f = r.scalar_one_or_none()
    if not f or (f.staff_id != staff.id and not staff.is_admin):
        raise HTTPException(403)
    await db.execute(delete(CRMFilter).where(CRMFilter.id == fid))
    return {"ok": True}


@router.post("/api/filters/{fid}/set-default")
async def set_default_filter(fid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    identifier = req["identifier"]
    existing = await db.execute(select(CRMFilterDefault).where(
        CRMFilterDefault.staff_id == staff.id, CRMFilterDefault.identifier == identifier
    ))
    fd = existing.scalar_one_or_none()
    if fd:
        fd.filter_id = fid
    else:
        db.add(CRMFilterDefault(filter_id=fid, staff_id=staff.id, identifier=identifier))
    return {"ok": True}


# ── Notifications ─────────────────────────────────────────────────────────────

@router.get("/api/notifications")
async def list_notifications(
    limit: int = 20,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = (select(CRMNotification)
         .where(CRMNotification.touserid == staff.id)
         .order_by(desc(CRMNotification.date))
         .limit(limit))
    r = await db.execute(q)
    items = [
        {
            "id": n.id, "description": n.description, "isread": n.isread,
            "from_fullname": n.from_fullname, "link": n.link,
            "date": n.date.isoformat(),
        }
        for n in r.scalars().all()
    ]
    unread = sum(1 for n in items if not n["isread"])
    return {"items": items, "unread": unread}


@router.post("/api/notifications/mark-all-read")
async def mark_all_notifications_read(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(
        update(CRMNotification).where(CRMNotification.touserid == staff.id).values(isread=True)
    )
    return {"ok": True}


@router.post("/api/notifications/{nid}/read")
async def mark_notification_read(nid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMNotification).where(CRMNotification.id == nid, CRMNotification.touserid == staff.id))
    n = r.scalar_one_or_none()
    if n:
        n.isread = True
    return {"ok": True}


# ── Sales Activity ────────────────────────────────────────────────────────────

@router.get("/api/sales-activity")
async def list_sales_activity(
    rel_type: str, rel_id: int,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(
        select(CRMSalesActivity)
        .where(CRMSalesActivity.rel_type == rel_type, CRMSalesActivity.rel_id == rel_id)
        .order_by(desc(CRMSalesActivity.date))
        .limit(100)
    )
    return [
        {"id": a.id, "description": a.description, "full_name": a.full_name,
         "additional_data": a.additional_data, "date": a.date.isoformat()}
        for a in r.scalars().all()
    ]


# ── Mail Queue ────────────────────────────────────────────────────────────────

@router.get("/api/mail-queue")
async def list_mail_queue(
    status: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    if not staff.is_admin:
        raise HTTPException(403)
    q = select(CRMMailQueue).order_by(desc(CRMMailQueue.date)).limit(200)
    if status:
        q = q.where(CRMMailQueue.status == status)
    r = await db.execute(q)
    return [
        {"id": m.id, "email": m.email, "subject": m.subject, "status": m.status,
         "retries": m.retries, "date": m.date.isoformat()}
        for m in r.scalars().all()
    ]


@router.post("/api/mail-queue/{mid}/retry")
async def retry_mail(mid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not staff.is_admin:
        raise HTTPException(403)
    r = await db.execute(select(CRMMailQueue).where(CRMMailQueue.id == mid))
    m = r.scalar_one_or_none()
    if not m:
        raise HTTPException(404)
    m.status = "pending"
    m.retries = 0
    return {"ok": True}


@router.delete("/api/mail-queue/{mid}")
async def delete_mail_queue_item(mid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    if not staff.is_admin:
        raise HTTPException(403)
    await db.execute(delete(CRMMailQueue).where(CRMMailQueue.id == mid))
    return {"ok": True}


# ── Tracked Mails ─────────────────────────────────────────────────────────────

@router.get("/api/tracked-mails/pixel/{uid}")
async def mail_open_pixel(uid: str, db: AsyncSession = Depends(get_db)):
    """1x1 tracking pixel endpoint — records mail open."""
    from fastapi.responses import Response as _Resp
    r = await db.execute(select(CRMTrackedMail).where(CRMTrackedMail.uid == uid))
    tm = r.scalar_one_or_none()
    if tm and not tm.opened:
        tm.opened = True
        tm.date_opened = _utcnow()
        await db.commit()
    pixel = b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
    return _Resp(content=pixel, media_type="image/gif", headers={"Cache-Control": "no-store, no-cache"})


@router.get("/api/tracked-mails")
async def list_tracked_mails(
    rel_type: Optional[str] = None, rel_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    q = select(CRMTrackedMail).order_by(desc(CRMTrackedMail.date)).limit(100)
    if rel_type:
        q = q.where(CRMTrackedMail.rel_type == rel_type)
    if rel_id:
        q = q.where(CRMTrackedMail.rel_id == rel_id)
    r = await db.execute(q)
    return [
        {"id": m.id, "email": m.email, "subject": m.subject, "opened": m.opened,
         "date": m.date.isoformat(),
         "date_opened": m.date_opened.isoformat() if m.date_opened else None}
        for m in r.scalars().all()
    ]


# ── Scheduled Emails ──────────────────────────────────────────────────────────

class ScheduledEmailReq(BaseModel):
    rel_id: int
    rel_type: str
    scheduled_at: str
    contacts: Optional[list] = None
    cc: Optional[str] = None
    attach_pdf: bool = True
    template: Optional[str] = None


@router.get("/api/scheduled-emails")
async def list_scheduled_emails(
    rel_type: Optional[str] = None, rel_id: Optional[int] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    q = select(CRMScheduledEmail).order_by(CRMScheduledEmail.scheduled_at)
    if rel_type:
        q = q.where(CRMScheduledEmail.rel_type == rel_type)
    if rel_id:
        q = q.where(CRMScheduledEmail.rel_id == rel_id)
    r = await db.execute(q)
    return [
        {"id": s.id, "rel_id": s.rel_id, "rel_type": s.rel_type, "status": s.status,
         "scheduled_at": s.scheduled_at.isoformat(), "template": s.template,
         "attach_pdf": s.attach_pdf, "contacts": s.contacts or []}
        for s in r.scalars().all()
    ]


@router.post("/api/scheduled-emails")
async def create_scheduled_email(req: ScheduledEmailReq, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    s = CRMScheduledEmail(
        rel_id=req.rel_id, rel_type=req.rel_type,
        scheduled_at=datetime.fromisoformat(req.scheduled_at),
        contacts=req.contacts or [], cc=req.cc,
        attach_pdf=req.attach_pdf, template=req.template,
        created_by=staff.id,
    )
    db.add(s)
    await db.flush()
    return {"id": s.id}


@router.delete("/api/scheduled-emails/{sid}")
async def cancel_scheduled_email(sid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMScheduledEmail).where(CRMScheduledEmail.id == sid))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    s.status = "cancelled"
    return {"ok": True}


# ── Module 31: Meta Ads App Connection ────────────────────────────────────────

def _internal_key_ok(request: Request) -> bool:
    key = os.environ.get("INTERNAL_API_KEY", "")
    if not key:
        return False
    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {key}"


# ── Internal endpoints (consumed by the Meta Ads app) ─────────────────────────

class InternalAuthReq(BaseModel):
    username: str
    password: str


@router.post("/api/internal/auth/verify")
async def internal_auth_verify(req: InternalAuthReq, request: Request, db: AsyncSession = Depends(get_db)):
    """Verify a Meta Ads app user's credentials. Returns user info on success."""
    if not _internal_key_ok(request):
        raise HTTPException(401, "Unauthorized")
    row = (await db.execute(text("SELECT id, username, email, hashed_password, role, is_active FROM users WHERE username = :u"), {"u": req.username})).fetchone()
    if not row or not row[5]:
        raise HTTPException(401, "Invalid credentials")
    if not _verify_pw(req.password, row[3] or ""):
        raise HTTPException(401, "Invalid credentials")
    return {"id": row[0], "username": row[1], "email": row[2], "role": row[4]}


@router.get("/api/internal/users/me")
async def internal_users_me(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Get Meta Ads app user info by id."""
    if not _internal_key_ok(request):
        raise HTTPException(401, "Unauthorized")
    row = (await db.execute(text("SELECT id, username, email, role, interface_access, is_active FROM users WHERE id = :uid"), {"uid": user_id})).fetchone()
    if not row:
        raise HTTPException(404, "User not found")
    return {"id": row[0], "username": row[1], "email": row[2], "role": row[3], "interface_access": row[4], "is_active": row[5]}


@router.get("/api/internal/clients")
async def internal_clients(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Get clients accessible by a Meta Ads app user."""
    if not _internal_key_ok(request):
        raise HTTPException(401, "Unauthorized")
    user_row = (await db.execute(text("SELECT id, role FROM users WHERE id = :uid AND is_active = TRUE"), {"uid": user_id})).fetchone()
    if not user_row:
        raise HTTPException(404, "User not found")
    if user_row[1] == "admin":
        rows = (await db.execute(text("SELECT id, name, industry, website, color_tag, is_archived FROM clients ORDER BY sort_order, name"))).fetchall()
    else:
        rows = (await db.execute(text(
            "SELECT c.id, c.name, c.industry, c.website, c.color_tag, c.is_archived "
            "FROM clients c JOIN user_client_assignments uca ON uca.client_id = c.id "
            "WHERE uca.user_id = :uid ORDER BY c.sort_order, c.name"
        ), {"uid": user_id})).fetchall()
    return [{"id": r[0], "name": r[1], "industry": r[2], "website": r[3], "color_tag": r[4], "is_archived": r[5]} for r in rows]


# ── CRM admin endpoints: connection status & data sync ────────────────────────

@router.get("/api/meta-ads-connection/status")
async def meta_ads_connection_status(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Returns counts from both the Meta Ads app tables and CRM tables."""
    # Meta Ads app side
    try:
        app_users = (await db.execute(text("SELECT COUNT(*) FROM users"))).scalar() or 0
    except Exception:
        app_users = None
    try:
        app_clients = (await db.execute(text("SELECT COUNT(*) FROM clients"))).scalar() or 0
    except Exception:
        app_clients = None
    try:
        app_assignments = (await db.execute(text("SELECT COUNT(*) FROM user_client_assignments"))).scalar() or 0
    except Exception:
        app_assignments = None
    # CRM side
    crm_staff = (await db.execute(select(func.count()).select_from(StaffMember))).scalar() or 0
    crm_customers = (await db.execute(select(func.count()).select_from(CRMCustomer))).scalar() or 0
    crm_access = (await db.execute(select(func.count()).select_from(CRMUserAppClientAccess))).scalar() or 0
    # Check view exists
    try:
        await db.execute(text("SELECT 1 FROM user_app_access_view LIMIT 1"))
        view_ok = True
    except Exception:
        view_ok = False
    internal_key_set = bool(os.environ.get("INTERNAL_API_KEY", ""))
    return {
        "database_shared": True,
        "view_created": view_ok,
        "internal_key_configured": internal_key_set,
        "meta_ads_app": {"users": app_users, "clients": app_clients, "assignments": app_assignments},
        "crm": {"staff": crm_staff, "customers": crm_customers, "app_client_access": crm_access},
    }


class SyncOptions(BaseModel):
    overwrite_existing: bool = False


@router.post("/api/meta-ads-connection/sync-users")
async def meta_ads_sync_users(opts: SyncOptions, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Import users from the Meta Ads app into crm_staff. Skips existing emails."""
    if not staff.is_admin:
        raise HTTPException(403, "Admin only")
    rows = (await db.execute(text("SELECT id, username, email, hashed_password, role, is_active FROM users"))).fetchall()
    imported = 0
    skipped = 0
    errors = []
    for row in rows:
        uid, uname, email, pwd, role, active = row
        if not email:
            email = f"{uname}@meta-ads-import.local"
        try:
            existing = (await db.execute(select(StaffMember).where(StaffMember.email == email))).scalar_one_or_none()
            if existing and not opts.overwrite_existing:
                skipped += 1
                continue
            if existing and opts.overwrite_existing:
                if pwd:
                    existing.hashed_password = pwd
                skipped += 1
                continue
            fname, lname = (uname.split(" ", 1) + [""])[:2]
            if not lname:
                lname = uname
                fname = uname.split(".")[0].capitalize() if "." in uname else uname
            new_staff = StaffMember(
                first_name=fname, last_name=lname,
                email=email,
                hashed_password=pwd or _hash_pw(secrets.token_urlsafe(16)),
                is_admin=(role == "admin"),
            )
            db.add(new_staff)
            imported += 1
        except Exception as e:
            errors.append(f"User {uid}: {e}")
    await db.commit()
    return {"imported": imported, "skipped": skipped, "errors": errors}


@router.post("/api/meta-ads-connection/sync-clients")
async def meta_ads_sync_clients(opts: SyncOptions, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Import clients from the Meta Ads app into crm_customers. Skips existing names."""
    if not staff.is_admin:
        raise HTTPException(403, "Admin only")
    rows = (await db.execute(text("SELECT id, name, industry, website, notes, color_tag FROM clients WHERE is_archived = FALSE"))).fetchall()
    imported = 0
    skipped = 0
    errors = []
    for row in rows:
        cid, name, industry, website, notes, color = row
        try:
            existing = (await db.execute(select(CRMCustomer).where(CRMCustomer.company == name))).scalar_one_or_none()
            if existing and not opts.overwrite_existing:
                skipped += 1
                continue
            if existing and opts.overwrite_existing:
                skipped += 1
                continue
            new_cust = CRMCustomer(
                company=name,
                industry=industry or "",
                website=website or "",
                notes=notes or "",
                created_by=staff.id,
            )
            db.add(new_cust)
            imported += 1
        except Exception as e:
            errors.append(f"Client {cid}: {e}")
    await db.commit()
    return {"imported": imported, "skipped": skipped, "errors": errors}


@router.post("/api/meta-ads-connection/sync-access")
async def meta_ads_sync_access(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    """Copy user_client_assignments into crm_user_app_client_access for the meta-ads-upload app."""
    if not staff.is_admin:
        raise HTTPException(403, "Admin only")
    app_row = (await db.execute(select(CRMApp).where(CRMApp.key == "meta-ads-upload"))).scalar_one_or_none()
    if not app_row:
        raise HTTPException(404, "meta-ads-upload app record not found in CRM")
    assignments = (await db.execute(text("SELECT user_id, client_id FROM user_client_assignments"))).fetchall()
    imported = 0
    skipped = 0
    errors = []
    for user_id_old, client_id_old in assignments:
        try:
            # Map old user_id → crm_staff by looking up matching email from users table
            user_row = (await db.execute(text("SELECT username, email FROM users WHERE id = :uid"), {"uid": user_id_old})).fetchone()
            if not user_row:
                skipped += 1
                continue
            email = user_row[1] or f"{user_row[0]}@meta-ads-import.local"
            staff_row = (await db.execute(select(StaffMember).where(StaffMember.email == email))).scalar_one_or_none()
            if not staff_row:
                skipped += 1
                continue
            # Map old client_id → crm_customer by matching name
            client_row = (await db.execute(text("SELECT name FROM clients WHERE id = :cid"), {"cid": client_id_old})).fetchone()
            if not client_row:
                skipped += 1
                continue
            cust_row = (await db.execute(select(CRMCustomer).where(CRMCustomer.company == client_row[0]))).scalar_one_or_none()
            if not cust_row:
                skipped += 1
                continue
            # Ensure app access exists
            uaa = (await db.execute(
                select(CRMUserAppAccess).where(CRMUserAppAccess.staff_id == staff_row.id, CRMUserAppAccess.app_id == app_row.id)
            )).scalar_one_or_none()
            if not uaa:
                uaa = CRMUserAppAccess(staff_id=staff_row.id, app_id=app_row.id, granted_by=staff.id)
                db.add(uaa)
                await db.flush()
            # Check if access already exists
            existing_acc = (await db.execute(
                select(CRMUserAppClientAccess).where(
                    CRMUserAppClientAccess.staff_id == staff_row.id,
                    CRMUserAppClientAccess.app_id == app_row.id,
                    CRMUserAppClientAccess.client_id == cust_row.id,
                )
            )).scalar_one_or_none()
            if existing_acc:
                skipped += 1
                continue
            db.add(CRMUserAppClientAccess(staff_id=staff_row.id, app_id=app_row.id, client_id=cust_row.id))
            imported += 1
        except Exception as e:
            errors.append(f"Assignment {user_id_old}→{client_id_old}: {e}")
    await db.commit()
    return {"imported": imported, "skipped": skipped, "errors": errors}


# ── DB initialisation ─────────────────────────────────────────────────────────

async def init_admin_db(engine) -> None:
    """Create all admin CRM tables and seed default data."""
    from sqlalchemy.ext.asyncio import AsyncConnection
    async with engine.begin() as conn:
        await conn.run_sync(AdminBase.metadata.create_all)

    # ── Schema migrations: each runs in its own connection so one failure can't abort others ──
    _migrations = [
        # crm_roles
        "ALTER TABLE crm_roles ADD COLUMN IF NOT EXISTS description TEXT",
        # crm_staff — Module 03 additions
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS timezone VARCHAR(64) NOT NULL DEFAULT 'UTC'",
        # crm_staff — unified login: username column (login by email OR username)
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS username VARCHAR(150)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_crm_staff_username ON crm_staff (username)",
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS last_ip VARCHAR(45)",
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS last_password_change_at TIMESTAMP",
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP",
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN NOT NULL DEFAULT false",
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS password_reset_token VARCHAR(128)",
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS password_reset_expires TIMESTAMP",
        "ALTER TABLE crm_staff ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
        # crm_customers — Module 08 additions
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS billing_address TEXT",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS billing_city VARCHAR(100)",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS billing_state VARCHAR(100)",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS billing_zip VARCHAR(20)",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS billing_country VARCHAR(100)",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS shipping_address TEXT",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS shipping_city VARCHAR(100)",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS shipping_state VARCHAR(100)",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS shipping_zip VARCHAR(20)",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS shipping_country VARCHAR(100)",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS converted_from_lead_id INTEGER",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS created_by INTEGER",
        "ALTER TABLE crm_customers ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
        # crm_contacts — Module 08 additions
        "ALTER TABLE crm_contacts ADD COLUMN IF NOT EXISTS can_login BOOLEAN NOT NULL DEFAULT false",
        "ALTER TABLE crm_contacts ADD COLUMN IF NOT EXISTS hashed_password TEXT",
        "ALTER TABLE crm_contacts ADD COLUMN IF NOT EXISTS email_opt_ins TEXT",
        # crm_line_items — Module 12 additions
        "ALTER TABLE crm_line_items ADD COLUMN IF NOT EXISTS estimate_id INTEGER",
        # crm_invoices — Module 15 additions
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS number INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS prefix VARCHAR(20) NOT NULL DEFAULT 'INV'",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS formatted_number VARCHAR(50) NOT NULL DEFAULT ''",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS sale_agent_id INTEGER",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS billing_address TEXT",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS shipping_address TEXT",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS discount_total DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS allowed_payment_modes TEXT",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS subscription_id INTEGER",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS hash VARCHAR(32)",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS last_overdue_reminder_at TIMESTAMP",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS last_due_reminder_at TIMESTAMP",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS cancel_overdue_reminders BOOLEAN NOT NULL DEFAULT false",
        "ALTER TABLE crm_invoices ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
        # crm_proposals — Module 14 additions
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS number INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS prefix VARCHAR(20) NOT NULL DEFAULT 'PROP'",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS formatted_number VARCHAR(50) NOT NULL DEFAULT ''",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS sale_agent_id INTEGER",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS proposal_to TEXT",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS billing_address TEXT",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS shipping_address TEXT",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS pipeline_order INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS discount_total DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS content TEXT",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS allow_comments BOOLEAN NOT NULL DEFAULT false",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS admin_note TEXT",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS hash VARCHAR(32)",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS acceptance_first_name VARCHAR(100)",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS acceptance_last_name VARCHAR(100)",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS acceptance_email VARCHAR(255)",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS acceptance_date TIMESTAMP",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS acceptance_ip VARCHAR(45)",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS signature_image TEXT",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS converted_to_invoice_id INTEGER",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS converted_at TIMESTAMP",
        "ALTER TABLE crm_proposals ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
        # crm_payment_modes — Module 16 additions
        "ALTER TABLE crm_payment_modes ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE crm_payment_modes ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true",
        "ALTER TABLE crm_payment_modes ADD COLUMN IF NOT EXISTS show_on_pdf BOOLEAN NOT NULL DEFAULT false",
        "ALTER TABLE crm_payment_modes ADD COLUMN IF NOT EXISTS selected_by_default BOOLEAN NOT NULL DEFAULT false",
        "ALTER TABLE crm_payment_modes ADD COLUMN IF NOT EXISTS invoices_only BOOLEAN NOT NULL DEFAULT false",
        "ALTER TABLE crm_payment_modes ADD COLUMN IF NOT EXISTS expenses_only BOOLEAN NOT NULL DEFAULT false",
        # crm_payments — Module 16 additions
        "ALTER TABLE crm_payments ADD COLUMN IF NOT EXISTS payment_method VARCHAR(255)",
        "ALTER TABLE crm_payments ADD COLUMN IF NOT EXISTS created_by_user_id INTEGER",
        # crm_line_items — Module 17 addition
        "ALTER TABLE crm_line_items ADD COLUMN IF NOT EXISTS credit_note_id INTEGER",
        # crm_expense_categories — Module 19 addition
        "ALTER TABLE crm_expense_categories ADD COLUMN IF NOT EXISTS description TEXT",
        # crm_expenses — Module 19 additions
        "ALTER TABLE crm_expenses ADD COLUMN IF NOT EXISTS tax_id_2 INTEGER",
        "ALTER TABLE crm_expenses ADD COLUMN IF NOT EXISTS invoice_id INTEGER",
        # crm_contracts — Module 20 additions
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS content TEXT",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS signed BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS marked_as_signed BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS acceptance_first_name VARCHAR(100)",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS acceptance_last_name VARCHAR(100)",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS acceptance_email VARCHAR(200)",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS acceptance_date TIMESTAMP",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS acceptance_ip VARCHAR(50)",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS acceptance_signature TEXT",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS hash VARCHAR(64)",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS trashed BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS not_visible_to_client BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS last_sent_at TIMESTAMP",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS last_sign_reminder_at TIMESTAMP",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS is_expiry_notified BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS tags JSON",
        "ALTER TABLE crm_contracts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP",
        # crm_projects — Module 21 additions
        "ALTER TABLE crm_projects ADD COLUMN IF NOT EXISTS rate_per_hour FLOAT",
        "ALTER TABLE crm_projects ADD COLUMN IF NOT EXISTS project_cost FLOAT",
        "ALTER TABLE crm_projects ADD COLUMN IF NOT EXISTS date_finished TIMESTAMP",
        # crm_email_templates — Module 29 additions
        "ALTER TABLE crm_email_templates ADD COLUMN IF NOT EXISTS from_name VARCHAR(100)",
        "ALTER TABLE crm_email_templates ADD COLUMN IF NOT EXISTS from_email VARCHAR(200)",
        "ALTER TABLE crm_email_templates ADD COLUMN IF NOT EXISTS plain_text BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE crm_email_templates ADD COLUMN IF NOT EXISTS default_body TEXT",
        "ALTER TABLE crm_email_templates ADD COLUMN IF NOT EXISTS default_subject VARCHAR(255)",
        # crm_goals — Module 27 (tables auto-created; extra safety)
        "ALTER TABLE crm_goals ADD COLUMN IF NOT EXISTS all_staff BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE crm_goals ADD COLUMN IF NOT EXISTS notify_on_success BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE crm_goals ADD COLUMN IF NOT EXISTS notify_on_failure BOOLEAN NOT NULL DEFAULT FALSE",
        # crm_kb_articles — Module 24 additions (tables auto-created; extra safety)
        "ALTER TABLE crm_kb_articles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP",
        # crm_vault_entries — Module 25 additions (tables auto-created; extra safety)
        "ALTER TABLE crm_vault_entries ADD COLUMN IF NOT EXISTS last_updated_at TIMESTAMP",
        "ALTER TABLE crm_vault_entries ADD COLUMN IF NOT EXISTS last_updated_by INTEGER",
        # Module 31 — shared access view (drop-then-create for idempotency)
        "DROP VIEW IF EXISTS user_app_access_view",
        "CREATE VIEW user_app_access_view AS SELECT uca.staff_id AS user_id, a.key AS app_key, uca.client_id FROM crm_user_app_client_access uca JOIN crm_apps a ON a.id = uca.app_id",
    ]
    for _sql in _migrations:
        try:
            async with engine.begin() as _conn:
                await _conn.execute(text(_sql))
        except Exception as _me:
            logger.debug("Migration skipped (%s): %s", type(_me).__name__, _sql)

    # Seed from a short session
    from sqlalchemy.ext.asyncio import AsyncSession as _AS, async_sessionmaker as _asm
    session_factory = _asm(bind=engine, expire_on_commit=False)
    async with session_factory() as db:
        # Default roles
        roles_exist = await db.execute(select(func.count()).select_from(CRMRole))
        if (roles_exist.scalar() or 0) == 0:
            for rname, rdesc, rperms in _DEFAULT_ROLES:
                db.add(CRMRole(name=rname, description=rdesc, permissions=rperms))

        # Seed Meta Ads app record
        app_exist = await db.execute(select(func.count()).select_from(CRMApp))
        if (app_exist.scalar() or 0) == 0:
            from config import settings as _s
            base = _s.BASE_URL.rstrip("/")
            db.add(CRMApp(
                key="meta-ads-upload",
                name="Meta Ads Upload",
                description="Upload and manage Meta (Facebook/Instagram) ad campaigns for clients.",
                icon="fa-solid fa-rectangle-ad",
                base_url=base,
                is_active=True,
            ))

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

        # Default estimate request statuses (Module 13)
        ers_exist = await db.execute(select(func.count()).select_from(CRMEstimateRequestStatus))
        if (ers_exist.scalar() or 0) == 0:
            for i, (name, color, flag) in enumerate([
                ("Processing", "#3b82f6", "processing"),
                ("Completed",  "#10b981", "completed"),
                ("Cancelled",  "#ef4444", "cancelled"),
            ]):
                db.add(CRMEstimateRequestStatus(name=name, color=color, flag=flag, statusorder=i))

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

        # Default ticket priorities
        tp_exist = await db.execute(select(func.count()).select_from(CRMTicketPriority))
        if (tp_exist.scalar() or 0) == 0:
            for i, (name, color) in enumerate([("Low", "#10b981"), ("Medium", "#f59e0b"), ("High", "#ef4444")]):
                db.add(CRMTicketPriority(name=name, color=color, sort_order=i))

        # Default ticket statuses
        ts_exist = await db.execute(select(func.count()).select_from(CRMTicketStatus))
        if (ts_exist.scalar() or 0) == 0:
            for i, (name, color, is_def) in enumerate([
                ("Open", "#6366f1", True), ("In Progress", "#3b82f6", False),
                ("Answered", "#10b981", False), ("On Hold", "#f59e0b", False), ("Closed", "#94a3b8", False),
            ]):
                db.add(CRMTicketStatus(name=name, color=color, sort_order=i, is_default=is_def))

        # Default ticket departments
        td_exist = await db.execute(select(func.count()).select_from(CRMTicketDepartment))
        if (td_exist.scalar() or 0) == 0:
            for name in ["General Support", "Billing", "Technical"]:
                db.add(CRMTicketDepartment(name=name))

        # Default ticket services
        tsv_exist = await db.execute(select(func.count()).select_from(CRMTicketService))
        if (tsv_exist.scalar() or 0) == 0:
            for name in ["Meta Ads", "Google Ads", "SEO", "Social Media", "Other"]:
                db.add(CRMTicketService(name=name))

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

        # Seed email templates
        et_exist = await db.execute(select(func.count()).select_from(CRMEmailTemplate))
        if (et_exist.scalar() or 0) == 0:
            _DEFAULT_TEMPLATES = [
                # Client
                ("client", "New Client Created", "new-client-created",
                 "Welcome to {company_name}", "<p>Hi {contact_first_name},</p><p>Your account has been created at <strong>{company_name}</strong>. You can log in at {crm_url}.</p><p>Regards,<br>{company_name}</p>"),
                ("client", "Contact Forgot Password", "contact-forgot-password",
                 "Reset your password", "<p>Hi {contact_first_name},</p><p>Click the link below to reset your password:</p><p><a href='{reset_password_url}'>{reset_password_url}</a></p><p>This link expires in 2 hours.</p>"),
                ("client", "Client Statement", "client-statement",
                 "Account Statement — {company_name}", "<p>Hi {contact_first_name},</p><p>Please find attached your account statement for <strong>{client_company}</strong>.</p>"),
                # Lead
                ("lead", "New Lead Assigned", "new-lead-assigned",
                 "New lead assigned to you: {lead_name}", "<p>Hi {staff_first_name},</p><p>A new lead has been assigned to you: <strong>{lead_name}</strong>.</p><p><a href='{lead_link}'>View Lead</a></p>"),
                ("lead", "New Web-to-Lead Submission", "new-web-to-lead-form-submitted",
                 "New Lead Form Submission", "<p>A new lead has been submitted via the website contact form.</p><p><strong>Name:</strong> {lead_name}<br><strong>Email:</strong> {lead_email}</p><p><a href='{lead_link}'>View in CRM</a></p>"),
                # Estimate
                ("estimate", "Send Estimate to Client", "estimate-send-to-client",
                 "Estimate #{estimate_number} from {company_name}", "<p>Hi {contact_first_name},</p><p>Please find your estimate below.</p><p><strong>Estimate #:</strong> {estimate_number}<br><strong>Total:</strong> {estimate_total}<br><strong>Expires:</strong> {estimate_expiry_date}</p><p><a href='{estimate_link}'>View Estimate</a></p>"),
                ("estimate", "Estimate Expiry Reminder", "estimate-expiry-reminder",
                 "Your estimate #{estimate_number} is expiring soon", "<p>Hi {contact_first_name},</p><p>Your estimate <strong>#{estimate_number}</strong> from {company_name} expires soon on <strong>{estimate_expiry_date}</strong>.</p><p><a href='{estimate_link}'>View Estimate</a></p>"),
                # Proposal
                ("proposal", "Send Proposal to Client", "proposal-send-to-customer",
                 "Proposal: {proposal_subject}", "<p>Hi {contact_first_name},</p><p>We have prepared a proposal for you.</p><p><strong>Subject:</strong> {proposal_subject}<br><strong>Total:</strong> {proposal_total}<br><strong>Valid until:</strong> {proposal_open_till}</p><p><a href='{proposal_link}'>View Proposal</a></p>"),
                ("proposal", "Proposal Accepted — to Staff", "proposal-client-accepted",
                 "Proposal #{proposal_number} accepted", "<p>{contact_first_name} {contact_last_name} has accepted proposal #{proposal_number}.</p><p><a href='{proposal_link}'>View Proposal</a></p>"),
                ("proposal", "Proposal Declined — to Staff", "proposal-client-declined",
                 "Proposal #{proposal_number} declined", "<p>{contact_first_name} {contact_last_name} has declined proposal #{proposal_number}.</p><p><a href='{proposal_link}'>View Proposal</a></p>"),
                # Invoice
                ("invoice", "Send Invoice to Client", "invoice-send-to-client",
                 "Invoice #{invoice_number} from {company_name}", "<p>Hi {contact_first_name},</p><p>Please find your invoice attached.</p><p><strong>Invoice #:</strong> {invoice_number}<br><strong>Due Date:</strong> {invoice_due_date}<br><strong>Amount Due:</strong> {invoice_due_amount}</p><p><a href='{invoice_link}'>View &amp; Pay Invoice</a></p>"),
                ("invoice", "Invoice Payment Recorded", "invoice-payment-recorded",
                 "Payment received for Invoice #{invoice_number}", "<p>Hi {contact_first_name},</p><p>Thank you — we have received your payment for Invoice <strong>#{invoice_number}</strong>.</p>"),
                ("invoice", "Invoice Overdue Notice", "invoice-overdue-notice",
                 "Invoice #{invoice_number} is overdue", "<p>Hi {contact_first_name},</p><p>Invoice <strong>#{invoice_number}</strong> (Amount: {invoice_due_amount}) is now overdue.</p><p>Please make payment at your earliest convenience: <a href='{invoice_link}'>{invoice_link}</a></p>"),
                ("invoice", "Invoice Due Reminder", "invoice-due-notice",
                 "Invoice #{invoice_number} due soon", "<p>Hi {contact_first_name},</p><p>A friendly reminder that Invoice <strong>#{invoice_number}</strong> (Amount: {invoice_due_amount}) is due on <strong>{invoice_due_date}</strong>.</p><p><a href='{invoice_link}'>Pay Now</a></p>"),
                # Credit Note
                ("credit_note", "Send Credit Note to Client", "credit-note-send-to-client",
                 "Credit Note #{credit_note_number} from {company_name}", "<p>Hi {contact_first_name},</p><p>A credit note has been issued to your account.</p><p><strong>Credit Note #:</strong> {credit_note_number}<br><strong>Date:</strong> {credit_note_date}<br><strong>Amount:</strong> {credit_note_total}</p>"),
                # Contract
                ("contract", "Send Contract to Client", "send-contract",
                 "Contract for review: {contract_subject}", "<p>Hi {contact_first_name},</p><p>Please review and sign the following contract:</p><p><strong>Subject:</strong> {contract_subject}<br><strong>Value:</strong> {contract_value}<br><strong>Period:</strong> {contract_start_date} – {contract_end_date}</p><p><a href='{contract_link}'>View &amp; Sign Contract</a></p>"),
                ("contract", "Contract Signed — to Staff", "contract-signed-to-staff",
                 "Contract signed: {contract_subject}", "<p>The contract <strong>{contract_subject}</strong> has been signed by the client.</p><p><a href='{contract_link}'>View Contract</a></p>"),
                ("contract", "Contract Expiry Reminder", "contract-expiration",
                 "Contract expiring soon: {contract_subject}", "<p>Hi {contact_first_name},</p><p>Your contract <strong>{contract_subject}</strong> is expiring on <strong>{contract_end_date}</strong>.</p>"),
                # Project
                ("project", "Assigned to Project", "assigned-to-project",
                 "You have been assigned to project: {project_name}", "<p>Hi {staff_first_name},</p><p>You have been assigned to the project <strong>{project_name}</strong>.</p><p><a href='{project_link}'>View Project</a></p>"),
                ("project", "Project Finished — to Customer", "project-finished-to-customer",
                 "Project {project_name} is complete!", "<p>Hi {contact_first_name},</p><p>Great news! Your project <strong>{project_name}</strong> has been marked as complete.</p>"),
                # Task
                ("task", "Task Assigned", "task-assigned",
                 "Task assigned: {task_name}", "<p>Hi {staff_first_name},</p><p>A task has been assigned to you: <strong>{task_name}</strong>.</p><p><strong>Due:</strong> {task_due_date}<br><strong>Priority:</strong> {task_priority}</p><p><a href='{task_link}'>View Task</a></p>"),
                ("task", "Task Deadline Notification", "task-deadline-notification",
                 "Task due soon: {task_name}", "<p>Hi {staff_first_name},</p><p>The task <strong>{task_name}</strong> is due on <strong>{task_due_date}</strong>.</p>"),
                # Ticket
                ("ticket", "New Ticket — to Admin", "new-ticket-opened-admin",
                 "New support ticket: {ticket_subject}", "<p>A new support ticket has been opened.</p><p><strong>ID:</strong> {ticket_id}<br><strong>Subject:</strong> {ticket_subject}<br><strong>Department:</strong> {ticket_department}<br><strong>Priority:</strong> {ticket_priority}</p><p><a href='{ticket_url}'>View Ticket</a></p>"),
                ("ticket", "Ticket Auto-Response", "ticket-autoresponse",
                 "We received your ticket: {ticket_subject}", "<p>Hi,</p><p>Thank you for contacting us. We have received your support request and will get back to you shortly.</p><p><strong>Ticket ID:</strong> {ticket_id}<br><strong>Subject:</strong> {ticket_subject}</p>"),
                ("ticket", "Ticket Reply", "ticket-reply",
                 "Re: {ticket_subject} [#{ticket_id}]", "<p>Hi,</p><p>There has been a new reply to your support ticket.</p><p><a href='{ticket_url}'>View Ticket</a></p>"),
                # Staff
                ("staff", "New Staff Created", "new-staff-created",
                 "Welcome to {company_name}", "<p>Hi {staff_first_name},</p><p>Your staff account has been created at <strong>{company_name}</strong>.</p><p><strong>Email:</strong> {staff_email}<br><strong>Password:</strong> {password}</p><p>Please log in and change your password immediately.</p>"),
                ("staff", "Staff Forgot Password", "staff-forgot-password",
                 "Reset your password", "<p>Hi {staff_first_name},</p><p>Click the link below to reset your password:</p><p><a href='{reset_password_url}'>{reset_password_url}</a></p><p>This link expires in 2 hours. If you did not request this, ignore this email.</p>"),
                # GDPR
                ("gdpr", "GDPR Removal Request", "gdpr-removal-request",
                 "Data Removal Request from {contact_first_name} {contact_last_name}", "<p>A data removal request has been submitted by:</p><p><strong>Name:</strong> {contact_first_name} {contact_last_name}<br><strong>Email:</strong> {contact_email}</p><p>Please review and process this request in accordance with your data protection policy.</p>"),
            ]
            for grp, name, slug, subject, body in _DEFAULT_TEMPLATES:
                db.add(CRMEmailTemplate(
                    group=grp, name=name, slug=slug,
                    subject=subject, body=body,
                    default_subject=subject, default_body=body,
                    is_active=True,
                ))

        # ── Unified login migration ──────────────────────────────────────
        # The CRM (crm_staff) is the single source of truth for identity.
        # Copy any existing Meta Ads app users (the `users` table) into
        # crm_staff so they can sign in to the CRM with the SAME credentials.
        # Idempotent: matches on username OR email and never overwrites or
        # deletes anything in the Meta Ads app — it only links/back-fills.
        try:
            meta_users = (await db.execute(text(
                "SELECT id, username, email, hashed_password, role, is_active FROM users"
            ))).fetchall()
            for mu in meta_users:
                muid, m_username, m_email, m_pwd, m_role, m_active = mu
                if not m_username and not m_email:
                    continue
                # Already linked? (match by username or email, case-insensitive)
                match_conds = []
                if m_username:
                    match_conds.append(StaffMember.username == m_username)
                if m_email:
                    match_conds.append(func.lower(StaffMember.email) == m_email.lower())
                existing = (await db.execute(
                    select(StaffMember).where(or_(*match_conds))
                )).scalars().first()
                if existing:
                    # Back-fill username link if missing so future logins match.
                    if m_username and not existing.username:
                        existing.username = m_username
                    continue
                # Derive a sensible name + a guaranteed-unique email.
                base_name = (m_username or (m_email.split("@")[0] if m_email else "user"))
                fname = base_name.split(".")[0].capitalize() if "." in base_name else base_name
                lname = base_name.split(".", 1)[1].capitalize() if "." in base_name else ""
                email = m_email or f"{base_name}@meta-ads-import.local"
                db.add(StaffMember(
                    first_name=fname or base_name,
                    last_name=lname or base_name,
                    email=email,
                    username=m_username,
                    hashed_password=m_pwd or _hash_pw(secrets.token_urlsafe(16)),
                    is_admin=(m_role == "admin"),
                    is_active=bool(m_active) if m_active is not None else True,
                ))
        except Exception as _mig_e:
            logger.debug("Meta users → crm_staff migration skipped: %s", _mig_e)

        await db.commit()


# ── Goals ─────────────────────────────────────────────────────────────────────

GOAL_TYPES = [
    "invoiced_amount", "paid_revenue", "leads_converted",
    "new_clients", "hours_logged", "projects_completed",
]


async def _compute_goal_achieved(goal: CRMGoal, db: AsyncSession) -> float:
    """Compute current achieved value for a goal based on its type and date range."""
    uid_filter = []
    if not goal.all_staff and goal.assigned_user_ids:
        uid_filter = goal.assigned_user_ids

    def date_cond(col):
        conds = []
        if goal.start_date:
            conds.append(col >= goal.start_date)
        if goal.end_date:
            conds.append(col <= goal.end_date)
        return conds

    if goal.goal_type == "invoiced_amount":
        q = select(func.coalesce(func.sum(CRMInvoice.subtotal + CRMInvoice.tax_total - CRMInvoice.discount_total), 0.0))
        for c in date_cond(CRMInvoice.created_at):
            q = q.where(c)
        return float((await db.execute(q)).scalar() or 0)

    if goal.goal_type == "paid_revenue":
        q = select(func.coalesce(func.sum(CRMPayment.amount), 0.0)).where(CRMPayment.status == "completed")
        for c in date_cond(CRMPayment.created_at):
            q = q.where(c)
        if uid_filter:
            q = q.where(CRMPayment.created_by_user_id.in_(uid_filter))
        return float((await db.execute(q)).scalar() or 0)

    if goal.goal_type == "leads_converted":
        q = select(func.count()).select_from(CRMLead).where(CRMLead.status_id.isnot(None))
        for c in date_cond(CRMLead.created_at):
            q = q.where(c)
        if uid_filter:
            q = q.where(CRMLead.assigned_to.in_(uid_filter))
        return float((await db.execute(q)).scalar() or 0)

    if goal.goal_type == "new_clients":
        q = select(func.count()).select_from(CRMCustomer)
        for c in date_cond(CRMCustomer.created_at):
            q = q.where(c)
        return float((await db.execute(q)).scalar() or 0)

    if goal.goal_type == "hours_logged":
        q = select(func.coalesce(func.sum(CRMTimesheet.duration), 0.0)).where(CRMTimesheet.end_time.isnot(None))
        for c in date_cond(CRMTimesheet.start_time):
            q = q.where(c)
        if uid_filter:
            q = q.where(CRMTimesheet.staff_id.in_(uid_filter))
        return float((await db.execute(q)).scalar() or 0)

    if goal.goal_type == "projects_completed":
        q = select(func.count()).select_from(CRMProject).where(CRMProject.status == "finished")
        for c in date_cond(CRMProject.created_at):
            q = q.where(c)
        return float((await db.execute(q)).scalar() or 0)

    return 0.0


def _goal_dict(g: CRMGoal, achieved: float = 0.0) -> dict:
    pct = min(100.0, round(achieved / g.target_value * 100, 1)) if g.target_value else 0.0
    return {
        "id": g.id, "subject": g.subject, "goal_type": g.goal_type,
        "target_value": g.target_value, "achieved_value": achieved, "percent": pct,
        "start_date": g.start_date.isoformat() if g.start_date else None,
        "end_date": g.end_date.isoformat() if g.end_date else None,
        "assigned_user_ids": g.assigned_user_ids or [],
        "all_staff": g.all_staff, "status": g.status,
        "notify_on_success": g.notify_on_success,
        "notify_on_failure": g.notify_on_failure,
        "contract_type_id": g.contract_type_id,
        "created_at": g.created_at.isoformat(),
    }


@router.get("/api/goals")
async def list_goals(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    goals = (await db.execute(select(CRMGoal).order_by(desc(CRMGoal.created_at)))).scalars().all()
    result = []
    for g in goals:
        achieved = await _compute_goal_achieved(g, db)
        result.append(_goal_dict(g, achieved))
    return result


@router.post("/api/goals")
async def create_goal(req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    g = CRMGoal(
        subject=req.get("subject", "Goal"),
        goal_type=req.get("goal_type", "paid_revenue"),
        target_value=float(req.get("target_value", 0)),
        start_date=datetime.fromisoformat(req["start_date"]) if req.get("start_date") else None,
        end_date=datetime.fromisoformat(req["end_date"]) if req.get("end_date") else None,
        all_staff=req.get("all_staff", True),
        assigned_user_ids=req.get("assigned_user_ids", []),
        status=req.get("status", "active"),
        notify_on_success=req.get("notify_on_success", True),
        notify_on_failure=req.get("notify_on_failure", False),
        contract_type_id=req.get("contract_type_id"),
        created_by=staff.id,
    )
    db.add(g)
    await db.flush()
    return {"id": g.id}


@router.put("/api/goals/{gid}")
async def update_goal(gid: int, req: dict, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CRMGoal).where(CRMGoal.id == gid))
    g = r.scalar_one_or_none()
    if not g:
        raise HTTPException(404)
    for f in ("subject", "goal_type", "all_staff", "assigned_user_ids", "status",
              "notify_on_success", "notify_on_failure", "contract_type_id"):
        if f in req:
            setattr(g, f, req[f])
    if "target_value" in req:
        g.target_value = float(req["target_value"])
    if "start_date" in req:
        g.start_date = datetime.fromisoformat(req["start_date"]) if req["start_date"] else None
    if "end_date" in req:
        g.end_date = datetime.fromisoformat(req["end_date"]) if req["end_date"] else None
    return {"ok": True}


@router.delete("/api/goals/{gid}")
async def delete_goal(gid: int, staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CRMGoal).where(CRMGoal.id == gid))
    return {"ok": True}


# ── Reports ────────────────────────────────────────────────────────────────────

@router.get("/api/reports/sales")
async def report_sales(
    from_date: Optional[str] = None, to_date: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    from_d = datetime.fromisoformat(from_date) if from_date else datetime(_utcnow().year, 1, 1, tzinfo=timezone.utc)
    to_d = datetime.fromisoformat(to_date) if to_date else _utcnow()

    # Monthly paid revenue
    monthly_r = await db.execute(
        select(extract("year", CRMPayment.created_at).label("yr"),
               extract("month", CRMPayment.created_at).label("mo"),
               func.sum(CRMPayment.amount).label("total"))
        .where(CRMPayment.created_at >= from_d, CRMPayment.created_at <= to_d,
               CRMPayment.status == "completed")
        .group_by("yr", "mo").order_by("yr", "mo")
    )
    monthly = [{"year": int(r.yr), "month": int(r.mo), "total": float(r.total or 0)} for r in monthly_r]

    # Top clients by revenue
    top_clients_r = await db.execute(
        select(CRMCustomer.company_name, func.sum(CRMPayment.amount).label("total"))
        .join(CRMInvoice, CRMPayment.invoice_id == CRMInvoice.id)
        .join(CRMCustomer, CRMInvoice.customer_id == CRMCustomer.id)
        .where(CRMPayment.created_at >= from_d, CRMPayment.created_at <= to_d,
               CRMPayment.status == "completed")
        .group_by(CRMCustomer.company_name).order_by(desc("total")).limit(10)
    )
    top_clients = [{"name": r[0], "total": float(r[1] or 0)} for r in top_clients_r]

    # Total summary
    total_invoiced_r = await db.execute(
        select(func.coalesce(func.sum(
            CRMInvoice.subtotal + CRMInvoice.tax_total - CRMInvoice.discount_total), 0.0))
        .where(CRMInvoice.created_at >= from_d, CRMInvoice.created_at <= to_d)
    )
    total_paid_r = await db.execute(
        select(func.coalesce(func.sum(CRMPayment.amount), 0.0))
        .where(CRMPayment.created_at >= from_d, CRMPayment.created_at <= to_d,
               CRMPayment.status == "completed")
    )
    outstanding_r = await db.execute(
        select(func.coalesce(func.sum(
            CRMInvoice.subtotal + CRMInvoice.tax_total - CRMInvoice.discount_total), 0.0))
        .where(CRMInvoice.status.in_(["unpaid", "partially_paid", "overdue"]),
               CRMInvoice.due_date <= _utcnow())
    )

    return {
        "from_date": from_d.isoformat(), "to_date": to_d.isoformat(),
        "monthly": monthly, "top_clients": top_clients,
        "total_invoiced": float(total_invoiced_r.scalar() or 0),
        "total_paid": float(total_paid_r.scalar() or 0),
        "outstanding": float(outstanding_r.scalar() or 0),
    }


@router.get("/api/reports/leads")
async def report_leads(
    from_date: Optional[str] = None, to_date: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    from_d = datetime.fromisoformat(from_date) if from_date else datetime(_utcnow().year, 1, 1, tzinfo=timezone.utc)
    to_d = datetime.fromisoformat(to_date) if to_date else _utcnow()

    base = select(CRMLead).where(CRMLead.created_at >= from_d, CRMLead.created_at <= to_d)

    # By source
    by_src_r = await db.execute(
        select(CRMLeadSource.name, func.count(CRMLead.id))
        .outerjoin(CRMLead, (CRMLead.source_id == CRMLeadSource.id) &
                   (CRMLead.created_at >= from_d) & (CRMLead.created_at <= to_d))
        .group_by(CRMLeadSource.name)
    )
    by_source = [{"source": r[0] or "Unknown", "count": r[1]} for r in by_src_r]

    # By status
    by_st_r = await db.execute(
        select(CRMLeadStatus.name, CRMLeadStatus.color, func.count(CRMLead.id))
        .outerjoin(CRMLead, (CRMLead.status_id == CRMLeadStatus.id) &
                   (CRMLead.created_at >= from_d) & (CRMLead.created_at <= to_d))
        .group_by(CRMLeadStatus.name, CRMLeadStatus.color)
    )
    by_status = [{"status": r[0], "color": r[1], "count": r[2]} for r in by_st_r]

    total = (await db.execute(select(func.count()).select_from(CRMLead)
                               .where(CRMLead.created_at >= from_d, CRMLead.created_at <= to_d))).scalar() or 0
    converted = (await db.execute(select(func.count()).select_from(CRMLead)
                                   .where(CRMLead.created_at >= from_d, CRMLead.created_at <= to_d,
                                          CRMLead.converted == True))).scalar() or 0

    return {
        "from_date": from_d.isoformat(), "to_date": to_d.isoformat(),
        "total": total, "converted": converted,
        "conversion_rate": round(converted / total * 100, 1) if total else 0,
        "by_source": by_source, "by_status": by_status,
    }


@router.get("/api/reports/leads-staff")
async def report_leads_staff(
    from_date: Optional[str] = None, to_date: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    from_d = datetime.fromisoformat(from_date) if from_date else datetime(_utcnow().year, 1, 1, tzinfo=timezone.utc)
    to_d = datetime.fromisoformat(to_date) if to_date else _utcnow()

    all_staff_r = await db.execute(select(StaffMember).where(StaffMember.is_active == True))
    all_staff_list = all_staff_r.scalars().all()
    result = []
    for s in all_staff_list:
        total_r = await db.execute(select(func.count()).select_from(CRMLead).where(
            CRMLead.assigned_to == s.id, CRMLead.created_at >= from_d, CRMLead.created_at <= to_d))
        conv_r = await db.execute(select(func.count()).select_from(CRMLead).where(
            CRMLead.assigned_to == s.id, CRMLead.created_at >= from_d, CRMLead.created_at <= to_d,
            CRMLead.converted == True))
        total = total_r.scalar() or 0
        conv = conv_r.scalar() or 0
        if total == 0:
            continue
        result.append({
            "staff_id": s.id, "full_name": s.full_name,
            "assigned": total, "converted": conv,
            "lost": total - conv,
            "rate": round(conv / total * 100, 1) if total else 0,
        })
    return sorted(result, key=lambda x: x["converted"], reverse=True)


@router.get("/api/reports/expenses")
async def report_expenses(
    from_date: Optional[str] = None, to_date: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    from_d = datetime.fromisoformat(from_date) if from_date else datetime(_utcnow().year, 1, 1, tzinfo=timezone.utc)
    to_d = datetime.fromisoformat(to_date) if to_date else _utcnow()

    by_cat_r = await db.execute(
        select(CRMExpenseCategory.name, func.sum(CRMExpense.amount).label("total"),
               func.count(CRMExpense.id).label("cnt"))
        .outerjoin(CRMExpense, (CRMExpense.category_id == CRMExpenseCategory.id) &
                   (CRMExpense.expense_date >= from_d) & (CRMExpense.expense_date <= to_d))
        .group_by(CRMExpenseCategory.name).order_by(desc("total"))
    )
    by_category = [{"category": r[0], "total": float(r[1] or 0), "count": r[2]} for r in by_cat_r]

    monthly_r = await db.execute(
        select(extract("year", CRMExpense.expense_date).label("yr"),
               extract("month", CRMExpense.expense_date).label("mo"),
               func.sum(CRMExpense.amount).label("total"))
        .where(CRMExpense.expense_date >= from_d, CRMExpense.expense_date <= to_d)
        .group_by("yr", "mo").order_by("yr", "mo")
    )
    monthly = [{"year": int(r.yr), "month": int(r.mo), "total": float(r.total or 0)} for r in monthly_r]

    total_r = await db.execute(
        select(func.coalesce(func.sum(CRMExpense.amount), 0.0))
        .where(CRMExpense.expense_date >= from_d, CRMExpense.expense_date <= to_d)
    )
    billable_r = await db.execute(
        select(func.coalesce(func.sum(CRMExpense.amount), 0.0))
        .where(CRMExpense.expense_date >= from_d, CRMExpense.expense_date <= to_d,
               CRMExpense.billable == True)
    )

    return {
        "from_date": from_d.isoformat(), "to_date": to_d.isoformat(),
        "total": float(total_r.scalar() or 0),
        "billable": float(billable_r.scalar() or 0),
        "by_category": by_category, "monthly": monthly,
    }


@router.get("/api/reports/expenses-income")
async def report_expenses_income(
    from_date: Optional[str] = None, to_date: Optional[str] = None,
    staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db),
):
    from_d = datetime.fromisoformat(from_date) if from_date else datetime(_utcnow().year, 1, 1, tzinfo=timezone.utc)
    to_d = datetime.fromisoformat(to_date) if to_date else _utcnow()

    income_r = await db.execute(
        select(extract("year", CRMPayment.created_at).label("yr"),
               extract("month", CRMPayment.created_at).label("mo"),
               func.sum(CRMPayment.amount).label("total"))
        .where(CRMPayment.created_at >= from_d, CRMPayment.created_at <= to_d,
               CRMPayment.status == "completed")
        .group_by("yr", "mo").order_by("yr", "mo")
    )
    income_map = {(int(r.yr), int(r.mo)): float(r.total or 0) for r in income_r}

    exp_r = await db.execute(
        select(extract("year", CRMExpense.expense_date).label("yr"),
               extract("month", CRMExpense.expense_date).label("mo"),
               func.sum(CRMExpense.amount).label("total"))
        .where(CRMExpense.expense_date >= from_d, CRMExpense.expense_date <= to_d)
        .group_by("yr", "mo").order_by("yr", "mo")
    )
    exp_map = {(int(r.yr), int(r.mo)): float(r.total or 0) for r in exp_r}

    all_keys = sorted(set(income_map) | set(exp_map))
    rows = []
    for (yr, mo) in all_keys:
        inc = income_map.get((yr, mo), 0)
        exp = exp_map.get((yr, mo), 0)
        rows.append({"year": yr, "month": mo, "income": inc, "expenses": exp, "profit": inc - exp})

    return {"from_date": from_d.isoformat(), "to_date": to_d.isoformat(), "rows": rows}


@router.get("/api/reports/kb")
async def report_kb(staff: StaffMember = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    articles_r = await db.execute(
        select(CRMKBArticle)
        .options(selectinload(CRMKBArticle.group), selectinload(CRMKBArticle.feedback))
        .order_by(CRMKBArticle.group_id, CRMKBArticle.subject)
    )
    result = []
    for a in articles_r.scalars().all():
        helpful = sum(1 for f in (a.feedback or []) if f.vote == "helpful")
        not_helpful = sum(1 for f in (a.feedback or []) if f.vote == "not_helpful")
        total = helpful + not_helpful
        result.append({
            "id": a.id, "subject": a.subject,
            "group_name": a.group.name if a.group else None,
            "active": a.active, "staff_only": a.staff_only,
            "helpful": helpful, "not_helpful": not_helpful, "total_votes": total,
            "score": round(helpful / total * 100, 1) if total else None,
        })
    return result


# ── Dashboard Layout ──────────────────────────────────────────────────────────

class _DashboardLayoutIn(BaseModel):
    layout: Any

@router.get("/api/dashboard/layout")
async def get_dashboard_layout(request: Request, db: AsyncSession = Depends(get_db)):
    staff = await _require_staff(request, db)
    row = (await db.execute(
        select(CRMDashboardLayout).where(CRMDashboardLayout.staff_id == staff.id)
    )).scalar_one_or_none()
    return {"layout": row.layout if row else None}

@router.put("/api/dashboard/layout")
async def save_dashboard_layout(request: Request, data: _DashboardLayoutIn, db: AsyncSession = Depends(get_db)):
    staff = await _require_staff(request, db)
    row = (await db.execute(
        select(CRMDashboardLayout).where(CRMDashboardLayout.staff_id == staff.id)
    )).scalar_one_or_none()
    if row:
        row.layout = data.layout
        row.updated_at = datetime.now(timezone.utc)
    else:
        row = CRMDashboardLayout(staff_id=staff.id, layout=data.layout)
        db.add(row)
    await db.commit()
    return {"ok": True}


# ── Dashboard Stats ──────────────────────────────────────────────────────────

@router.get("/api/dashboard/stats")
async def get_dashboard_stats(request: Request, db: AsyncSession = Depends(get_db)):
    staff = await _require_staff(request, db)
    now = datetime.now(timezone.utc)
    cur_year = now.year

    inv_awaiting = (await db.scalar(
        select(func.count()).select_from(CRMInvoice)
        .where(CRMInvoice.status.in_(["unpaid", "partially_paid", "overdue"]))
    )) or 0
    inv_total = (await db.scalar(select(func.count()).select_from(CRMInvoice))) or 0
    leads_converted = (await db.scalar(
        select(func.count()).select_from(CRMLead)
        .where(CRMLead.converted_customer_id.isnot(None))
    )) or 0
    leads_total = (await db.scalar(select(func.count()).select_from(CRMLead))) or 0
    projects_active = (await db.scalar(
        select(func.count()).select_from(CRMProject).where(CRMProject.status == "in_progress")
    )) or 0
    projects_total = (await db.scalar(select(func.count()).select_from(CRMProject))) or 0
    tasks_not_done = (await db.scalar(
        select(func.count()).select_from(CRMTask).where(CRMTask.status != "complete")
    )) or 0
    tasks_total = (await db.scalar(select(func.count()).select_from(CRMTask))) or 0
    file_count = (await db.scalar(select(func.count()).select_from(CRMFile))) or 0

    inv_by_status = (await db.execute(
        select(CRMInvoice.status, func.count()).group_by(CRMInvoice.status)
    )).all()
    inv_overview = [{"status": r[0] or "draft", "count": r[1]} for r in inv_by_status]

    prop_by_status = (await db.execute(
        select(CRMProposal.status, func.count()).group_by(CRMProposal.status)
    )).all()
    prop_overview = [{"status": r[0] or "draft", "count": r[1]} for r in prop_by_status]

    pay_monthly = (await db.execute(
        select(
            extract("month", CRMPayment.date).label("mo"),
            func.sum(CRMPayment.amount).label("total"),
        )
        .where(extract("year", CRMPayment.date) == cur_year)
        .group_by("mo").order_by("mo")
    )).all()
    m_inc = {int(r.mo): float(r.total or 0) for r in pay_monthly}
    monthly_income = [m_inc.get(m, 0.0) for m in range(1, 13)]

    inv_amt_rows = (await db.execute(
        select(CRMInvoice.status, func.sum(CRMInvoice.total)).group_by(CRMInvoice.status)
    )).all()
    inv_amt = {r[0]: float(r[1] or 0) for r in inv_amt_rows}

    all_tasks_q = (await db.execute(
        select(CRMTask, CRMProject.name.label("pname"))
        .outerjoin(CRMProject, CRMTask.project_id == CRMProject.id)
        .where(CRMTask.status != "complete")
        .order_by(desc(CRMTask.created_at)).limit(100)
    )).all()
    my_tasks = [
        {"id": r.CRMTask.id, "name": r.CRMTask.name, "status": r.CRMTask.status,
         "priority": r.CRMTask.priority,
         "start_date": r.CRMTask.start_date.isoformat() if r.CRMTask.start_date else None,
         "due_date": r.CRMTask.due_date.isoformat() if r.CRMTask.due_date else None,
         "project_name": r.pname or ""}
        for r in all_tasks_q
        if staff.id in (r.CRMTask.assignees or [])
    ][:20]

    my_pid = (await db.execute(
        select(CRMProjectMember.project_id).where(CRMProjectMember.staff_id == staff.id)
    )).scalars().all()
    my_projs = (await db.execute(
        select(CRMProject).where(CRMProject.id.in_(my_pid))
        .order_by(desc(CRMProject.created_at)).limit(8)
    )).scalars().all()
    my_projects = [
        {"id": p.id, "name": p.name, "status": p.status, "progress": p.progress,
         "deadline": p.deadline.isoformat() if p.deadline else None}
        for p in my_projs
    ]

    my_rems = (await db.execute(
        select(CRMReminder)
        .where(CRMReminder.is_notified == False)
        .where(CRMReminder.created_by == staff.id)
        .order_by(CRMReminder.remind_at).limit(5)
    )).scalars().all()
    my_reminders = [
        {"id": r.id, "description": r.description,
         "remind_at": r.remind_at.isoformat() if r.remind_at else None,
         "rel_type": r.rel_type}
        for r in my_rems
    ]

    anns = (await db.execute(
        select(CRMAnnouncement).order_by(desc(CRMAnnouncement.created_at)).limit(5)
    )).scalars().all()
    announcements = [
        {"id": a.id, "content": a.content,
         "created_at": a.created_at.isoformat() if a.created_at else None}
        for a in anns
    ]

    act_q = (await db.execute(
        select(CRMActivity, StaffMember.first_name, StaffMember.last_name)
        .outerjoin(StaffMember, CRMActivity.staff_id == StaffMember.id)
        .order_by(desc(CRMActivity.created_at)).limit(10)
    )).all()
    activity = [
        {"id": r[0].id, "description": r[0].description or r[0].action,
         "module": r[0].module,
         "date": r[0].created_at.isoformat() if r[0].created_at else None,
         "user": f"{r[1] or ''} {r[2] or ''}".strip() or "System"}
        for r in act_q
    ]

    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    next_month = month_start.replace(year=month_start.year + 1, month=1) if month_start.month == 12 else month_start.replace(month=month_start.month + 1)
    cal_evs = (await db.execute(
        select(CRMEvent)
        .where(CRMEvent.start_date >= month_start)
        .where(CRMEvent.start_date < next_month).limit(50)
    )).scalars().all()
    calendar_events = [
        {"id": e.id, "title": e.title, "start_date": e.start_date.isoformat(), "color": e.color}
        for e in cal_evs
    ]

    pay_q = (await db.execute(
        select(CRMPayment, CRMInvoice.invoice_number)
        .outerjoin(CRMInvoice, CRMPayment.invoice_id == CRMInvoice.id)
        .order_by(desc(CRMPayment.date)).limit(10)
    )).all()
    recent_payments = [
        {"id": r[0].id, "amount": r[0].amount,
         "date": r[0].date.isoformat() if r[0].date else None,
         "invoice_number": r[1] or f"INV-{r[0].invoice_id}"}
        for r in pay_q
    ]

    exp_cutoff = now + timedelta(days=30)
    exp_q = (await db.execute(
        select(CRMContract)
        .where(CRMContract.end_date.isnot(None))
        .where(CRMContract.end_date <= exp_cutoff)
        .where(CRMContract.status != "cancelled")
        .order_by(CRMContract.end_date).limit(10)
    )).scalars().all()
    expiring_contracts = [
        {"id": c.id, "subject": c.subject,
         "end_date": c.end_date.isoformat() if c.end_date else None,
         "status": c.status}
        for c in exp_q
    ]

    todos_unf = (await db.execute(
        select(CRMTodo).where(CRMTodo.staff_id == staff.id)
        .where(CRMTodo.is_done == False).order_by(CRMTodo.created_at).limit(5)
    )).scalars().all()
    todos_fin = (await db.execute(
        select(CRMTodo).where(CRMTodo.staff_id == staff.id)
        .where(CRMTodo.is_done == True).order_by(desc(CRMTodo.done_at)).limit(5)
    )).scalars().all()

    leads_src = (await db.execute(
        select(CRMLeadSource.name, func.count(CRMLead.id))
        .outerjoin(CRMLead, CRMLead.source_id == CRMLeadSource.id)
        .group_by(CRMLeadSource.name)
    )).all()
    leads_by_source = [{"source": r[0] or "Unknown", "count": r[1]} for r in leads_src]

    proj_status_rows = (await db.execute(
        select(CRMProject.status, func.count()).group_by(CRMProject.status)
    )).all()

    proj_act = (await db.execute(
        select(CRMProjectActivity).order_by(desc(CRMProjectActivity.dateadded)).limit(8)
    )).scalars().all()

    unb_q = (await db.execute(
        select(CRMTimesheet, StaffMember.first_name, StaffMember.last_name,
               CRMProject.name.label("pname"))
        .join(StaffMember, CRMTimesheet.staff_id == StaffMember.id)
        .outerjoin(CRMProject, CRMTimesheet.project_id == CRMProject.id)
        .where(CRMTimesheet.end_time.isnot(None))
        .order_by(desc(CRMTimesheet.start_time)).limit(20)
    )).all()
    unbilled_time = [
        {"id": r[0].id, "duration": r[0].duration,
         "staff_name": f"{r[1] or ''} {r[2] or ''}".strip(),
         "project_name": r[3] or "",
         "start_date": r[0].start_time.isoformat() if r[0].start_time else None}
        for r in unb_q
    ]

    return {
        "storage": {"file_count": file_count, "limit_gb": 5},
        "invoices_awaiting": inv_awaiting, "invoices_total": inv_total,
        "leads_converted": leads_converted, "leads_total": leads_total,
        "projects_active": projects_active, "projects_total": projects_total,
        "tasks_not_done": tasks_not_done, "tasks_total": tasks_total,
        "invoice_overview": inv_overview,
        "estimate_overview": [],
        "proposal_overview": prop_overview,
        "income": {
            "year": cur_year, "monthly": monthly_income,
            "outstanding": inv_amt.get("unpaid", 0) + inv_amt.get("partially_paid", 0),
            "past_due": inv_amt.get("overdue", 0),
            "paid": inv_amt.get("paid", 0),
        },
        "my_tasks": my_tasks,
        "my_projects": my_projects,
        "my_reminders": my_reminders,
        "announcements": announcements,
        "activity": activity,
        "calendar_events": calendar_events,
        "recent_payments": recent_payments,
        "expiring_contracts": expiring_contracts,
        "todos_unfinished": [{"id": t.id, "title": t.title} for t in todos_unf],
        "todos_finished": [{"id": t.id, "title": t.title} for t in todos_fin],
        "leads_by_source": leads_by_source,
        "projects_by_status": [{"status": r[0] or "unknown", "count": r[1]} for r in proj_status_rows],
        "project_activity": [
            {"id": a.id, "fullname": a.fullname, "description_key": a.description_key,
             "date": a.dateadded.isoformat() if a.dateadded else None}
            for a in proj_act
        ],
        "unbilled_time": unbilled_time,
        "goals": [],
        "subscriptions": {"active": 0, "mrr": 0, "churned": 0, "failed": 0},
    }
