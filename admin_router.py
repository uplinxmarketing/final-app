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
from sqlalchemy import select, func, desc, delete, update, extract, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database import get_db
from admin_models import (
    AdminBase, CRMRole, CRMApp, CRMUserAppAccess, CRMUserAppClientAccess,
    StaffMember, CRMCustomer, CRMContact, CRMNote,
    CRMLead, CRMLeadSource, CRMLeadStatus, CRMProject, CRMProjectMember,
    CRMTask, CRMTaskComment, CRMTimesheet, CRMInvoice, CRMProposal,
    CRMLineItem, CRMPayment, CRMPaymentMode, CRMExpense, CRMExpenseCategory,
    CRMContract, CRMContractType, CRMEvent, CRMAnnouncement,
    CRMAnnouncementComment, CRMActivity, CRMSetting, CRMEmailTemplate,
    CRMCatalogItem, CRMTaxRate, CRMCurrency, CRMCustomerGroup, CRMTodo,
    CRMStaffNote, CRMTag,
    CRMCustomField, CRMCustomFieldValue, CRMTaggable, CRMReminder,
    CRMPolyNote, CRMFile, CRMFilter, CRMFilterDefault, CRMNotification,
    CRMSalesActivity, CRMProjectActivity, CRMMailQueue, CRMTrackedMail,
    CRMScheduledEmail, CRMDashboardLayout,
)

router = APIRouter(prefix="/admin")

# ── Capability matrix ─────────────────────────────────────────────────────────
# { module_key: { capability_key: display_label } }
CAPABILITY_MATRIX: dict[str, dict[str, str]] = {
    "dashboard":      {"view": "View Dashboard"},
    "customers":      {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete", "import": "Import", "export": "Export"},
    "leads":          {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete", "convert": "Convert to Customer", "import": "Import"},
    "estimates":      {"view": "View", "create": "Create", "edit": "Edit", "delete": "Delete", "send": "Send to Client"},
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
    email: str
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
    result = await db.execute(
        select(StaffMember).options(selectinload(StaffMember.role)).where(
            StaffMember.email == req.email.lower().strip(),
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
