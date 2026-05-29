"""
admin_models.py — SQLAlchemy ORM models for the Uplinx Admin / CRM system.

All tables are prefixed with 'crm_' to coexist safely alongside the existing
Uplinx Meta Ad Upload tables. This file must NOT import from or modify any
existing model definitions.
"""
from __future__ import annotations

import hashlib
import secrets
import base64 as _b64
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint, Index,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AdminBase(DeclarativeBase):
    """Separate declarative base so admin tables are never mixed with app tables."""


# ── Roles & Permissions ──────────────────────────────────────────────────────

class CRMRole(AdminBase):
    """A named permission set assigned to staff members."""
    __tablename__ = "crm_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # JSON blob: { module: { capability: bool } }
    permissions: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    staff: Mapped[list["StaffMember"]] = relationship("StaffMember", back_populates="role")


class CRMApp(AdminBase):
    """A connected application that shares auth/clients with the CRM."""
    __tablename__ = "crm_apps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    icon: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    base_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    user_access: Mapped[list["CRMUserAppAccess"]] = relationship("CRMUserAppAccess", back_populates="app", cascade="all, delete-orphan")


class CRMUserAppAccess(AdminBase):
    """Which staff members can access which apps."""
    __tablename__ = "crm_user_app_access"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    app_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_apps.id", ondelete="CASCADE"), nullable=False)
    granted_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    app: Mapped[CRMApp] = relationship("CRMApp", back_populates="user_access")
    client_access: Mapped[list["CRMUserAppClientAccess"]] = relationship(
        "CRMUserAppClientAccess",
        primaryjoin="and_(CRMUserAppClientAccess.staff_id==CRMUserAppAccess.staff_id, CRMUserAppClientAccess.app_id==CRMUserAppAccess.app_id)",
        foreign_keys="[CRMUserAppClientAccess.staff_id, CRMUserAppClientAccess.app_id]",
        viewonly=True,
    )


class CRMUserAppClientAccess(AdminBase):
    """Which clients a staff member can manage within a specific app."""
    __tablename__ = "crm_user_app_client_access"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    app_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_apps.id", ondelete="CASCADE"), nullable=False)
    # client_id references crm_customers once Module 08 is built
    client_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class StaffMember(AdminBase):
    """A staff / admin user for the CRM system."""
    __tablename__ = "crm_staff"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    linkedin: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_roles.id", ondelete="SET NULL"), nullable=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Per-staff permission overrides: { module: { permission: true/false/null } }
    permission_overrides: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    profile_photo: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    email_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    language: Mapped[str] = mapped_column(String(10), nullable=False, default="en")
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    last_password_change_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    force_password_change: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    password_reset_token: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    password_reset_expires: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    role: Mapped[Optional[CRMRole]] = relationship("CRMRole", back_populates="staff")
    timesheets: Mapped[list["CRMTimesheet"]] = relationship("CRMTimesheet", back_populates="staff", cascade="all, delete-orphan")
    notes: Mapped[list["CRMStaffNote"]] = relationship("CRMStaffNote", foreign_keys="CRMStaffNote.staff_id", back_populates="staff", cascade="all, delete-orphan")

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


class CRMStaffNote(AdminBase):
    """Internal notes about a staff member."""
    __tablename__ = "crm_staff_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    author_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    staff: Mapped[StaffMember] = relationship("StaffMember", foreign_keys=[staff_id], back_populates="notes")


# ── Customer Groups & Tags ───────────────────────────────────────────────────

class CRMCustomerGroup(AdminBase):
    __tablename__ = "crm_customer_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class CRMTag(AdminBase):
    __tablename__ = "crm_tags"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    color: Mapped[str] = mapped_column(String(20), nullable=False, default="#6366f1")


# ── Customers ────────────────────────────────────────────────────────────────

class CRMCustomer(AdminBase):
    """A company / customer managed in the CRM."""
    __tablename__ = "crm_customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    company_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    vat_number: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    website: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    language: Mapped[str] = mapped_column(String(10), nullable=False, default="en")
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    zip_code: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # Billing address (separate from main/shipping)
    billing_address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    billing_city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    billing_state: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    billing_zip: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    billing_country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # Shipping address
    shipping_address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    shipping_city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    shipping_state: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    shipping_zip: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    shipping_country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # Groups: stored as JSON array of group IDs
    group_ids: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    tags: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    allow_portal_login: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    converted_from_lead_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_leads.id", ondelete="SET NULL"), nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    contacts: Mapped[list["CRMContact"]] = relationship("CRMContact", back_populates="customer", cascade="all, delete-orphan")
    notes: Mapped[list["CRMNote"]] = relationship("CRMNote", back_populates="customer", cascade="all, delete-orphan")
    projects: Mapped[list["CRMProject"]] = relationship("CRMProject", back_populates="customer")
    invoices: Mapped[list["CRMInvoice"]] = relationship("CRMInvoice", back_populates="customer")
    proposals: Mapped[list["CRMProposal"]] = relationship("CRMProposal", back_populates="customer")
    contracts: Mapped[list["CRMContract"]] = relationship("CRMContract", back_populates="customer")
    expenses: Mapped[list["CRMExpense"]] = relationship("CRMExpense", back_populates="customer")


class CRMContact(AdminBase):
    """A contact person at a customer company."""
    __tablename__ = "crm_contacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    customer_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="CASCADE"), nullable=False)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    can_login: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_portal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    hashed_password: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # email_opt_ins: { receives_invoice, receives_estimate, receives_proposal, receives_contract, receives_task, receives_project, receives_ticket }
    email_opt_ins: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=lambda: {
        "receives_invoice": True, "receives_estimate": True, "receives_proposal": True,
        "receives_contract": True, "receives_task": True, "receives_project": True, "receives_ticket": True,
    })
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    customer: Mapped[CRMCustomer] = relationship("CRMCustomer", back_populates="contacts")

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


class CRMNote(AdminBase):
    """Rich-text note attached to a customer (or lead/project)."""
    __tablename__ = "crm_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="CASCADE"), nullable=True)
    lead_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_leads.id", ondelete="CASCADE"), nullable=True)
    author_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    customer: Mapped[Optional[CRMCustomer]] = relationship("CRMCustomer", back_populates="notes")
    lead: Mapped[Optional["CRMLead"]] = relationship("CRMLead", back_populates="notes")
    author: Mapped[Optional[StaffMember]] = relationship("StaffMember")


# ── Leads ────────────────────────────────────────────────────────────────────

class CRMLeadSource(AdminBase):
    __tablename__ = "crm_lead_sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class CRMLeadStatus(AdminBase):
    __tablename__ = "crm_lead_statuses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    color: Mapped[str] = mapped_column(String(20), nullable=False, default="#6366f1")
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class CRMLead(AdminBase):
    __tablename__ = "crm_leads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    salutation: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    company: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    website: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_lead_sources.id", ondelete="SET NULL"), nullable=True)
    status_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_lead_statuses.id", ondelete="SET NULL"), nullable=True)
    assigned_to: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    zip_code: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    tags: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    last_contact: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    converted_customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    source: Mapped[Optional[CRMLeadSource]] = relationship("CRMLeadSource")
    status: Mapped[Optional[CRMLeadStatus]] = relationship("CRMLeadStatus")
    assignee: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[assigned_to])
    notes: Mapped[list[CRMNote]] = relationship("CRMNote", back_populates="lead", cascade="all, delete-orphan")

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


# ── Finance: Invoices, Proposals, Payments ───────────────────────────────────

class CRMTaxRate(AdminBase):
    __tablename__ = "crm_tax_rates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    rate: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class CRMCurrency(AdminBase):
    __tablename__ = "crm_currencies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    code: Mapped[str] = mapped_column(String(10), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    symbol: Mapped[str] = mapped_column(String(10), nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class CRMInvoice(AdminBase):
    __tablename__ = "crm_invoices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    # Numbering
    number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    prefix: Mapped[str] = mapped_column(String(20), nullable=False, default="INV")
    formatted_number: Mapped[str] = mapped_column(String(50), nullable=False, default="", index=True)
    invoice_number: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    # Parties
    customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="SET NULL"), nullable=True)
    project_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="SET NULL"), nullable=True)
    sale_agent_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    # Addresses
    billing_address: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    shipping_address: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    bill_to: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    order_number: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="draft")  # draft|not_sent|unpaid|partially_paid|overdue|paid
    date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Money
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    discount_type: Mapped[str] = mapped_column(String(20), nullable=False, default="before_tax")
    discount_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    discount_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    adjustment: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    subtotal: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tax_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    amount_paid: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    allowed_payment_modes: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    # Notes
    client_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    terms: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    admin_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    # Assignment & recurrence
    assigned_to: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    is_recurring: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recurring_config: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    subscription_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # Public link
    hash: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True, default=lambda: secrets.token_hex(16))
    # Reminders
    last_overdue_reminder_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_due_reminder_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_overdue_reminders: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Timestamps
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    customer: Mapped[Optional[CRMCustomer]] = relationship("CRMCustomer", back_populates="invoices")
    project: Mapped[Optional["CRMProject"]] = relationship("CRMProject", back_populates="invoices")
    sale_agent: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[sale_agent_id])
    items: Mapped[list["CRMLineItem"]] = relationship("CRMLineItem", back_populates="invoice", cascade="all, delete-orphan",
                                                       primaryjoin="CRMLineItem.invoice_id == CRMInvoice.id")
    payments: Mapped[list["CRMPayment"]] = relationship("CRMPayment", back_populates="invoice", cascade="all, delete-orphan")
    assignee: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[assigned_to])


class CRMProposal(AdminBase):
    __tablename__ = "crm_proposals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    # Numbering
    number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    prefix: Mapped[str] = mapped_column(String(20), nullable=False, default="PROP")
    formatted_number: Mapped[str] = mapped_column(String(50), nullable=False, default="", index=True)
    proposal_number: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    # Parties
    customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="SET NULL"), nullable=True)
    lead_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_leads.id", ondelete="SET NULL"), nullable=True)
    sale_agent_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    proposal_to: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    # Addresses
    billing_address: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    shipping_address: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft", index=True)  # draft|sent|open|revised|declined|accepted
    pipeline_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    open_till: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Money
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    discount_type: Mapped[str] = mapped_column(String(20), nullable=False, default="before_tax")
    discount_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    discount_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    adjustment: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    subtotal: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tax_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Content & notes
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    allow_comments: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    client_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    terms: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    admin_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    assigned_to: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    # Public link
    hash: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True, default=lambda: secrets.token_hex(16))
    # E-sign acceptance
    acceptance_first_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    acceptance_last_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    acceptance_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    acceptance_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    acceptance_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    signature_image: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Conversion
    converted_to_invoice_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    converted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Timestamps
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    customer: Mapped[Optional[CRMCustomer]] = relationship("CRMCustomer", back_populates="proposals")
    sale_agent: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[sale_agent_id])
    items: Mapped[list["CRMLineItem"]] = relationship("CRMLineItem", back_populates="proposal", cascade="all, delete-orphan",
                                                       primaryjoin="CRMLineItem.proposal_id == CRMProposal.id")
    assignee: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[assigned_to])


class CRMEstimate(AdminBase):
    """A pre-sale price quote / estimate."""
    __tablename__ = "crm_estimates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    # Number
    number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    prefix: Mapped[str] = mapped_column(String(20), nullable=False, default="EST")
    formatted_number: Mapped[str] = mapped_column(String(50), nullable=False, default="", index=True)
    # Parties
    customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="SET NULL"), nullable=True)
    lead_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_leads.id", ondelete="SET NULL"), nullable=True)
    sale_agent_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    project_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="SET NULL"), nullable=True)
    # Addresses (stored as JSON blobs: {name, address, city, state, zip, country})
    billing_address: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    shipping_address: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    # Dates
    date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expiry_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Money
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    discount_type: Mapped[str] = mapped_column(String(20), nullable=False, default="before_tax")
    discount_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    subtotal: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tax_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    discount_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    adjustment: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Status
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft", index=True)
    pipeline_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Notes
    client_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    terms: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    admin_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Public link
    hash: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True, default=lambda: secrets.token_hex(16))
    # Acceptance / e-sign
    acceptance_first_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    acceptance_last_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    acceptance_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    acceptance_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    acceptance_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    signature_image: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Conversion
    converted_to_invoice_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    converted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Timestamps
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    customer: Mapped[Optional[CRMCustomer]] = relationship("CRMCustomer")
    sale_agent: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[sale_agent_id])
    items: Mapped[list["CRMLineItem"]] = relationship("CRMLineItem", back_populates="estimate",
                                                       cascade="all, delete-orphan",
                                                       primaryjoin="CRMLineItem.estimate_id == CRMEstimate.id")


class CRMLineItem(AdminBase):
    """A line item on an invoice, proposal, estimate, or credit note."""
    __tablename__ = "crm_line_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    invoice_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_invoices.id", ondelete="CASCADE"), nullable=True)
    proposal_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_proposals.id", ondelete="CASCADE"), nullable=True)
    estimate_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_estimates.id", ondelete="CASCADE"), nullable=True)
    credit_note_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_credit_notes.id", ondelete="CASCADE"), nullable=True)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    long_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    qty: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    discount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tax_ids: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    invoice: Mapped[Optional[CRMInvoice]] = relationship("CRMInvoice", back_populates="items",
                                                          foreign_keys=[invoice_id])
    proposal: Mapped[Optional[CRMProposal]] = relationship("CRMProposal", back_populates="items",
                                                            foreign_keys=[proposal_id])
    estimate: Mapped[Optional["CRMEstimate"]] = relationship("CRMEstimate", back_populates="items",
                                                              foreign_keys=[estimate_id])
    credit_note: Mapped[Optional["CRMCreditNote"]] = relationship("CRMCreditNote", back_populates="items",
                                                                   foreign_keys=[credit_note_id])


class CRMPaymentMode(AdminBase):
    __tablename__ = "crm_payment_modes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    show_on_pdf: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    selected_by_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    invoices_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expenses_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class CRMPayment(AdminBase):
    __tablename__ = "crm_payments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    invoice_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_invoices.id", ondelete="CASCADE"), nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    payment_mode_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_payment_modes.id", ondelete="SET NULL"), nullable=True)
    payment_method: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    transaction_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    invoice: Mapped[CRMInvoice] = relationship("CRMInvoice", back_populates="payments")
    payment_mode: Mapped[Optional[CRMPaymentMode]] = relationship("CRMPaymentMode")
    created_by: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[created_by_user_id])


class CRMCreditNote(AdminBase):
    __tablename__ = "crm_credit_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    prefix: Mapped[str] = mapped_column(String(20), nullable=False, default="CN")
    formatted_number: Mapped[str] = mapped_column(String(50), nullable=False, default="", index=True)
    reference_no: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="SET NULL"), nullable=True)
    assigned_to: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    # Status: Open | Closed | Void
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="Open", index=True)
    date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    # Money
    discount_type: Mapped[str] = mapped_column(String(20), nullable=False, default="before_tax")
    discount_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    discount_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    adjustment: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    subtotal: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tax_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    remaining: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Addresses
    billing_address: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    shipping_address: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    # Notes
    client_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    terms: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    admin_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Public link
    hash: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True, default=lambda: secrets.token_hex(16))
    # Timestamps
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    customer: Mapped[Optional["CRMCustomer"]] = relationship("CRMCustomer")
    assignee: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[assigned_to])
    items: Mapped[list["CRMLineItem"]] = relationship(
        "CRMLineItem", back_populates="credit_note", cascade="all, delete-orphan",
        primaryjoin="CRMLineItem.credit_note_id == CRMCreditNote.id")
    applications: Mapped[list["CRMCreditApplication"]] = relationship(
        "CRMCreditApplication", back_populates="credit_note", cascade="all, delete-orphan")
    refunds: Mapped[list["CRMCreditRefund"]] = relationship(
        "CRMCreditRefund", back_populates="credit_note", cascade="all, delete-orphan")


class CRMCreditApplication(AdminBase):
    __tablename__ = "crm_credit_applications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    credit_note_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_credit_notes.id", ondelete="CASCADE"), nullable=False)
    invoice_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_invoices.id", ondelete="CASCADE"), nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    applied_by_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)

    credit_note: Mapped[CRMCreditNote] = relationship("CRMCreditNote", back_populates="applications")
    invoice: Mapped[CRMInvoice] = relationship("CRMInvoice")
    applied_by: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[applied_by_user_id])


class CRMCreditRefund(AdminBase):
    __tablename__ = "crm_credit_refunds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    credit_note_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_credit_notes.id", ondelete="CASCADE"), nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    refunded_on: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    payment_mode_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_payment_modes.id", ondelete="SET NULL"), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recorded_by_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)

    credit_note: Mapped[CRMCreditNote] = relationship("CRMCreditNote", back_populates="refunds")
    payment_mode: Mapped[Optional[CRMPaymentMode]] = relationship("CRMPaymentMode")
    recorded_by: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[recorded_by_user_id])


# ── Expenses ─────────────────────────────────────────────────────────────────

class CRMExpenseCategory(AdminBase):
    __tablename__ = "crm_expense_categories"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class CRMExpense(AdminBase):
    __tablename__ = "crm_expenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    category_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_expense_categories.id", ondelete="SET NULL"), nullable=True)
    customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="SET NULL"), nullable=True)
    project_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="SET NULL"), nullable=True)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    tax_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_tax_rates.id", ondelete="SET NULL"), nullable=True)
    tax_id_2: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_tax_rates.id", ondelete="SET NULL"), nullable=True)
    payment_mode_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_payment_modes.id", ondelete="SET NULL"), nullable=True)
    reference: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expense_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    receipt_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    invoice_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_invoices.id", ondelete="SET NULL"), nullable=True)
    is_billable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_billed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_recurring: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recurring_config: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    category: Mapped[Optional[CRMExpenseCategory]] = relationship("CRMExpenseCategory")
    customer: Mapped[Optional[CRMCustomer]] = relationship("CRMCustomer", back_populates="expenses")


# ── Contracts ────────────────────────────────────────────────────────────────

class CRMContractType(AdminBase):
    __tablename__ = "crm_contract_types"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class CRMContract(AdminBase):
    __tablename__ = "crm_contracts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    contract_number: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="SET NULL"), nullable=True)
    project_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="SET NULL"), nullable=True)
    contract_type_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_contract_types.id", ondelete="SET NULL"), nullable=True)
    value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    end_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")  # draft|active|expired|cancelled
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    allow_esign: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    marked_as_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    signed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    signed_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    acceptance_first_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    acceptance_last_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    acceptance_email: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    acceptance_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    acceptance_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    acceptance_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True, default=lambda: secrets.token_hex(16))
    trashed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    not_visible_to_client: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sign_reminder_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_expiry_notified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tags: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    customer: Mapped[Optional[CRMCustomer]] = relationship("CRMCustomer", back_populates="contracts")
    project: Mapped[Optional["CRMProject"]] = relationship("CRMProject", back_populates="contracts", foreign_keys=[project_id])
    contract_type: Mapped[Optional[CRMContractType]] = relationship("CRMContractType")
    renewals: Mapped[list["CRMContractRenewal"]] = relationship("CRMContractRenewal", back_populates="contract", cascade="all, delete-orphan")


class CRMContractRenewal(AdminBase):
    __tablename__ = "crm_contract_renewals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_contracts.id", ondelete="CASCADE"), nullable=False)
    old_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    new_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    old_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    new_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    old_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    new_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    renewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    renewed_by_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)

    contract: Mapped[CRMContract] = relationship("CRMContract", back_populates="renewals")
    renewed_by: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[renewed_by_user_id])


# ── Subscriptions ─────────────────────────────────────────────────────────────

class CRMSubscription(AdminBase):
    __tablename__ = "crm_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description_in_invoice_item: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Parties
    customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="SET NULL"), nullable=True)
    project_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="SET NULL"), nullable=True)
    # Billing
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    interval: Mapped[str] = mapped_column(String(20), nullable=False, default="month")  # day|week|month|year
    interval_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    trial_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Tax
    tax_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_tax_rates.id", ondelete="SET NULL"), nullable=True)
    tax_id_2: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_tax_rates.id", ondelete="SET NULL"), nullable=True)
    # Stripe
    stripe_plan_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Status: Draft | Not Subscribed | Active | Past Due | Unpaid | Canceled | Incomplete
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="Draft", index=True)
    next_billing_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    terms: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hash: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True, default=lambda: secrets.token_hex(16))
    is_test_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    customer: Mapped[Optional["CRMCustomer"]] = relationship("CRMCustomer")
    created_by: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[created_by_user_id])


# ── Projects & Tasks ─────────────────────────────────────────────────────────

class CRMProject(AdminBase):
    __tablename__ = "crm_projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    customer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_customers.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="in_progress")  # not_started|in_progress|on_hold|cancelled|finished
    billing_type: Mapped[str] = mapped_column(String(30), nullable=False, default="fixed_rate")  # fixed_rate|project_hours|task_hours
    total_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    rate_per_hour: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    project_cost: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    estimated_hours: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    calculate_progress_from_tasks: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    date_finished: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    settings: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=dict)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    customer: Mapped[Optional[CRMCustomer]] = relationship("CRMCustomer", back_populates="projects")
    members: Mapped[list["CRMProjectMember"]] = relationship("CRMProjectMember", back_populates="project", cascade="all, delete-orphan")
    tasks: Mapped[list["CRMTask"]] = relationship("CRMTask", back_populates="project", cascade="all, delete-orphan")
    timesheets: Mapped[list["CRMTimesheet"]] = relationship("CRMTimesheet", back_populates="project")
    invoices: Mapped[list[CRMInvoice]] = relationship("CRMInvoice", back_populates="project")
    contracts: Mapped[list[CRMContract]] = relationship("CRMContract", back_populates="project",
                                                         foreign_keys="CRMContract.project_id")
    milestones: Mapped[list["CRMMilestone"]] = relationship("CRMMilestone", back_populates="project", cascade="all, delete-orphan")
    discussions: Mapped[list["CRMProjectDiscussion"]] = relationship("CRMProjectDiscussion", back_populates="project", cascade="all, delete-orphan")
    pinned_by: Mapped[list["CRMPinnedProject"]] = relationship("CRMPinnedProject", back_populates="project", cascade="all, delete-orphan")


class CRMProjectMember(AdminBase):
    __tablename__ = "crm_project_members"
    __table_args__ = (UniqueConstraint("project_id", "staff_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="CASCADE"), nullable=False)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    project: Mapped[CRMProject] = relationship("CRMProject", back_populates="members")
    staff: Mapped[StaffMember] = relationship("StaffMember")


class CRMMilestone(AdminBase):
    __tablename__ = "crm_milestones"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    color: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, default="#6366f1")
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    project: Mapped[CRMProject] = relationship("CRMProject", back_populates="milestones")


class CRMProjectDiscussion(AdminBase):
    __tablename__ = "crm_project_discussions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="CASCADE"), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    visible_to_customer: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    project: Mapped[CRMProject] = relationship("CRMProject", back_populates="discussions")
    creator: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[created_by])
    comments: Mapped[list["CRMDiscussionComment"]] = relationship("CRMDiscussionComment", back_populates="discussion", cascade="all, delete-orphan")


class CRMDiscussionComment(AdminBase):
    __tablename__ = "crm_discussion_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    discussion_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_project_discussions.id", ondelete="CASCADE"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    discussion: Mapped[CRMProjectDiscussion] = relationship("CRMProjectDiscussion", back_populates="comments")
    creator: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[created_by])


class CRMPinnedProject(AdminBase):
    __tablename__ = "crm_pinned_projects"
    __table_args__ = (UniqueConstraint("staff_id", "project_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="CASCADE"), nullable=False)
    pinned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    project: Mapped[CRMProject] = relationship("CRMProject", back_populates="pinned_by")
    staff: Mapped["StaffMember"] = relationship("StaffMember")


class CRMTask(AdminBase):
    __tablename__ = "crm_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    project_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="CASCADE"), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="not_started")  # not_started|in_progress|testing|awaiting_feedback|complete
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="normal")  # urgent|high|normal|low
    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    assignees: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)  # list of staff IDs
    followers: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    tags: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    checklist: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)  # [{text, done}]
    total_logged_time: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # seconds
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    project: Mapped[Optional[CRMProject]] = relationship("CRMProject", back_populates="tasks")
    comments: Mapped[list["CRMTaskComment"]] = relationship("CRMTaskComment", back_populates="task", cascade="all, delete-orphan")
    timesheets: Mapped[list["CRMTimesheet"]] = relationship("CRMTimesheet", back_populates="task")


class CRMTaskComment(AdminBase):
    __tablename__ = "crm_task_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    task_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_tasks.id", ondelete="CASCADE"), nullable=False)
    author_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    task: Mapped[CRMTask] = relationship("CRMTask", back_populates="comments")
    author: Mapped[Optional[StaffMember]] = relationship("StaffMember")


class CRMTimesheet(AdminBase):
    __tablename__ = "crm_timesheets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_tasks.id", ondelete="SET NULL"), nullable=True)
    project_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="SET NULL"), nullable=True)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # seconds
    note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    staff: Mapped[StaffMember] = relationship("StaffMember", back_populates="timesheets")
    task: Mapped[Optional[CRMTask]] = relationship("CRMTask", back_populates="timesheets")
    project: Mapped[Optional[CRMProject]] = relationship("CRMProject", back_populates="timesheets")


# ── Calendar & Events ────────────────────────────────────────────────────────

class CRMEvent(AdminBase):
    __tablename__ = "crm_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    start_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    color: Mapped[str] = mapped_column(String(20), nullable=False, default="#6366f1")
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    notification_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    creator: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[created_by])


# ── Announcements ────────────────────────────────────────────────────────────

class CRMAnnouncement(AdminBase):
    __tablename__ = "crm_announcements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    author_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # None = all departments
    likes: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)  # list of staff IDs
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    author: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[author_id])


class CRMAnnouncementComment(AdminBase):
    __tablename__ = "crm_announcement_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    announcement_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_announcements.id", ondelete="CASCADE"), nullable=False)
    author_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    likes: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


# ── Activity Log ─────────────────────────────────────────────────────────────

class CRMActivity(AdminBase):
    __tablename__ = "crm_activity"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    staff_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    module: Mapped[str] = mapped_column(String(50), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    record_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    record_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    staff: Mapped[Optional[StaffMember]] = relationship("StaffMember")


# ── CRM Settings ─────────────────────────────────────────────────────────────

class CRMSetting(AdminBase):
    __tablename__ = "crm_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


# ── Email Templates ──────────────────────────────────────────────────────────

class CRMEmailTemplate(AdminBase):
    __tablename__ = "crm_email_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    group: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


# ── Catalog Items ────────────────────────────────────────────────────────────

class CRMCatalogItem(AdminBase):
    """Saved items/services for reuse in invoices and proposals."""
    __tablename__ = "crm_catalog_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tax_ids: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    unit: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    group: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


# ── To-Do Items ──────────────────────────────────────────────────────────────

class CRMTodo(AdminBase):
    __tablename__ = "crm_todos"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    is_done: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    done_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    staff: Mapped[StaffMember] = relationship("StaffMember")


# ── Custom Fields ─────────────────────────────────────────────────────────────

class CRMCustomField(AdminBase):
    __tablename__ = "crm_custom_fields"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    field_to: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    field_type: Mapped[str] = mapped_column(String(30), nullable=False, default="input")
    options: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    default_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    display_inline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    bs_col_width: Mapped[int] = mapped_column(Integer, nullable=False, default=12)
    show_on_pdf: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    show_on_ticket_form: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    only_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    show_on_table: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    show_on_client_portal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    disallow_client_edit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    field_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    values: Mapped[list["CRMCustomFieldValue"]] = relationship(
        "CRMCustomFieldValue", back_populates="field", cascade="all, delete-orphan"
    )


class CRMCustomFieldValue(AdminBase):
    __tablename__ = "crm_custom_field_values"
    __table_args__ = (UniqueConstraint("field_id", "rel_id", "rel_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    field_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_custom_fields.id", ondelete="CASCADE"), nullable=False)
    rel_id: Mapped[int] = mapped_column(Integer, nullable=False)
    rel_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    field: Mapped["CRMCustomField"] = relationship("CRMCustomField", back_populates="values")


# ── Taggables (polymorphic tag assignments) ───────────────────────────────────

class CRMTaggable(AdminBase):
    __tablename__ = "crm_taggables"
    __table_args__ = (UniqueConstraint("tag_id", "rel_id", "rel_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tag_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_tags.id", ondelete="CASCADE"), nullable=False)
    rel_id: Mapped[int] = mapped_column(Integer, nullable=False)
    rel_type: Mapped[str] = mapped_column(String(50), nullable=False)
    tag_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    tag: Mapped["CRMTag"] = relationship("CRMTag")


# ── Reminders (polymorphic) ───────────────────────────────────────────────────

class CRMReminder(AdminBase):
    __tablename__ = "crm_reminders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    rel_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rel_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remind_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notify_staff: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    notify_by_email: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_notified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    creator: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[created_by])


# ── Polymorphic Notes ─────────────────────────────────────────────────────────

class CRMPolyNote(AdminBase):
    """Polymorphic notes for any entity."""
    __tablename__ = "crm_poly_notes"
    __table_args__ = (Index("ix_crm_poly_notes_rel", "rel_type", "rel_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    rel_id: Mapped[int] = mapped_column(Integer, nullable=False)
    rel_type: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    date_contacted: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    addedfrom: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    dateadded: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    author: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[addedfrom])


# ── Polymorphic Files ─────────────────────────────────────────────────────────

class CRMFile(AdminBase):
    __tablename__ = "crm_files"
    __table_args__ = (Index("ix_crm_files_rel", "rel_type", "rel_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    rel_id: Mapped[int] = mapped_column(Integer, nullable=False)
    rel_type: Mapped[str] = mapped_column(String(50), nullable=False)
    file_name: Mapped[str] = mapped_column(String(500), nullable=False)
    filetype: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    visible_to_customer: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attachment_key: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    external: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    external_link: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    thumbnail_link: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    staffid: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    contact_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_contacts.id", ondelete="SET NULL"), nullable=True)
    task_comment_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dateadded: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    uploader: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[staffid])


# ── Saved Filters ─────────────────────────────────────────────────────────────

class CRMFilter(AdminBase):
    __tablename__ = "crm_filters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    builder: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    staff: Mapped["StaffMember"] = relationship("StaffMember")


class CRMFilterDefault(AdminBase):
    __tablename__ = "crm_filter_defaults"
    __table_args__ = (UniqueConstraint("staff_id", "identifier"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    filter_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_filters.id", ondelete="CASCADE"), nullable=False)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    identifier: Mapped[str] = mapped_column(String(100), nullable=False)

    filter: Mapped["CRMFilter"] = relationship("CRMFilter")
    staff: Mapped["StaffMember"] = relationship("StaffMember")


# ── In-App Notifications ──────────────────────────────────────────────────────

class CRMNotification(AdminBase):
    __tablename__ = "crm_notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    isread: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    isread_inline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    fromuserid: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    fromclientid: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_contacts.id", ondelete="SET NULL"), nullable=True)
    from_fullname: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    touserid: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False)
    fromcompany: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    link: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    additional_data: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    from_staff: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[fromuserid])
    to_staff: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[touserid])


# ── Sales Activity (per-entity timeline) ─────────────────────────────────────

class CRMSalesActivity(AdminBase):
    __tablename__ = "crm_sales_activity"
    __table_args__ = (Index("ix_crm_sales_activity_rel", "rel_type", "rel_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    rel_type: Mapped[str] = mapped_column(String(50), nullable=False)
    rel_id: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    additional_data: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    staffid: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    staff: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[staffid])


# ── Project Activity (per-project timeline) ───────────────────────────────────

class CRMProjectActivity(AdminBase):
    __tablename__ = "crm_project_activity"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_projects.id", ondelete="CASCADE"), nullable=False)
    staff_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    contact_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_contacts.id", ondelete="SET NULL"), nullable=True)
    fullname: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    visible_to_customer: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description_key: Mapped[str] = mapped_column(String(200), nullable=False)
    additional_data: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    dateadded: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    staff: Mapped[Optional["StaffMember"]] = relationship("StaffMember", foreign_keys=[staff_id])


# ── Estimate Request Forms (Module 13) ───────────────────────────────────────

class CRMEstimateRequestStatus(AdminBase):
    """Configurable statuses for estimate requests (Cancelled/Processing/Completed + custom)."""
    __tablename__ = "crm_estimate_request_statuses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    color: Mapped[str] = mapped_column(String(20), nullable=False, default="#6366f1")
    statusorder: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # flag: 'cancelled' | 'processing' | 'completed' | ''
    flag: Mapped[str] = mapped_column(String(20), nullable=False, default="")


class CRMEstimateRequestForm(AdminBase):
    """A public quote-request form embedded on the client's website."""
    __tablename__ = "crm_estimate_request_forms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    form_key: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True,
                                           default=lambda: secrets.token_hex(16))
    type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    language: Mapped[str] = mapped_column(String(10), nullable=False, default="en")
    # JSON array of field definitions
    form_data: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    submit_btn_label: Mapped[str] = mapped_column(String(100), nullable=False, default="Submit Request")
    submit_btn_bg_color: Mapped[str] = mapped_column(String(20), nullable=False, default="#6366f1")
    submit_btn_text_color: Mapped[str] = mapped_column(String(20), nullable=False, default="#ffffff")
    success_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True,
                                                            default="Thank you! We'll be in touch shortly.")
    redirect_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    recaptcha_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    honeypot_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # notify_type: 'assigned' | 'specific'
    notify_type: Mapped[str] = mapped_column(String(20), nullable=False, default="assigned")
    notify_user_ids: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True, default=list)
    default_assignee_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    default_assignee: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[default_assignee_id])
    requests: Mapped[list["CRMEstimateRequest"]] = relationship("CRMEstimateRequest", back_populates="form",
                                                                  cascade="all, delete-orphan")


class CRMEstimateRequest(AdminBase):
    """A submitted quote inquiry from a prospect via an estimate request form."""
    __tablename__ = "crm_estimate_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    form_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_estimate_request_forms.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    submission: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    status_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_estimate_request_statuses.id", ondelete="SET NULL"), nullable=True)
    assigned_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    last_status_change_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    date_estimated: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    converted_estimate_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    form: Mapped[CRMEstimateRequestForm] = relationship("CRMEstimateRequestForm", back_populates="requests")
    status: Mapped[Optional[CRMEstimateRequestStatus]] = relationship("CRMEstimateRequestStatus", foreign_keys=[status_id])
    assignee: Mapped[Optional[StaffMember]] = relationship("StaffMember", foreign_keys=[assigned_user_id])


# ── Mail Queue ────────────────────────────────────────────────────────────────

class CRMMailQueue(AdminBase):
    __tablename__ = "crm_mail_queue"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    engine: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    email: Mapped[str] = mapped_column(String(500), nullable=False)
    subject: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    cc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    bcc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    alt_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    headers: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    attachments: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    retries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


# ── Tracked Mails ─────────────────────────────────────────────────────────────

class CRMTrackedMail(AdminBase):
    __tablename__ = "crm_tracked_mails"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    uid: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    rel_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rel_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    email: Mapped[str] = mapped_column(String(500), nullable=False)
    opened: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    date_opened: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)


# ── Scheduled Emails ──────────────────────────────────────────────────────────

class CRMScheduledEmail(AdminBase):
    __tablename__ = "crm_scheduled_emails"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    rel_id: Mapped[int] = mapped_column(Integer, nullable=False)
    rel_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    contacts: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    cc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attach_pdf: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    template: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


# ── Dashboard Layout ──────────────────────────────────────────────────────────

class CRMDashboardLayout(AdminBase):
    __tablename__ = "crm_dashboard_layouts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    staff_id: Mapped[int] = mapped_column(Integer, ForeignKey("crm_staff.id", ondelete="CASCADE"), nullable=False, unique=True)
    layout: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    staff: Mapped["StaffMember"] = relationship("StaffMember")
