"""Authentication, users, roles and public form configuration (SRS 1.6 i-ii)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from supportnova.api.deps import client_ip, current_user, db_session, require, require_any
from supportnova.api.serializers import iso, user_public
from supportnova.audit import service as audit
from supportnova.core.config import get_settings
from supportnova.core.errors import AuthenticationFailed, Conflict, NotFound, ValidationFailed
from supportnova.core.timeutil import utcnow
from supportnova.database.models import Customer, Department, Role, User
from supportnova.security.auth import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    create_access_token,
    hash_password,
    new_csrf_token,
    verify_password,
)
from supportnova.services.rules import rule_service

router = APIRouter(tags=["auth"])
MAX_FAILED = 5


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


def _set_session(response: Response, user: User) -> str:
    settings = get_settings()
    token = create_access_token(user.id, user.role_code)
    csrf = new_csrf_token()
    max_age = settings.access_token_minutes * 60
    response.set_cookie(ACCESS_COOKIE, token, httponly=True, secure=True, samesite="none", max_age=max_age, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=True, samesite="none", max_age=max_age, path="/")
    return csrf


@router.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(db_session)) -> dict[str, Any]:
    user = db.execute(select(User).where(func.lower(User.email) == body.email.lower())).scalar_one_or_none()
    now = utcnow()
    if user is not None and user.locked_until is not None:
        locked = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=now.tzinfo)
        if locked > now:
            raise AuthenticationFailed("Too many failed attempts - the account is locked for a few minutes.", code="account_locked")
    if user is None or not user.is_active or not verify_password(body.password, user.password_hash):
        if user is not None:
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED:
                user.locked_until = now + timedelta(minutes=5)
                user.failed_logins = 0
            audit.record(db, action="auth.login_failed", entity_type="user", entity_id=user.id, summary="Failed sign-in",
                         actor_label=body.email, ip_address=client_ip(request))
            db.commit()
        raise AuthenticationFailed("Invalid email or password.", code="invalid_credentials")
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    csrf = _set_session(response, user)
    audit.record(db, action="auth.login", entity_type="user", entity_id=user.id, actor=user, summary="Signed in",
                 ip_address=client_ip(request))
    db.commit()
    return {"user": user_public(user), "permissions": sorted(user.permissions), "csrf_token": csrf,
            "access_token": create_access_token(user.id, user.role_code)}


@router.post("/auth/logout")
def logout(response: Response, user: User = Depends(current_user), db: Session = Depends(db_session)) -> dict[str, str]:
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    audit.record(db, action="auth.logout", entity_type="user", entity_id=user.id, actor=user, summary="Signed out")
    db.commit()
    return {"status": "signed_out"}


@router.get("/auth/me")
def me(request: Request, response: Response, user: User = Depends(current_user)) -> dict[str, Any]:
    csrf = request.cookies.get(CSRF_COOKIE)
    if not csrf and request.cookies.get(ACCESS_COOKIE):
        csrf = _set_session(response, user)
    return {"user": user_public(user), "permissions": sorted(user.permissions), "csrf_token": csrf}


DEMO_SIGN_INS = ("admin@lumora.example", "manager@lumora.example", "reviewer@lumora.example", "agent@lumora.example",
                 "customer@lumora.example")


@router.get("/auth/demo-accounts")
def demo_accounts(db: Session = Depends(db_session)) -> dict[str, Any]:
    """Public (login page): the demo sign-ins, only while SEED_DEMO_USERS is on and only accounts that still
    exist and are active. The demo password is demo-only data by design - never enable this for real users."""
    settings = get_settings()
    if not settings.seed_demo_users:
        return {"enabled": False, "password": None, "accounts": []}
    rows = {u.email: u for u in db.execute(select(User).where(User.email.in_(DEMO_SIGN_INS), User.is_active.is_(True))).scalars()}
    accounts = [{"email": e, "role": rows[e].role_code} for e in DEMO_SIGN_INS if e in rows]
    return {"enabled": bool(accounts), "password": settings.demo_password.get_secret_value() if accounts else None,
            "accounts": accounts}


@router.get("/config/public")
def public_config(user: User = Depends(current_user), db: Session = Depends(db_session)) -> dict[str, Any]:
    """Form options (channels, customer types, tones, ...) and taxonomy names for the UI."""
    matrix = rule_service.matrix(db)
    org = matrix.organization
    settings = get_settings()
    return {
        "organization": org.get("organization", {}),
        "channels": org.get("channels", []), "customer_types": org.get("customer_types", []),
        "preferred_contact_methods": org.get("preferred_contact_methods", []),
        "requested_resolutions": org.get("requested_resolutions", []), "response_tones": org.get("response_tones", []),
        "reference_formats": org.get("reference_formats", {}),
        "categories": [{"code": c.code, "name": c.name, "subcategories": [
            {"code": s.code, "name": s.name, "description": s.description} for s in matrix.subcategories.values() if s.category == c.code and s.is_active]}
            for c in matrix.categories.values() if c.is_active],
        "departments": [{"code": d.code, "name": d.name} for d in matrix.departments.values() if d.is_active],
        "products": [{"sku": p.sku, "name": p.name, "type": p.type} for p in matrix.products.values()],
        "escalation_levels": [lv.name for lv in matrix.escalation_levels],
        "statuses": ["New", "Processing", "Analyzed", "Assigned", "In Progress", "Awaiting Customer", "Escalated", "Resolved", "Closed", "Reopened"],
        "verification_statuses": ["Pending", "Verified", "Manual Review", "Human Verified"],
        "ai": {"provider": settings.resolved_provider, "model": settings.resolved_model, "configured": settings.ai_configured},
        "limits": {"max_attachment_mb": settings.max_attachment_mb, "max_upload_mb": settings.max_upload_mb},
    }


# ------------------------------------------------------------------------ users
class UserIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=160)
    role: str
    password: str | None = Field(default=None, min_length=10, max_length=200)
    department: str | None = None
    customer_ref: str | None = None
    is_active: bool = True


def _apply_user(db: Session, user: User, body: UserIn) -> None:
    role = db.execute(select(Role).where(Role.code == body.role)).scalar_one_or_none()
    if role is None:
        raise ValidationFailed("Unknown role.")
    user.role_id = role.id
    user.full_name = body.full_name
    user.is_active = body.is_active
    user.department_id = None
    if body.department:
        dept = db.execute(select(Department).where(Department.code == body.department)).scalar_one_or_none()
        if dept is None:
            raise ValidationFailed("Unknown department.")
        user.department_id = dept.id
    user.customer_id = None
    if body.customer_ref:
        cust = db.execute(select(Customer).where(Customer.customer_ref == body.customer_ref)).scalar_one_or_none()
        if cust is None:
            raise ValidationFailed("Unknown customer reference.")
        user.customer_id = cust.id


@router.get("/staff")
def staff_directory(role: str | None = None, department: str | None = None,
                    user: User = Depends(require_any("review:act", "complaint:update")), db: Session = Depends(db_session)) -> dict[str, Any]:
    """Minimal directory of active staff for assignment pickers (no emails or login data)."""
    q = select(User).join(Role).where(User.is_active.is_(True), Role.code != "customer")
    if role:
        q = q.where(Role.code == role)
    if department:
        q = q.join(Department, Department.id == User.department_id).where(Department.code == department)
    rows = db.execute(q.order_by(User.full_name)).scalars().all()
    return {"items": [{"id": u.id, "full_name": u.full_name, "role": u.role_code, "department": u.department.code if u.department else None}
                      for u in rows]}


@router.get("/users")
def list_users(user: User = Depends(require("users:read")), db: Session = Depends(db_session)) -> dict[str, Any]:
    rows = db.execute(select(User).order_by(User.id)).scalars().all()
    return {"items": [{**(user_public(u) or {}), "is_active": u.is_active, "last_login_at": iso(u.last_login_at),
                       "created_at": iso(u.created_at)} for u in rows], "total": len(rows)}


@router.post("/users", status_code=201)
def create_user(body: UserIn, actor: User = Depends(require("users:manage")), db: Session = Depends(db_session)) -> dict[str, Any]:
    if db.execute(select(User).where(func.lower(User.email) == body.email.lower())).first():
        raise Conflict("A user with this email already exists.")
    if not body.password:
        raise ValidationFailed("A password of at least 10 characters is required.")
    user = User(email=body.email.lower(), full_name=body.full_name, password_hash=hash_password(body.password), role_id=0)
    _apply_user(db, user, body)
    db.add(user)
    db.flush()
    audit.record(db, action="user.created", entity_type="user", entity_id=user.id, actor=actor,
                 summary=f"Created user {user.email} ({body.role})")
    db.commit()
    return user_public(user) or {}


@router.put("/users/{user_id}")
def update_user(user_id: int, body: UserIn, actor: User = Depends(require("users:manage")), db: Session = Depends(db_session)) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("User not found.")
    before = user_public(user)
    _apply_user(db, user, body)
    if body.password:
        user.password_hash = hash_password(body.password)
    audit.record(db, action="user.updated", entity_type="user", entity_id=user.id, actor=actor, summary=f"Updated user {user.email}",
                 details={"before": before, "after": user_public(user), "password_changed": bool(body.password)})
    db.commit()
    return user_public(user) or {}


@router.get("/roles")
def list_roles(user: User = Depends(require("users:read")), db: Session = Depends(db_session)) -> dict[str, Any]:
    return {"items": [{"code": r.code, "name": r.name, "description": r.description, "permissions": r.permissions}
                      for r in db.execute(select(Role).order_by(Role.id)).scalars()]}


@router.get("/customers")
def search_customers(q: str = "", user: User = Depends(require("complaint:read_all")), db: Session = Depends(db_session)) -> dict[str, Any]:
    query = select(Customer)
    if q:
        like = f"%{q.lower()}%"
        query = query.where(func.lower(Customer.customer_ref).like(like) | func.lower(Customer.full_name).like(like)
                            | func.lower(Customer.email).like(like))
    rows = db.execute(query.order_by(Customer.customer_ref).limit(25)).scalars().all()
    return {"items": [{"customer_ref": c.customer_ref, "full_name": c.full_name, "email": c.email, "customer_type": c.customer_type}
                      for c in rows]}
