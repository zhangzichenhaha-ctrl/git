import hashlib
import hmac
import logging
import os
import re
import secrets
from datetime import datetime, timedelta
from uuid import uuid4

import bcrypt
import models
from email_service import (
    EmailConfigurationError,
    EmailDeliveryError,
    email_verification_enabled,
    send_verification_email,
)

from fastapi import Depends, FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from ai_service import (
    judge_experience_relevance,
    judge_skill_similarity,
    normalize_skills,
    parse_project_requirement,
    parse_user_profile,
)
from database import DATABASE_URL, get_db, init_db
from models import (
    FavoriteProject,
    Feedback,
    MatchRecord,
    Notification,
    OwnerInterest,
    Project,
    ProjectProfile,
    User,
    UserSession,
    EmailVerification,
    UserProfile,
)

app = FastAPI()
ADMIN_TOKENS: dict[str, int] = {}
logger = logging.getLogger(__name__)


@app.on_event("startup")
def startup_event() -> None:
    if DATABASE_URL.startswith("sqlite"):
        init_db()

@app.get("/")
def root():
    return {"message": "欢迎来到知遇Link API"}

@app.get("/api/health")
def health_check():
    return {"status": "ok"}

class ProfileRequest(BaseModel):
    raw_text: str


class AuthRegisterRequest(BaseModel):
    username: str
    password: str
    confirm_password: str
    email: str
    school: str
    major: str
    grade: str


class AuthLoginRequest(BaseModel):
    username: str
    password: str


class EmailCodeRequest(BaseModel):
    code: str


class AdminLoginRequest(BaseModel):
    admin_name: str
    password: str


class AdminRegisterRequest(BaseModel):
    admin_name: str
    email: str
    password: str
    confirm_password: str


class AdminReviewActionRequest(BaseModel):
    admin_name: str
    action: str


class MatchRequest(BaseModel):
    user_profile: dict
    project_profile: dict


class SaveProfileRequest(BaseModel):
    user_id: int
    raw_text: str
    parsed_data: dict


class CreateProjectRequest(BaseModel):
    owner_id: int
    name: str
    raw_text: str
    parsed_data: dict
    scope: str = "same_school"


class InterestRequest(BaseModel):
    user_id: int
    project_id: int


class OwnerCandidateActionRequest(BaseModel):
    owner_id: int
    user_id: int
    project_id: int
    action: str


class ContactSettingsRequest(BaseModel):
    user_id: int
    contact_method: str = ""
    contact_value: str = ""
    contact_visible: bool = False


class NotificationActionRequest(BaseModel):
    user_id: int


class ProjectStatusRequest(BaseModel):
    owner_id: int
    project_id: int
    status: str


class FeedbackRequest(BaseModel):
    user_id: int
    category: str
    content: str
    contact_email: str = ""
    source_page: str = ""


class FeedbackReplyRequest(BaseModel):
    admin_name: str
    status: str
    admin_reply: str = ""


class AdminProjectModerationRequest(BaseModel):
    action: str
    reason: str = ""


class AdminBanUserRequest(BaseModel):
    reason: str = ""


def _hash_password(password: str) -> str:
    """Hash a password with a per-user salt for database storage."""
    iterations = 600_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, password_hash: str | None) -> bool:
    """Verify a password against the stored PBKDF2 hash."""
    if not password_hash:
        return False

    try:
        algorithm, iterations_text, salt_text, digest_text = password_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_text)
        expected_digest = bytes.fromhex(digest_text)
        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return secrets.compare_digest(actual_digest, expected_digest)
    except (TypeError, ValueError):
        return False


def _verify_bcrypt_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False

    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _email_code_hash(code: str) -> str:
    pepper = os.getenv("EMAIL_CODE_PEPPER", "").strip()
    if not pepper:
        raise EmailConfigurationError("EMAIL_CODE_PEPPER is not configured")
    return hmac.new(
        pepper.encode("utf-8"), code.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _authenticated_user(
    authorization: str | None,
    db: Session,
) -> tuple[User | None, JSONResponse | None]:
    if not authorization or not authorization.startswith("Bearer "):
        return None, JSONResponse(status_code=401, content={"error": "authentication_required"})
    token = authorization.removeprefix("Bearer ").strip()
    session = db.scalar(
        select(UserSession).where(
            UserSession.token_hash == _token_hash(token),
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.now(),
        )
    )
    if session is None:
        return None, JSONResponse(status_code=401, content={"error": "invalid_user_token"})
    user = db.get(User, session.user_id)
    if user is None or user.role != "user":
        return None, JSONResponse(status_code=401, content={"error": "invalid_user_token"})
    if user.is_banned:
        return None, JSONResponse(
            status_code=403,
            content={"error": "account_banned", "reason": user.ban_reason or ""},
        )
    return user, None


def _new_user_session(db: Session, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            user_id=user_id,
            token_hash=_token_hash(token),
            expires_at=datetime.now() + timedelta(days=30),
        )
    )
    return token


def _masked_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[:1] + "*"
    else:
        masked_local = local[:2] + "***"
    return f"{masked_local}@{domain}" if domain else "***"


def _add_notification(
    db: Session,
    *,
    user_id: int,
    notification_type: str,
    title: str,
    content: str,
    related_project_id: int | None = None,
    related_user_id: int | None = None,
) -> None:
    db.add(
        Notification(
            user_id=user_id,
            type=notification_type,
            title=title,
            content=content,
            related_project_id=related_project_id,
            related_user_id=related_user_id,
        )
    )


@app.post("/api/auth/register")
def auth_register(
    request: AuthRegisterRequest,
    db: Session = Depends(get_db),
):
    username = request.username.strip()
    email = request.email.strip().lower()
    school = request.school.strip()
    major = request.major.strip()
    grade = request.grade.strip()

    if request.password != request.confirm_password:
        return JSONResponse(
            status_code=400,
            content={"error": "password_mismatch"},
        )

    if len(request.password) < 8:
        return JSONResponse(
            status_code=400,
            content={"error": "password_too_short"},
        )

    if (
        not username
        or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
        or not request.password.strip()
    ):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_input"},
        )

    existing_username = db.scalar(
        select(User).where(User.username == username)
    )
    if existing_username:
        return JSONResponse(
            status_code=400,
            content={"error": "username_taken"},
        )

    existing_email = db.scalar(select(User).where(User.email == email))
    if existing_email:
        return JSONResponse(
            status_code=400,
            content={"error": "email_taken"},
        )

    user = User(
        username=username,
        email=email,
        password_hash=_hash_password(request.password),
        school=school,
        major=major,
        grade=grade,
    )
    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        return JSONResponse(
            status_code=400,
            content={"error": "registration_failed"},
        )
    except SQLAlchemyError:
        db.rollback()
        return JSONResponse(
            status_code=500,
            content={"error": "registration_failed"},
        )

    return {"status": "ok"}


@app.post("/api/admin/register")
def admin_register(
    request: AdminRegisterRequest,
    db: Session = Depends(get_db),
):
    admin_name = request.admin_name.strip()
    email = request.email.strip()
    if not admin_name or len(admin_name) > 100:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_admin_name"},
        )
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_email"},
        )
    if request.password != request.confirm_password:
        return JSONResponse(
            status_code=400,
            content={"error": "password_mismatch"},
        )
    if len(request.password) < 8:
        return JSONResponse(
            status_code=400,
            content={"error": "password_too_short"},
        )

    name_matches = db.scalars(
        select(User)
        .where(
            (User.admin_name == admin_name) | (User.username == admin_name)
        )
        .order_by(User.created_at.desc())
    ).all()
    reusable_admin = None
    for existing in name_matches:
        if existing.role != "admin":
            return JSONResponse(
                status_code=400,
                content={"error": "admin_name_exists"},
            )
        if existing.admin_status in {"pending", "approved"}:
            return JSONResponse(
                status_code=400,
                content={"error": "admin_name_exists"},
            )
        if existing.admin_status == "rejected" and reusable_admin is None:
            reusable_admin = existing

    email_matches = db.scalars(
        select(User).where(User.email == email)
    ).all()
    rejected_email_admin = None
    for existing in email_matches:
        if reusable_admin is not None and existing.id == reusable_admin.id:
            continue
        if (
            existing.role != "admin"
            or existing.admin_status in {"pending", "approved"}
        ):
            return JSONResponse(
                status_code=400,
                content={"error": "email_exists"},
            )
        if existing.admin_status == "rejected":
            rejected_email_admin = existing

    if reusable_admin is None:
        reusable_admin = rejected_email_admin
    elif (
        rejected_email_admin is not None
        and rejected_email_admin.id != reusable_admin.id
    ):
        return JSONResponse(
            status_code=400,
            content={"error": "email_exists"},
        )

    password_hash = bcrypt.hashpw(
        request.password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    if reusable_admin is not None:
        reusable_admin.admin_name = admin_name
        reusable_admin.username = admin_name
        reusable_admin.email = email
        reusable_admin.admin_password_hash = password_hash
        reusable_admin.admin_status = "pending"
        reusable_admin.is_banned = False
        reusable_admin.banned_at = None
        reusable_admin.ban_reason = None
        reusable_admin.created_at = datetime.now()
        admin = reusable_admin
    else:
        admin = User(
            admin_name=admin_name,
            username=admin_name,
            email=email,
            admin_password_hash=password_hash,
            user_password_hash=None,
            role="admin",
            admin_status="pending",
        )
    try:
        db.add(admin)
        db.commit()
    except IntegrityError:
        db.rollback()
        name_exists = db.scalar(
            select(User).where(
                (User.admin_name == admin_name) | (User.username == admin_name)
            )
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": "admin_name_exists" if name_exists else "email_exists"
            },
        )
    except SQLAlchemyError:
        db.rollback()
        return _server_error()
    return {"status": "ok", "admin_status": "pending"}


@app.post("/api/auth/login")
def auth_login(
    request: AuthLoginRequest,
    db: Session = Depends(get_db),
):
    username = request.username.strip()

    user = db.scalar(select(User).where(User.username == username))
    if not user:
        return JSONResponse(
            status_code=400,
            content={"error": "user_not_found"},
        )

    if not _verify_password(request.password, user.password_hash):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_password"},
        )

    if user.is_banned:
        return JSONResponse(
            status_code=403,
            content={
                "error": "account_banned",
                "reason": user.ban_reason or "",
            },
        )

    token = _new_user_session(db, user.id)
    db.commit()
    return {
        "status": "ok",
        "token": token,
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "email_verified": user.email_verified_at is not None,
        "school": user.school,
    }


@app.post("/api/auth/logout")
def auth_logout(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        session = db.scalar(
            select(UserSession).where(UserSession.token_hash == _token_hash(token))
        )
        if session is not None:
            session.revoked_at = datetime.now()
            db.commit()
    return {"success": True}


@app.get("/api/account_status/{user_id}")
def account_status(user_id: int, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None or user.role != "user":
        return {"success": True, "exists": False, "is_banned": False}
    return {
        "success": True,
        "exists": True,
        "is_banned": bool(user.is_banned),
        "reason": user.ban_reason or "",
    }


@app.get("/api/email/status")
def email_status(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    user, error = _authenticated_user(authorization, db)
    if error:
        return error
    latest = db.scalar(
        select(EmailVerification)
        .where(EmailVerification.user_id == user.id)
        .order_by(EmailVerification.created_at.desc())
    )
    resend_after = 0
    if latest:
        interval_seconds = int(os.getenv("EMAIL_SEND_INTERVAL_SECONDS", "60"))
        resend_after = max(
            0,
            int(
                (
                    latest.created_at
                    + timedelta(seconds=interval_seconds)
                    - datetime.now()
                ).total_seconds()
            ),
        )
    return {
        "success": True,
        "enabled": email_verification_enabled(),
        "email": _masked_email(user.email),
        "verified": user.email_verified_at is not None,
        "verified_at": user.email_verified_at.isoformat() if user.email_verified_at else None,
        "resend_after": resend_after,
    }


@app.post("/api/email/send_code")
def send_email_code(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    user, error = _authenticated_user(authorization, db)
    if error:
        return error
    if not email_verification_enabled():
        return JSONResponse(status_code=503, content={"error": "email_verification_disabled"})
    if user.email_verified_at is not None:
        return JSONResponse(status_code=400, content={"error": "email_already_verified"})

    now = datetime.now()
    interval_seconds = int(os.getenv("EMAIL_SEND_INTERVAL_SECONDS", "60"))
    latest = db.scalar(
        select(EmailVerification)
        .where(EmailVerification.user_id == user.id)
        .order_by(EmailVerification.created_at.desc())
    )
    if latest and latest.created_at + timedelta(seconds=interval_seconds) > now:
        seconds = int(
            (latest.created_at + timedelta(seconds=interval_seconds) - now).total_seconds()
        )
        return JSONResponse(
            status_code=429,
            content={"error": "send_too_frequent", "resend_after": max(1, seconds)},
        )
    daily_count = db.scalar(
        select(func.count(EmailVerification.id)).where(
            EmailVerification.user_id == user.id,
            EmailVerification.created_at >= now - timedelta(days=1),
        )
    ) or 0
    email_daily_count = db.scalar(
        select(func.count(EmailVerification.id)).where(
            EmailVerification.email == user.email.lower(),
            EmailVerification.created_at >= now - timedelta(days=1),
        )
    ) or 0
    daily_limit = int(os.getenv("EMAIL_DAILY_LIMIT", "10"))
    if daily_count >= daily_limit or email_daily_count >= daily_limit:
        return JSONResponse(status_code=429, content={"error": "daily_limit_reached"})

    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_minutes = int(os.getenv("EMAIL_CODE_EXPIRE_MINUTES", "10"))
    try:
        code_hash = _email_code_hash(code)
        send_verification_email(user.email, code, expires_minutes)
        db.execute(
            delete(EmailVerification).where(
                EmailVerification.created_at < now - timedelta(days=7)
            )
        )
        db.execute(
            delete(EmailVerification).where(
                EmailVerification.user_id == user.id,
                EmailVerification.consumed_at.is_(None),
            )
        )
        db.add(
            EmailVerification(
                user_id=user.id,
                email=user.email.lower(),
                code_hash=code_hash,
                expires_at=now + timedelta(minutes=expires_minutes),
            )
        )
        db.commit()
    except EmailConfigurationError:
        db.rollback()
        return JSONResponse(status_code=503, content={"error": "email_verification_unavailable"})
    except EmailDeliveryError:
        db.rollback()
        return JSONResponse(status_code=502, content={"error": "email_delivery_failed"})
    return {
        "success": True,
        "expires_in": expires_minutes * 60,
        "resend_after": interval_seconds,
    }


@app.post("/api/email/verify")
def verify_email_code(
    request: EmailCodeRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    user, error = _authenticated_user(authorization, db)
    if error:
        return error
    if user.email_verified_at is not None:
        return {"success": True, "verified": True, "verified_at": user.email_verified_at.isoformat()}

    verification = db.scalar(
        select(EmailVerification)
        .where(
            EmailVerification.user_id == user.id,
            EmailVerification.email == user.email.lower(),
            EmailVerification.consumed_at.is_(None),
        )
        .order_by(EmailVerification.created_at.desc())
    )
    if verification is None:
        return JSONResponse(status_code=400, content={"error": "code_expired"})
    max_attempts = int(os.getenv("EMAIL_MAX_ATTEMPTS", "5"))
    if verification.attempts >= max_attempts:
        return JSONResponse(status_code=429, content={"error": "too_many_attempts"})
    if verification.expires_at <= datetime.now():
        verification.consumed_at = datetime.now()
        db.commit()
        return JSONResponse(status_code=400, content={"error": "code_expired"})
    try:
        valid = secrets.compare_digest(verification.code_hash, _email_code_hash(request.code.strip()))
    except EmailConfigurationError:
        return JSONResponse(status_code=503, content={"error": "email_verification_unavailable"})
    if not valid:
        verification.attempts += 1
        db.commit()
        return JSONResponse(status_code=400, content={"error": "invalid_code", "remaining_attempts": max_attempts - verification.attempts})
    now = datetime.now()
    verification.consumed_at = now
    user.email_verified_at = now
    db.commit()
    return {"success": True, "verified": True, "verified_at": now.isoformat()}


@app.post("/api/admin/login")
def admin_login(
    request: AdminLoginRequest,
    db: Session = Depends(get_db),
):
    admin_name = request.admin_name.strip()
    admin = db.scalar(
        select(User).where(
            User.admin_name == admin_name,
            User.role == "admin",
        )
    )
    if not admin:
        return JSONResponse(
            status_code=400,
            content={"error": "admin_not_found"},
        )

    if not _verify_bcrypt_password(
        request.password,
        admin.admin_password_hash,
    ):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_password"},
        )

    if admin.is_banned:
        return JSONResponse(
            status_code=403,
            content={
                "error": "account_banned",
                "reason": admin.ban_reason or "",
            },
        )

    if admin.admin_status != "approved":
        return JSONResponse(
            status_code=400,
            content={"error": "admin_not_approved"},
        )

    token = str(uuid4())
    ADMIN_TOKENS[token] = admin.id
    return {
        "status": "ok",
        "token": token,
        "admin_name": admin.admin_name or admin.username,
        "admin_status": admin.admin_status,
    }


def _require_admin_token(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return "admin_token_required"

    token = authorization.removeprefix("Bearer ").strip()
    if token not in ADMIN_TOKENS:
        return "invalid_admin_token"

    return None


def _admin_auth_response(authorization: str | None) -> JSONResponse | None:
    error = _require_admin_token(authorization)
    if error:
        return JSONResponse(status_code=401, content={"error": error})
    return None


def _server_error() -> JSONResponse:
    return JSONResponse(status_code=500, content={"error": "server_error"})


def _serialize_user(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "school": user.school,
        "major": user.major,
        "grade": user.grade,
        "role": user.role,
        "created_at": user.created_at.isoformat(),
        "is_banned": user.is_banned,
        "banned_at": user.banned_at.isoformat() if user.banned_at else None,
        "ban_reason": user.ban_reason or "",
    }


@app.get("/api/admin/users")
def admin_users(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        users = db.scalars(
            select(User)
            .where(User.role == "user")
            .order_by(User.created_at.desc())
        ).all()
        return [_serialize_user(user) for user in users]
    except Exception:
        return _server_error()


@app.get("/api/admin/feedback")
def admin_feedback(
    status: str = "all",
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error
    allowed_statuses = {"all", "pending", "reviewing", "resolved", "rejected"}
    if status not in allowed_statuses:
        return JSONResponse(status_code=400, content={"error": "invalid_status"})
    try:
        query = select(Feedback, User).join(User, User.id == Feedback.user_id)
        if status != "all":
            query = query.where(Feedback.status == status)
        rows = db.execute(query.order_by(Feedback.created_at.desc())).all()
        category_rows = db.execute(
            select(Feedback.category, func.count(Feedback.id)).group_by(Feedback.category)
        ).all()
        status_rows = db.execute(
            select(Feedback.status, func.count(Feedback.id)).group_by(Feedback.status)
        ).all()
        return {
            "success": True,
            "feedback": [
                {
                    "feedback_id": item.id,
                    "user_id": user.id,
                    "username": user.username,
                    "category": item.category,
                    "content": item.content,
                    "contact_email": item.contact_email or "",
                    "source_page": item.source_page or "",
                    "status": item.status,
                    "admin_reply": item.admin_reply or "",
                    "created_at": item.created_at,
                    "updated_at": item.updated_at,
                }
                for item, user in rows
            ],
            "statistics": {
                "by_category": {str(key): int(value) for key, value in category_rows},
                "by_status": {str(key): int(value) for key, value in status_rows},
                "total": sum(int(value) for _, value in category_rows),
            },
        }
    except Exception:
        return _server_error()


@app.post("/api/admin/feedback/{feedback_id}/reply")
def admin_reply_feedback(
    feedback_id: int,
    request: FeedbackReplyRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error
    if request.status not in {"pending", "reviewing", "resolved", "rejected"}:
        return JSONResponse(status_code=400, content={"error": "invalid_status"})
    feedback = db.get(Feedback, feedback_id)
    if feedback is None:
        return JSONResponse(status_code=404, content={"error": "feedback_not_found"})
    feedback.status = request.status
    feedback.admin_reply = request.admin_reply.strip()[:3000] or None
    try:
        if feedback.admin_reply:
            _add_notification(
                db,
                user_id=feedback.user_id,
                notification_type="feedback_reply",
                title="你的反馈有了新回复",
                content=feedback.admin_reply,
            )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return _server_error()
    return {"success": True, "status": feedback.status}


@app.get("/api/admin/users/search")
def admin_users_search(
    username: str = "",
    school: str = "",
    major: str = "",
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        conditions = [User.role == "user"]
        if username.strip():
            conditions.append(User.username.ilike(f"%{username.strip()}%"))
        if school.strip():
            conditions.append(User.school.ilike(f"%{school.strip()}%"))
        if major.strip():
            conditions.append(User.major.ilike(f"%{major.strip()}%"))

        statement = select(User).order_by(User.created_at.desc())
        if conditions:
            statement = statement.where(*conditions)
        users = db.scalars(statement).all()
        return [_serialize_user(user) for user in users]
    except Exception:
        return _server_error()


def _serialize_competition(project: Project) -> dict:
    return {
        "id": project.id,
        "title": project.name,
        "creator": project.owner.username if project.owner else "",
        "description": project.raw_text or "",
        "status": project.status,
        "moderation_status": project.moderation_status,
        "moderation_reason": project.moderation_reason or "",
        "moderated_at": (
            project.moderated_at.isoformat() if project.moderated_at else None
        ),
        "created_at": project.created_at.isoformat(),
    }


@app.get("/api/admin/statistics")
def admin_statistics(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error
    try:
        project_status_rows = db.execute(
            select(Project.status, func.count(Project.id)).group_by(Project.status)
        ).all()
        feedback_status_rows = db.execute(
            select(Feedback.status, func.count(Feedback.id)).group_by(Feedback.status)
        ).all()
        return {
            "success": True,
            "users": db.scalar(
                select(func.count(User.id)).where(User.role == "user")
            ) or 0,
            "projects": db.scalar(select(func.count(Project.id))) or 0,
            "active_projects": db.scalar(
                select(func.count(Project.id)).where(
                    Project.moderation_status == "active"
                )
            ) or 0,
            "removed_projects": db.scalar(
                select(func.count(Project.id)).where(
                    Project.moderation_status == "removed"
                )
            ) or 0,
            "favorites": db.scalar(select(func.count(FavoriteProject.id))) or 0,
            "mutual_matches": db.scalar(
                select(func.count(OwnerInterest.id)).where(
                    OwnerInterest.status == "interested"
                )
            ) or 0,
            "pending_feedback": db.scalar(
                select(func.count(Feedback.id)).where(Feedback.status == "pending")
            ) or 0,
            "project_statuses": {
                str(key): int(value) for key, value in project_status_rows
            },
            "feedback_statuses": {
                str(key): int(value) for key, value in feedback_status_rows
            },
        }
    except Exception:
        return _server_error()


@app.get("/api/admin/competitions")
def admin_competitions(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        projects = db.scalars(
            select(Project).order_by(Project.created_at.desc())
        ).all()
        return [_serialize_competition(project) for project in projects]
    except Exception:
        return _server_error()


@app.get("/api/admin/competitions/search")
def admin_competitions_search(
    title: str = "",
    creator: str = "",
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        statement = (
            select(Project)
            .join(User, Project.owner_id == User.id)
            .order_by(Project.created_at.desc())
        )
        if title.strip():
            statement = statement.where(
                Project.name.ilike(f"%{title.strip()}%")
            )
        if creator.strip():
            statement = statement.where(
                User.username.ilike(f"%{creator.strip()}%")
            )

        projects = db.scalars(statement).all()
        return [_serialize_competition(project) for project in projects]
    except Exception:
        return _server_error()


@app.post("/api/admin/project/{project_id}/moderation")
def admin_moderate_project(
    project_id: int,
    request: AdminProjectModerationRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error
    if request.action not in {"remove", "restore"}:
        return JSONResponse(status_code=400, content={"error": "invalid_action"})
    project = db.get(Project, project_id)
    if project is None:
        return JSONResponse(status_code=404, content={"error": "competition_not_found"})

    reason = request.reason.strip()[:1000]
    if request.action == "remove" and not reason:
        return JSONResponse(status_code=400, content={"error": "reason_required"})

    changed = False
    if request.action == "remove" and project.moderation_status != "removed":
        project.moderation_previous_status = project.status
        project.moderation_status = "removed"
        project.moderation_reason = reason
        project.moderated_at = datetime.now()
        project.status = "closed"
        changed = True
        _add_notification(
            db,
            user_id=project.owner_id,
            notification_type="project_moderated",
            title="你的项目已被平台下架",
            content=f"项目“{project.name}”已被下架。原因：{reason}",
            related_project_id=project.id,
        )
        interested_user_ids = db.scalars(
            select(MatchRecord.user_id).where(
                MatchRecord.project_id == project.id,
                MatchRecord.status == "interested",
            )
        ).all()
        for interested_user_id in set(interested_user_ids):
            _add_notification(
                db,
                user_id=interested_user_id,
                notification_type="project_moderated",
                title="你关注的项目已被平台下架",
                content=f"项目“{project.name}”当前已停止展示和招募。",
                related_project_id=project.id,
            )
    elif request.action == "restore" and project.moderation_status == "removed":
        restored_status = project.moderation_previous_status or "recruiting"
        if restored_status not in {"recruiting", "full", "closed", "completed"}:
            restored_status = "recruiting"
        project.status = restored_status
        project.moderation_status = "active"
        project.moderation_reason = reason or None
        project.moderation_previous_status = None
        project.moderated_at = datetime.now()
        changed = True
        _add_notification(
            db,
            user_id=project.owner_id,
            notification_type="project_restored",
            title="你的项目已恢复展示",
            content=f"项目“{project.name}”已通过平台复核并恢复。",
            related_project_id=project.id,
        )
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return _server_error()
    return {
        "success": True,
        "moderation_status": project.moderation_status,
        "status": project.status,
        "changed": changed,
    }


@app.get("/api/admin/review/list")
def admin_review_list(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        statement = (
            select(User)
            .where(
                User.role == "admin",
                User.admin_status == "pending",
            )
            .order_by(User.created_at.asc())
        )
        admins = db.scalars(statement).all()
        return [
            {
                "admin_name": admin.admin_name or admin.username,
                "username": admin.username,
                "created_at": admin.created_at.isoformat(),
                "admin_status": admin.admin_status,
            }
            for admin in admins
        ]
    except Exception:
        return _server_error()


@app.post("/api/admin/review/action")
def admin_review_action(
    request: AdminReviewActionRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    action = request.action.strip().lower()
    if action not in {"approve", "reject"}:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_action"},
        )

    try:
        actor_id = ADMIN_TOKENS.get(
            authorization.removeprefix("Bearer ").strip()
            if authorization and authorization.startswith("Bearer ")
            else ""
        )
        admin = db.scalar(
            select(User).where(
                User.role == "admin",
                (User.admin_name == request.admin_name.strip())
                | (User.username == request.admin_name.strip()),
            )
        )
        if not admin:
            return JSONResponse(
                status_code=404,
                content={"error": "admin_not_found"},
            )
        if admin.id == actor_id:
            return JSONResponse(
                status_code=400,
                content={"error": "cannot_review_self"},
            )
        if admin.admin_status != "pending":
            return JSONResponse(
                status_code=400,
                content={"error": "admin_not_pending"},
            )

        admin.admin_status = "approved" if action == "approve" else "rejected"
        db.commit()
        return {
            "status": "ok",
            "admin_name": admin.admin_name or admin.username,
            "admin_status": admin.admin_status,
        }
    except Exception:
        db.rollback()
        return _server_error()


@app.get("/api/admin/user/{username}")
def admin_user_detail(
    username: str,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            return JSONResponse(
                status_code=404,
                content={"error": "user_not_found"},
            )
        return _serialize_user(user)
    except Exception:
        return _server_error()


@app.get("/api/admin/competition/{competition_id}")
def admin_competition_detail(
    competition_id: int,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        project = db.get(Project, competition_id)
        if not project:
            return JSONResponse(
                status_code=404,
                content={"error": "competition_not_found"},
            )
        return _serialize_competition(project)
    except Exception:
        return _server_error()


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        user = db.get(User, user_id)
        if user is None:
            return JSONResponse(
                status_code=404,
                content={"error": "user_not_found"},
            )
        if user.role != "user":
            return JSONResponse(
                status_code=403,
                content={"error": "protected_account"},
            )

        project_ids = list(
            db.scalars(
                select(Project.id).where(Project.owner_id == user_id)
            ).all()
        )
        project_count = len(project_ids)

        if project_ids:
            db.execute(
                delete(Notification).where(
                    Notification.related_project_id.in_(project_ids)
                )
            )
            db.execute(
                delete(ProjectProfile).where(
                    ProjectProfile.project_id.in_(project_ids)
                )
            )
            db.execute(
                delete(MatchRecord).where(
                    MatchRecord.project_id.in_(project_ids)
                )
            )
            db.execute(
                delete(OwnerInterest).where(
                    OwnerInterest.project_id.in_(project_ids)
                )
            )
            db.execute(
                delete(FavoriteProject).where(
                    FavoriteProject.project_id.in_(project_ids)
                )
            )

        db.execute(delete(UserProfile).where(UserProfile.user_id == user_id))
        db.execute(
            delete(Notification).where(
                or_(
                    Notification.user_id == user_id,
                    Notification.related_user_id == user_id,
                )
            )
        )
        db.execute(
            delete(FavoriteProject).where(FavoriteProject.user_id == user_id)
        )
        db.execute(delete(Feedback).where(Feedback.user_id == user_id))
        db.execute(delete(EmailVerification).where(EmailVerification.user_id == user_id))
        db.execute(delete(UserSession).where(UserSession.user_id == user_id))
        db.execute(delete(MatchRecord).where(MatchRecord.user_id == user_id))
        db.execute(delete(OwnerInterest).where(OwnerInterest.user_id == user_id))
        db.execute(delete(Project).where(Project.owner_id == user_id))
        db.execute(delete(User).where(User.id == user_id))
        db.commit()
        return {
            "success": True,
            "deleted_user": user.username,
            "deleted_projects": project_count,
        }
    except SQLAlchemyError:
        db.rollback()
        return _server_error()


@app.delete("/api/admin/competitions/{project_id}")
def admin_delete_competition(
    project_id: int,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        project = db.get(Project, project_id)
        if project is None:
            return JSONResponse(
                status_code=404,
                content={"error": "project_not_found"},
            )

        project_name = project.name
        db.execute(
            delete(Notification).where(
                Notification.related_project_id == project_id
            )
        )
        db.execute(
            delete(ProjectProfile).where(ProjectProfile.project_id == project_id)
        )
        db.execute(
            delete(MatchRecord).where(MatchRecord.project_id == project_id)
        )
        db.execute(
            delete(OwnerInterest).where(OwnerInterest.project_id == project_id)
        )
        db.execute(
            delete(FavoriteProject).where(
                FavoriteProject.project_id == project_id
            )
        )
        db.execute(delete(Project).where(Project.id == project_id))
        db.commit()
        return {
            "success": True,
            "deleted_project": project_name,
        }
    except SQLAlchemyError:
        db.rollback()
        return _server_error()


@app.post("/api/admin/users/{user_id}/ban")
def admin_ban_user(
    user_id: int,
    request: AdminBanUserRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        user = db.get(User, user_id)
        if user is None:
            return JSONResponse(
                status_code=404,
                content={"error": "user_not_found"},
            )
        if user.role != "user":
            return JSONResponse(
                status_code=403,
                content={"error": "protected_account"},
            )

        if user.is_banned:
            return {
                "success": True,
                "changed": False,
                "closed_projects": 0,
            }

        user.is_banned = True
        user.banned_at = datetime.now()
        user.ban_reason = request.reason.strip()[:255] or None
        db.execute(
            delete(UserSession).where(UserSession.user_id == user_id)
        )
        projects = db.scalars(
            select(Project).where(Project.owner_id == user_id)
        ).all()
        for project in projects:
            project.status = "closed"
        db.commit()
        return {
            "success": True,
            "changed": True,
            "closed_projects": len(projects),
        }
    except SQLAlchemyError:
        db.rollback()
        return _server_error()


@app.post("/api/admin/users/{user_id}/unban")
def admin_unban_user(
    user_id: int,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    auth_error = _admin_auth_response(authorization)
    if auth_error:
        return auth_error

    try:
        user = db.get(User, user_id)
        if user is None:
            return JSONResponse(
                status_code=404,
                content={"error": "user_not_found"},
            )
        if user.role != "user":
            return JSONResponse(
                status_code=403,
                content={"error": "protected_account"},
            )

        if not user.is_banned:
            return {"success": True, "changed": False}

        user.is_banned = False
        user.banned_at = None
        user.ban_reason = None
        db.commit()
        return {"success": True, "changed": True}
    except SQLAlchemyError:
        db.rollback()
        return _server_error()


@app.post("/api/save_profile")
def save_profile(request: SaveProfileRequest, db: Session = Depends(get_db)):
    if db.get(User, request.user_id) is None:
        return {"success": False, "message": "用户不存在"}

    profile = db.scalar(
        select(UserProfile).where(UserProfile.user_id == request.user_id)
    )
    data = request.parsed_data
    values = {
        "raw_text": request.raw_text,
        "skills": data.get("skills", []),
        "skill_levels": data.get("skill_levels", {}),
        "experience": data.get("experience", []),
        "interests": data.get("interests", []),
        "preference": data.get("preference", ""),
        "time_commitment": data.get("time_commitment", "未知"),
    }

    if profile:
        for field, value in values.items():
            setattr(profile, field, value)
    else:
        profile = UserProfile(user_id=request.user_id, **values)
        db.add(profile)

    try:
        db.execute(
            delete(OwnerInterest).where(OwnerInterest.user_id == request.user_id)
        )
        db.execute(
            delete(MatchRecord).where(MatchRecord.user_id == request.user_id)
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "画像保存失败"}

    return {"success": True}


@app.post("/api/create_project")
def create_project(request: CreateProjectRequest, db: Session = Depends(get_db)):
    if db.get(User, request.owner_id) is None:
        return {"success": False, "message": "用户不存在"}

    data = request.parsed_data
    project = Project(
        owner_id=request.owner_id,
        name=request.name,
        raw_text=request.raw_text,
        scope=request.scope,
    )

    try:
        db.add(project)
        db.flush()
        db.add(
            ProjectProfile(
                project_id=project.id,
                required_skills=data.get("required_skills", []),
                time_requirement=data.get("time_requirement", "未知"),
                priority=data.get("priority", []),
                project_type=data.get("project_type", ""),
                background=data.get("background", ""),
            )
        )
        db.commit()
        db.refresh(project)
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "项目创建失败"}

    return {"success": True, "project_id": project.id}


@app.post("/api/project_status")
def update_project_status(
    request: ProjectStatusRequest,
    db: Session = Depends(get_db),
):
    project = db.get(Project, request.project_id)
    if not project:
        return {"success": False, "message": "项目不存在"}
    if project.owner_id != request.owner_id:
        return {"success": False, "message": "无权修改该项目"}
    if project.moderation_status == "removed":
        return {"success": False, "message": "项目已被平台下架，无法修改状态"}

    allowed_statuses = {"recruiting", "full", "closed", "completed"}
    if request.status not in allowed_statuses:
        return {"success": False, "message": "项目状态无效"}

    previous_status = project.status
    project.status = request.status
    try:
        if previous_status != request.status:
            status_labels = {
                "recruiting": "恢复招募",
                "full": "已满员",
                "closed": "已关闭",
                "completed": "已完成",
            }
            interested_user_ids = db.scalars(
                select(MatchRecord.user_id).where(
                    MatchRecord.project_id == project.id,
                    MatchRecord.status == "interested",
                )
            ).all()
            for interested_user_id in set(interested_user_ids):
                _add_notification(
                    db,
                    user_id=interested_user_id,
                    notification_type="project_status_changed",
                    title="项目状态发生变化",
                    content=(
                        f"你关注的项目“{project.name}”"
                        f"已更新为{status_labels[request.status]}。"
                    ),
                    related_project_id=project.id,
                )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "项目状态更新失败"}
    return {"success": True, "status": project.status}


@app.delete("/api/project/{project_id}")
def delete_project(
    project_id: int,
    owner_id: int,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        return {"success": False, "message": "项目不存在"}
    if project.owner_id != owner_id:
        return {"success": False, "message": "无权删除该项目"}

    try:
        interested_user_ids = db.scalars(
            select(MatchRecord.user_id).where(
                MatchRecord.project_id == project_id,
                MatchRecord.status == "interested",
            )
        ).all()
        for interested_user_id in set(interested_user_ids):
            _add_notification(
                db,
                user_id=interested_user_id,
                notification_type="project_deleted",
                title="项目已被删除",
                content=f"你关注的项目“{project.name}”已被发起人删除。",
                related_user_id=project.owner_id,
            )
        db.execute(
            delete(OwnerInterest).where(OwnerInterest.project_id == project_id)
        )
        db.execute(
            delete(MatchRecord).where(MatchRecord.project_id == project_id)
        )
        db.execute(
            delete(FavoriteProject).where(FavoriteProject.project_id == project_id)
        )
        db.execute(
            delete(ProjectProfile).where(ProjectProfile.project_id == project_id)
        )
        db.delete(project)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "项目删除失败"}
    return {"success": True}


@app.get("/api/profile/{user_id}")
def get_profile(user_id: int, db: Session = Depends(get_db)):
    profile = db.scalar(select(UserProfile).where(UserProfile.user_id == user_id))
    if not profile:
        return {"success": False, "message": "画像不存在"}

    return {
        "success": True,
        "user_id": profile.user_id,
        "raw_text": profile.raw_text,
        "skills": profile.skills,
        "skill_levels": profile.skill_levels,
        "experience": profile.experience,
        "interests": profile.interests,
        "preference": profile.preference,
        "time_commitment": profile.time_commitment,
        "contact_method": profile.contact_method or "",
        "contact_value": profile.contact_value or "",
        "contact_visible": bool(profile.contact_visible),
        "updated_at": profile.updated_at,
    }


@app.post("/api/profile/contact")
def save_contact_settings(
    request: ContactSettingsRequest,
    db: Session = Depends(get_db),
):
    user = db.get(User, request.user_id)
    if user is None:
        return {"success": False, "message": "用户不存在"}

    method = request.contact_method.strip().lower()
    value = request.contact_value.strip()
    allowed_methods = {"", "wechat", "qq", "phone", "other"}
    if method not in allowed_methods:
        return {"success": False, "message": "联系方式类型无效"}
    if value and not method:
        return {"success": False, "message": "请选择联系方式类型"}
    if len(value) > 255:
        return {"success": False, "message": "联系方式内容过长"}

    profile = db.scalar(
        select(UserProfile).where(UserProfile.user_id == request.user_id)
    )
    if profile is None:
        profile = UserProfile(
            user_id=request.user_id,
            skills=[],
            skill_levels={},
            experience=[],
            interests=[],
            time_commitment="未知",
        )
        db.add(profile)
    profile.contact_method = method or None
    profile.contact_value = value or None
    profile.contact_visible = bool(request.contact_visible and value)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "联系方式保存失败"}
    return {
        "success": True,
        "contact_method": profile.contact_method or "",
        "contact_visible": bool(profile.contact_visible),
    }


@app.get("/api/projects")
def list_projects(
    keyword: str = "",
    school: str = "",
    project_type: str = "",
    skill: str = "",
    scope: str = "",
    status: str = "recruiting",
    sort: str = "latest",
    page: int = 1,
    page_size: int = 12,
    user_id: int | None = None,
    db: Session = Depends(get_db),
):
    """Return a filterable public project directory."""
    page = max(page, 1)
    page_size = min(max(page_size, 1), 50)
    allowed_scopes = {"", "same_school", "cross_school"}
    allowed_statuses = {"all", "recruiting", "full", "closed", "completed"}
    allowed_sorts = {"latest", "match"}
    if scope not in allowed_scopes:
        return {"success": False, "message": "开放范围筛选无效"}
    if status not in allowed_statuses:
        return {"success": False, "message": "项目状态筛选无效"}
    if sort not in allowed_sorts:
        return {"success": False, "message": "排序方式无效"}

    rows = db.execute(
        select(Project, ProjectProfile, User)
        .outerjoin(ProjectProfile, ProjectProfile.project_id == Project.id)
        .join(User, User.id == Project.owner_id)
    ).all()

    match_records: dict[int, MatchRecord] = {}
    favorite_project_ids: set[int] = set()
    if user_id is not None:
        match_records = {
            record.project_id: record
            for record in db.scalars(
                select(MatchRecord).where(MatchRecord.user_id == user_id)
            ).all()
        }
        favorite_project_ids = set(
            db.scalars(
                select(FavoriteProject.project_id).where(
                    FavoriteProject.user_id == user_id
                )
            ).all()
        )

    keyword_value = keyword.strip().casefold()
    school_value = school.strip().casefold()
    type_value = project_type.strip().casefold()
    skill_value = skill.strip().casefold()
    projects = []

    for project, profile, owner in rows:
        if project.moderation_status == "removed":
            continue
        required_skills = profile.required_skills if profile else []
        searchable = " ".join(
            (
                project.name or "",
                project.raw_text or "",
                profile.background if profile else "",
                profile.project_type if profile else "",
                owner.school or "",
                " ".join(str(item) for item in required_skills),
            )
        ).casefold()
        if keyword_value and keyword_value not in searchable:
            continue
        if school_value and school_value not in (owner.school or "").casefold():
            continue
        profile_type = profile.project_type if profile else ""
        if type_value and type_value not in (profile_type or "").casefold():
            continue
        if skill_value and not any(
            skill_value in str(item).casefold() for item in required_skills
        ):
            continue
        if scope and project.scope != scope:
            continue
        if status != "all" and project.status != status:
            continue

        record = match_records.get(project.id)
        projects.append(
            {
                "project_id": project.id,
                "name": project.name,
                "owner_id": project.owner_id,
                "owner_username": owner.username,
                "owner_school": owner.school or "",
                "raw_text": project.raw_text or "",
                "status": project.status,
                "scope": project.scope,
                "moderation_status": project.moderation_status,
                "moderation_reason": project.moderation_reason or "",
                "created_at": project.created_at,
                "required_skills": required_skills,
                "time_requirement": profile.time_requirement if profile else "未知",
                "priority": profile.priority if profile else [],
                "project_type": profile.project_type if profile else "",
                "background": profile.background if profile else "",
                "total_score": record.total_score if record else None,
                "interested": bool(record and record.status == "interested"),
                "favorited": project.id in favorite_project_ids,
            }
        )

    if sort == "match":
        projects.sort(
            key=lambda item: (
                item["total_score"] is not None,
                item["total_score"] or 0,
                item["created_at"],
            ),
            reverse=True,
        )
    else:
        projects.sort(key=lambda item: item["created_at"], reverse=True)

    total = len(projects)
    start = (page - 1) * page_size
    paginated = projects[start : start + page_size]
    total_pages = max((total + page_size - 1) // page_size, 1)
    return {
        "success": True,
        "projects": paginated,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
        },
    }


@app.get("/api/project/{project_id}")
def get_project(
    project_id: int,
    user_id: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        return {"success": False, "message": "项目不存在"}
    if (
        project.moderation_status == "removed"
        and user_id != project.owner_id
    ):
        return {"success": False, "message": "该项目已被平台下架"}

    profile = db.scalar(
        select(ProjectProfile).where(ProjectProfile.project_id == project_id)
    )
    owner = db.get(User, project.owner_id)
    match_record = (
        db.scalar(
            select(MatchRecord).where(
                MatchRecord.user_id == user_id,
                MatchRecord.project_id == project_id,
            )
        )
        if user_id is not None
        else None
    )
    favorite = (
        db.scalar(
            select(FavoriteProject).where(
                FavoriteProject.user_id == user_id,
                FavoriteProject.project_id == project_id,
            )
        )
        if user_id is not None
        else None
    )
    return {
        "success": True,
        "project_id": project.id,
        "owner_id": project.owner_id,
        "owner_username": owner.username if owner else "",
        "owner_school": owner.school if owner else "",
        "owner_major": owner.major if owner else "",
        "owner_grade": owner.grade if owner else "",
        "name": project.name,
        "raw_text": project.raw_text,
        "status": project.status,
        "scope": project.scope,
        "created_at": project.created_at,
        "required_skills": profile.required_skills if profile else [],
        "time_requirement": profile.time_requirement if profile else "未知",
        "priority": profile.priority if profile else [],
        "project_type": profile.project_type if profile else "",
        "background": profile.background if profile else "",
        "updated_at": profile.updated_at if profile else None,
        "interested": bool(match_record and match_record.status == "interested"),
        "favorited": favorite is not None,
        "moderation_status": project.moderation_status,
        "moderation_reason": (
            project.moderation_reason or ""
            if user_id == project.owner_id
            else ""
        ),
    }


@app.get("/api/my_projects/{user_id}")
def get_my_projects(user_id: int, db: Session = Depends(get_db)):
    if db.get(User, user_id) is None:
        return {"success": False, "message": "用户不存在"}

    rows = db.execute(
        select(Project, ProjectProfile)
        .outerjoin(ProjectProfile, ProjectProfile.project_id == Project.id)
        .where(Project.owner_id == user_id)
        .order_by(Project.created_at.desc(), Project.id.desc())
    ).all()

    projects = []
    for project, profile in rows:
        projects.append(
            {
                "project_id": project.id,
                "name": project.name,
                "status": project.status,
                "scope": project.scope,
                "created_at": project.created_at.date().isoformat(),
                "raw_text": project.raw_text or "",
                "required_skills": profile.required_skills if profile else [],
                "time_requirement": (
                    profile.time_requirement if profile else "未知"
                ),
                "priority": profile.priority if profile else [],
                "project_type": profile.project_type if profile else "",
                "background": profile.background if profile else "",
            }
        )

    return {"success": True, "projects": projects}


def _serialize_favorite(project: Project, favorite: FavoriteProject) -> dict:
    profile = project.profile
    return {
        "favorite_id": favorite.id,
        "project_id": project.id,
        "name": project.name,
        "owner_id": project.owner_id,
        "owner_username": project.owner.username if project.owner else "",
        "owner_school": project.owner.school if project.owner else "",
        "status": project.status,
        "scope": project.scope,
        "raw_text": project.raw_text or "",
        "required_skills": profile.required_skills if profile else [],
        "project_type": profile.project_type if profile else "",
        "time_requirement": profile.time_requirement if profile else "未知",
        "created_at": project.created_at,
        "favorited_at": favorite.created_at,
    }


@app.post("/api/favorites")
def add_favorite(request: InterestRequest, db: Session = Depends(get_db)):
    if db.get(User, request.user_id) is None:
        return {"success": False, "message": "用户不存在"}
    if db.get(Project, request.project_id) is None:
        return {"success": False, "message": "项目不存在"}
    favorite = db.scalar(
        select(FavoriteProject).where(
            FavoriteProject.user_id == request.user_id,
            FavoriteProject.project_id == request.project_id,
        )
    )
    if favorite is not None:
        return {"success": True, "favorited": True, "idempotent": True}
    db.add(FavoriteProject(user_id=request.user_id, project_id=request.project_id))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return {"success": True, "favorited": True, "idempotent": True}
    return {"success": True, "favorited": True}


@app.delete("/api/favorites/{project_id}")
def remove_favorite(project_id: int, user_id: int, db: Session = Depends(get_db)):
    favorite = db.scalar(
        select(FavoriteProject).where(
            FavoriteProject.user_id == user_id,
            FavoriteProject.project_id == project_id,
        )
    )
    if favorite is None:
        return {"success": True, "favorited": False, "idempotent": True}
    db.delete(favorite)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "取消收藏失败"}
    return {"success": True, "favorited": False}


@app.get("/api/favorites/{user_id}")
def get_favorites(user_id: int, db: Session = Depends(get_db)):
    if db.get(User, user_id) is None:
        return {"success": False, "message": "用户不存在"}
    rows = db.execute(
        select(Project, FavoriteProject)
        .join(FavoriteProject, FavoriteProject.project_id == Project.id)
        .where(FavoriteProject.user_id == user_id)
        .order_by(FavoriteProject.created_at.desc())
    ).all()
    return {
        "success": True,
        "favorites": [_serialize_favorite(project, favorite) for project, favorite in rows],
    }


@app.post("/api/feedback")
def create_feedback(request: FeedbackRequest, db: Session = Depends(get_db)):
    if db.get(User, request.user_id) is None:
        return {"success": False, "message": "用户不存在"}
    allowed_categories = {
        "功能建议", "匹配不准确", "使用问题", "内容举报", "账号问题", "其他"
    }
    category = request.category.strip()
    content = request.content.strip()
    if category not in allowed_categories:
        return {"success": False, "message": "反馈类型无效"}
    if not content:
        return {"success": False, "message": "请填写反馈内容"}
    if len(content) > 3000:
        return {"success": False, "message": "反馈内容不能超过3000字"}
    feedback = Feedback(
        user_id=request.user_id,
        category=category,
        content=content,
        contact_email=request.contact_email.strip()[:255] or None,
        source_page=request.source_page.strip()[:80] or None,
    )
    db.add(feedback)
    try:
        db.commit()
        db.refresh(feedback)
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "反馈提交失败"}
    return {"success": True, "feedback_id": feedback.id}


@app.get("/api/my_feedback/{user_id}")
def get_my_feedback(user_id: int, db: Session = Depends(get_db)):
    if db.get(User, user_id) is None:
        return {"success": False, "message": "用户不存在"}
    feedbacks = db.scalars(
        select(Feedback)
        .where(Feedback.user_id == user_id)
        .order_by(Feedback.created_at.desc())
    ).all()
    return {
        "success": True,
        "feedback": [
            {
                "feedback_id": item.id,
                "category": item.category,
                "content": item.content,
                "contact_email": item.contact_email or "",
                "source_page": item.source_page or "",
                "status": item.status,
                "admin_reply": item.admin_reply or "",
                "created_at": item.created_at,
                "updated_at": item.updated_at,
            }
            for item in feedbacks
        ],
    }


@app.post("/api/interest")
def mark_interest(request: InterestRequest, db: Session = Depends(get_db)):
    interested_user = db.get(User, request.user_id)
    if interested_user is None:
        return {"success": False, "message": "用户不存在"}
    project = db.get(Project, request.project_id)
    if project is None:
        return {"success": False, "message": "项目不存在"}
    if project.owner_id == request.user_id:
        return {"success": False, "message": "不能对自己发布的项目表达感兴趣"}
    if project.status != "recruiting":
        return {"success": False, "message": "该项目当前不接受新的申请"}

    records = db.scalars(
        select(MatchRecord)
        .where(
            MatchRecord.user_id == request.user_id,
            MatchRecord.project_id == request.project_id,
        )
    ).all()
    already_interested = any(record.status == "interested" for record in records)
    if records:
        for record in records:
            record.status = "interested"
    else:
        db.add(
            MatchRecord(
                user_id=request.user_id,
                project_id=request.project_id,
                total_score=0.0,
                skill_match=0.0,
                time_match=0.0,
                experience_match=0.0,
                explanation="尚未计算匹配度",
                status="interested",
            )
        )

    try:
        if not already_interested:
            _add_notification(
                db,
                user_id=project.owner_id,
                notification_type="candidate_interested",
                title="有新的候选人表达意向",
                content=f"{interested_user.username} 对项目“{project.name}”感兴趣。",
                related_project_id=project.id,
                related_user_id=interested_user.id,
            )
        db.commit()
    except IntegrityError:
        db.rollback()
        concurrent_record = db.scalar(
            select(MatchRecord).where(
                MatchRecord.user_id == request.user_id,
                MatchRecord.project_id == request.project_id,
            )
        )
        if concurrent_record is None:
            return {"success": False, "message": "感兴趣状态保存失败"}
        concurrent_record.status = "interested"
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            return {"success": False, "message": "感兴趣状态保存失败"}
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "感兴趣状态保存失败"}
    return {
        "success": True,
        "status": "interested",
        "interested": True,
    }


@app.get("/api/interested_users/{project_id}")
def get_interested_users(project_id: int, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        return {"success": False, "message": "项目不存在"}

    rows = db.execute(
        select(User, MatchRecord)
        .join(MatchRecord, MatchRecord.user_id == User.id)
        .where(
            MatchRecord.project_id == project_id,
            MatchRecord.status == "interested",
        )
        .order_by(MatchRecord.total_score.desc())
    ).all()

    users_by_id = {}
    for user, record in rows:
        current = users_by_id.get(user.id)
        if current is None or record.total_score > current["total_score"]:
            users_by_id[user.id] = {
                "user_id": user.id,
                "username": user.username,
                "school": user.school or "",
                "total_score": round(record.total_score, 3),
            }
    users = sorted(
        users_by_id.values(),
        key=lambda item: item["total_score"],
        reverse=True,
    )
    return {"success": True, "users": users}


@app.get("/api/project/{project_id}/candidates")
def get_project_candidates(
    project_id: int,
    owner_id: int,
    db: Session = Depends(get_db),
):
    """Return public candidate summaries for a project owner."""
    project = db.get(Project, project_id)
    if project is None:
        return {"success": False, "message": "项目不存在"}
    if project.owner_id != owner_id:
        return {"success": False, "message": "无权查看该项目候选人"}

    rows = db.execute(
        select(User, UserProfile, MatchRecord, OwnerInterest)
        .join(MatchRecord, MatchRecord.user_id == User.id)
        .outerjoin(UserProfile, UserProfile.user_id == User.id)
        .outerjoin(
            OwnerInterest,
            (OwnerInterest.project_id == project_id)
            & (OwnerInterest.user_id == User.id),
        )
        .where(
            MatchRecord.project_id == project_id,
            MatchRecord.status == "interested",
        )
        .order_by(MatchRecord.total_score.desc(), User.id.asc())
    ).all()

    candidates = []
    for user, profile, record, owner_interest in rows:
        candidates.append(
            {
                "user_id": user.id,
                "username": user.username,
                "school": user.school or "",
                "major": user.major or "",
                "grade": user.grade or "",
                "skills": profile.skills if profile else [],
                "experience": profile.experience if profile else [],
                "interests": profile.interests if profile else [],
                "time_commitment": (
                    profile.time_commitment if profile else "未知"
                ),
                "total_score": round(record.total_score, 3),
                "skill_match": round(record.skill_match, 3),
                "time_match": round(record.time_match, 3),
                "experience_match": round(record.experience_match, 3),
                "explanation": record.explanation or "暂无匹配解释",
                "owner_status": (
                    owner_interest.status if owner_interest else "pending"
                ),
                "owner_interested": bool(
                    owner_interest and owner_interest.status == "interested"
                ),
                "mutual": bool(
                    owner_interest and owner_interest.status == "interested"
                ),
            }
        )
    return {"success": True, "project_id": project_id, "candidates": candidates}


@app.get("/api/my_matches/{user_id}")
def get_my_matches(user_id: int, db: Session = Depends(get_db)):
    if db.get(User, user_id) is None:
        return {"success": False, "message": "用户不存在"}

    rows = db.execute(
        select(Project, ProjectProfile, User, MatchRecord, OwnerInterest)
        .join(MatchRecord, MatchRecord.project_id == Project.id)
        .join(User, User.id == Project.owner_id)
        .outerjoin(ProjectProfile, ProjectProfile.project_id == Project.id)
        .outerjoin(
            OwnerInterest,
            (OwnerInterest.project_id == Project.id)
            & (OwnerInterest.user_id == user_id),
        )
        .where(
            MatchRecord.user_id == user_id,
            MatchRecord.status == "interested",
        )
        .order_by(MatchRecord.created_at.desc())
    ).all()

    matches = []
    for project, profile, owner, record, owner_interest in rows:
        owner_status = owner_interest.status if owner_interest else "pending"
        relationship_status = {
            "interested": "mutual",
            "rejected": "owner_declined",
        }.get(owner_status, "user_interested")
        matches.append(
            {
                "project_id": project.id,
                "project_name": project.name,
                "project_status": project.status,
                "owner_username": owner.username,
                "owner_school": owner.school or "",
                "scope": project.scope,
                "required_skills": profile.required_skills if profile else [],
                "time_requirement": profile.time_requirement if profile else "未知",
                "total_score": round(record.total_score, 3),
                "skill_match": round(record.skill_match, 3),
                "time_match": round(record.time_match, 3),
                "experience_match": round(record.experience_match, 3),
                "explanation": record.explanation or "暂无匹配解释",
                "relationship_status": relationship_status,
                "created_at": record.created_at,
            }
        )
    return {"success": True, "matches": matches}


def _contact_payload(user: User, profile: UserProfile | None) -> dict:
    email_verified = user.email_verified_at is not None
    payload = {
        "user_id": user.id,
        "username": user.username,
        "email": user.email if email_verified else "",
        "email_verified": email_verified,
        "contact_method": "",
        "contact_value": "",
    }
    if profile and profile.contact_visible and profile.contact_value:
        payload["contact_method"] = profile.contact_method or "other"
        payload["contact_value"] = profile.contact_value
    return payload


@app.get("/api/match/{user_id}/{project_id}")
def get_mutual_match_detail(
    user_id: int,
    project_id: int,
    viewer_id: int,
    db: Session = Depends(get_db),
):
    """Reveal the counterpart's contact only after a mutual match."""
    project = db.get(Project, project_id)
    candidate = db.get(User, user_id)
    if project is None or candidate is None:
        return {"success": False, "message": "匹配关系不存在"}
    if viewer_id not in {user_id, project.owner_id}:
        return {"success": False, "message": "无权查看该匹配信息"}

    user_interested = db.scalar(
        select(MatchRecord.id).where(
            MatchRecord.user_id == user_id,
            MatchRecord.project_id == project_id,
            MatchRecord.status == "interested",
        )
    )
    owner_interested = db.scalar(
        select(OwnerInterest.id).where(
            OwnerInterest.project_id == project_id,
            OwnerInterest.user_id == user_id,
            OwnerInterest.status == "interested",
        )
    )
    if not user_interested or not owner_interested:
        return {
            "success": True,
            "mutual": False,
            "message": "双方尚未完成互选",
        }

    counterpart = candidate if viewer_id == project.owner_id else db.get(User, project.owner_id)
    counterpart_profile = db.scalar(
        select(UserProfile).where(UserProfile.user_id == counterpart.id)
    )
    return {
        "success": True,
        "mutual": True,
        "project_id": project.id,
        "project_name": project.name,
        "counterpart": _contact_payload(counterpart, counterpart_profile),
    }


@app.post("/api/owner_candidate_action")
def owner_candidate_action(
    request: OwnerCandidateActionRequest,
    db: Session = Depends(get_db),
):
    project = db.get(Project, request.project_id)
    if project is None:
        return {"success": False, "message": "项目不存在"}
    if project.owner_id != request.owner_id:
        return {"success": False, "message": "无权处理该项目候选人"}
    if request.action not in {"interested", "rejected"}:
        return {"success": False, "message": "候选人处理状态无效"}
    candidate_interest = db.scalar(
        select(MatchRecord.id).where(
            MatchRecord.user_id == request.user_id,
            MatchRecord.project_id == request.project_id,
            MatchRecord.status == "interested",
        )
    )
    if candidate_interest is None:
        return {"success": False, "message": "该用户尚未对项目表达感兴趣"}

    decision = db.scalar(
        select(OwnerInterest).where(
            OwnerInterest.project_id == request.project_id,
            OwnerInterest.user_id == request.user_id,
        )
    )
    previous_status = decision.status if decision else "pending"
    if decision is None:
        decision = OwnerInterest(
            project_id=request.project_id,
            user_id=request.user_id,
            status=request.action,
        )
        db.add(decision)
    else:
        decision.status = request.action
    try:
        if previous_status != request.action:
            candidate = db.get(User, request.user_id)
            if request.action == "interested":
                _add_notification(
                    db,
                    user_id=request.user_id,
                    notification_type="mutual_match",
                    title="双方匹配成功",
                    content=(
                        f"项目“{project.name}”的发起人也对你感兴趣，"
                        "联系方式已解锁。"
                    ),
                    related_project_id=project.id,
                    related_user_id=project.owner_id,
                )
                _add_notification(
                    db,
                    user_id=request.owner_id,
                    notification_type="mutual_match",
                    title="双方匹配成功",
                    content=(
                        f"你与候选人{candidate.username}在项目“{project.name}”"
                        "中完成互选，联系方式已解锁。"
                    ),
                    related_project_id=project.id,
                    related_user_id=request.user_id,
                )
            else:
                _add_notification(
                    db,
                    user_id=request.user_id,
                    notification_type="candidate_declined",
                    title="项目方已更新处理结果",
                    content=f"项目“{project.name}”的发起人当前暂不考虑你的申请。",
                    related_project_id=project.id,
                    related_user_id=request.owner_id,
                )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "候选人状态保存失败"}
    return {
        "success": True,
        "status": decision.status,
        "mutual": decision.status == "interested",
    }


@app.post("/api/owner_interest")
def mark_owner_interest(request: InterestRequest, db: Session = Depends(get_db)):
    project = db.get(Project, request.project_id)
    if not project:
        return {"success": False, "message": "项目不存在"}
    if db.get(User, request.user_id) is None:
        return {"success": False, "message": "用户不存在"}
    if project.owner_id == request.user_id:
        return {"success": False, "message": "不能标记项目发起人本人"}
    candidate_interest = db.scalar(
        select(MatchRecord.id).where(
            MatchRecord.user_id == request.user_id,
            MatchRecord.project_id == request.project_id,
            MatchRecord.status == "interested",
        )
    )
    if candidate_interest is None:
        return {"success": False, "message": "该用户尚未对项目表达感兴趣"}

    existing = db.scalar(
        select(OwnerInterest).where(
            OwnerInterest.project_id == request.project_id,
            OwnerInterest.user_id == request.user_id,
        )
    )
    if existing is None:
        db.add(
            OwnerInterest(
                project_id=request.project_id,
                user_id=request.user_id,
                status="interested",
            )
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return {"success": False, "message": "发起人意向保存失败"}
    else:
        existing.status = "interested"
        db.commit()
    return {"success": True}


@app.post("/api/check_mutual")
def check_mutual(request: InterestRequest, db: Session = Depends(get_db)):
    user_interested = db.scalar(
        select(MatchRecord.id)
        .where(
            MatchRecord.user_id == request.user_id,
            MatchRecord.project_id == request.project_id,
            MatchRecord.status == "interested",
        )
        .limit(1)
    )
    owner_interested = db.scalar(
        select(OwnerInterest.id)
        .where(
            OwnerInterest.project_id == request.project_id,
            OwnerInterest.user_id == request.user_id,
            OwnerInterest.status == "interested",
        )
        .limit(1)
    )
    return {
        "success": True,
        "mutual": bool(user_interested and owner_interested),
    }


@app.get("/api/notifications/{user_id}")
def get_notifications(
    user_id: int,
    unread_only: bool = False,
    page: int = 1,
    page_size: int = 30,
    db: Session = Depends(get_db),
):
    if db.get(User, user_id) is None:
        return {"success": False, "message": "用户不存在"}
    page = max(page, 1)
    page_size = min(max(page_size, 1), 50)
    query = select(Notification).where(Notification.user_id == user_id)
    if unread_only:
        query = query.where(Notification.is_read.is_(False))
    notifications = db.scalars(
        query.order_by(Notification.created_at.desc(), Notification.id.desc())
    ).all()
    unread_count = len(
        db.scalars(
            select(Notification.id).where(
                Notification.user_id == user_id,
                Notification.is_read.is_(False),
            )
        ).all()
    )
    total = len(notifications)
    start = (page - 1) * page_size
    items = notifications[start : start + page_size]
    return {
        "success": True,
        "notifications": [
            {
                "notification_id": item.id,
                "type": item.type,
                "title": item.title,
                "content": item.content,
                "related_project_id": item.related_project_id,
                "related_user_id": item.related_user_id,
                "is_read": item.is_read,
                "created_at": item.created_at,
            }
            for item in items
        ],
        "unread_count": unread_count,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": max((total + page_size - 1) // page_size, 1),
        },
    }


@app.post("/api/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: int,
    request: NotificationActionRequest,
    db: Session = Depends(get_db),
):
    notification = db.get(Notification, notification_id)
    if notification is None:
        return {"success": False, "message": "通知不存在"}
    if notification.user_id != request.user_id:
        return {"success": False, "message": "无权修改该通知"}
    notification.is_read = True
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "通知状态更新失败"}
    return {"success": True}


@app.post("/api/notifications/read-all")
def mark_all_notifications_read(
    request: NotificationActionRequest,
    db: Session = Depends(get_db),
):
    notifications = db.scalars(
        select(Notification).where(
            Notification.user_id == request.user_id,
            Notification.is_read.is_(False),
        )
    ).all()
    for notification in notifications:
        notification.is_read = True
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "通知状态更新失败"}
    return {"success": True, "updated_count": len(notifications)}

@app.post("/api/parse_profile")
def parse_profile(request: ProfileRequest):
    try:
        result = parse_user_profile(request.raw_text)
        for field in ("skills", "interests"):
            original_value = result.get(field, [])
            try:
                result[field] = normalize_skills(original_value)
            except Exception:
                result[field] = original_value
                logger.warning(
                    "用户画像字段 %s 归一化失败，保留原始值",
                    field,
                    exc_info=True,
                )
        return {"success": True, "data": result}
    except Exception:
        return {"success": False, "message": "解析失败，请重试"}


@app.post("/api/parse_project")
def parse_project(request: ProfileRequest):
    try:
        result = parse_project_requirement(request.raw_text)
        return {"success": True, "data": result}
    except Exception:
        return {"success": False, "message": "解析失败，请重试"}


def _hours(value: str) -> float | None:
    """Extract hours from Chinese or English weekly time descriptions."""
    match = re.search(
        r"(\d+(?:\.\d+)?)\s*(?:小时|hours?|hrs?|h)",
        value or "",
        re.IGNORECASE,
    )
    return float(match.group(1)) if match else None


def _calculate_time_match(user_time: str, project_time: str) -> float:
    user_hours = _hours(user_time)
    project_hours = _hours(project_time)

    print("[match debug] extracted user hours:", user_hours)
    print("[match debug] extracted project hours:", project_hours)

    if user_hours is None or project_hours is None or project_hours <= 0:
        return 0.5
    if user_hours >= project_hours:
        return 1.0
    if user_hours >= project_hours * 0.8:
        return 0.7
    if user_hours >= project_hours * 0.5:
        return 0.4
    return 0.1


def _display_list(values: list) -> str:
    cleaned = [str(value).strip() for value in values if str(value).strip()]
    return "、".join(cleaned) if cleaned else "未提供"


def _build_match_explanation(
    total_score: float,
    skill_match: float,
    time_match: float,
    experience_match: float,
    user_skills: list[str],
    required_skills: list[str],
    user_time: str,
    project_time: str,
    user_experience: list[str],
    project_type: str,
) -> str:
    if total_score >= 0.8:
        overall = "整体高度匹配。"
    elif total_score >= 0.5:
        overall = "整体部分匹配。"
    else:
        overall = "整体匹配度较低。"

    advantages = []
    gaps = []

    if skill_match >= 0.7:
        advantages.append(
            f"技能匹配度较高（{skill_match:.0%}），你的技能为"
            f"{_display_list(user_skills)}，项目需要{_display_list(required_skills)}。"
        )
    elif skill_match < 0.5:
        gaps.append(
            f"技能维度与项目需求重合度不足（{skill_match:.0%}）：项目需要"
            f"{_display_list(required_skills)}，你的技能为{_display_list(user_skills)}。"
        )
    else:
        gaps.append(
            f"技能仅部分覆盖（{skill_match:.0%}）：项目需要"
            f"{_display_list(required_skills)}，你的技能为{_display_list(user_skills)}。"
        )

    if time_match >= 0.7:
        advantages.append(
            f"时间投入满足度较高（用户可投入{user_time}，项目要求{project_time}）。"
        )
    elif time_match < 0.5:
        gaps.append(
            f"时间投入不足（用户可投入{user_time}，项目要求{project_time}）。"
        )
    else:
        gaps.append(
            f"时间信息不足，暂按中性分处理（用户时间：{user_time}；"
            f"项目时间：{project_time}）。"
        )

    if experience_match >= 0.7:
        advantages.append(
            f"经验方向与项目较相关（用户经历：{_display_list(user_experience)}；"
            f"项目类型：{project_type or '未提供'}）。"
        )
    elif experience_match < 0.5:
        gaps.append(
            f"经验方向与项目相关性较低（用户经历：{_display_list(user_experience)}；"
            f"项目类型：{project_type or '未提供'}）。"
        )
    else:
        gaps.append(
            f"经验相关性尚不明确（用户经历：{_display_list(user_experience)}；"
            f"项目类型：{project_type or '未提供'}）。"
        )

    advantage_text = "具体优势：" + "".join(advantages) if advantages else "具体优势：暂未发现明显高分维度。"
    gap_text = "具体差距：" + "".join(gaps) if gaps else "具体差距：暂未发现明显短板。"
    return overall + advantage_text + gap_text


def _calculate_match_scores(
    user: dict,
    project: dict,
    experience_score: float | None = None,
) -> dict:
    """Calculate all matching dimensions for one user/project pair."""
    normalized_user_skills = normalize_skills(user["skills"])
    normalized_user_interests = normalize_skills(user.get("interests", []))
    normalized_required_skills = normalize_skills(project["required_skills"])
    user_skills = {skill.lower() for skill in normalized_user_skills}
    user_interests = {interest.lower() for interest in normalized_user_interests}
    required_skill_names = {
        skill.lower() for skill in normalized_required_skills
    }

    print("[match debug] normalized user skills:", normalized_user_skills)
    print("[match debug] normalized user interests:", normalized_user_interests)
    print("[match debug] normalized required skills:", normalized_required_skills)

    skill_similarity_results = judge_skill_similarity(
        normalized_user_skills,
        normalized_required_skills,
    )
    skill_hit_count = sum(
        1 for _, _, similarity in skill_similarity_results if similarity >= 0.7
    )
    if not skill_similarity_results:
        skill_hit_count = len(user_skills & required_skill_names)

    interest_similarity_results = judge_skill_similarity(
        normalized_user_interests,
        normalized_required_skills,
    )
    interest_hit_count = sum(
        1 for _, _, similarity in interest_similarity_results if similarity >= 0.7
    )
    if not interest_similarity_results:
        interest_hit_count = len(user_interests & required_skill_names)

    skill_match = (
        min(
            (skill_hit_count + 0.5 * interest_hit_count)
            / len(required_skill_names),
            1.0,
        )
        if required_skill_names
        else 0
    )

    print("[match debug] skill similarity results:", skill_similarity_results)
    print("[match debug] interest similarity results:", interest_similarity_results)
    print("[match debug] skill hit count:", skill_hit_count)
    print("[match debug] interest hit count:", interest_hit_count)

    time_match = _calculate_time_match(
        str(user["time_commitment"]),
        str(project["time_requirement"]),
    )
    print("[match debug] time match score:", time_match)
    project_type = str(project["project_type"])
    project_background = str(project.get("background", ""))
    experience_match = (
        experience_score
        if experience_score is not None
        else judge_experience_relevance(
            user_experience=user["experience"],
            project_type=project_type,
            project_background=project_background,
        )
    )

    print("[match debug] user experience:", user["experience"])
    print("[match debug] project type:", project_type)
    print("[match debug] project background:", project_background)
    print("[match debug] AI experience score:", experience_match)

    total_score = skill_match * 0.6 + time_match * 0.2 + experience_match * 0.2
    explanation = _build_match_explanation(
        total_score=total_score,
        skill_match=skill_match,
        time_match=time_match,
        experience_match=experience_match,
        user_skills=normalized_user_skills,
        required_skills=normalized_required_skills,
        user_time=str(user["time_commitment"]),
        project_time=str(project["time_requirement"]),
        user_experience=user["experience"],
        project_type=project_type,
    )

    return {
        "total_score": round(total_score, 3),
        "skill_match": round(skill_match, 3),
        "time_match": time_match,
        "experience_match": experience_match,
        "explanation": explanation,
    }


@app.post("/api/match")
def match_profiles(request: MatchRequest):
    user = request.user_profile
    project = request.project_profile

    required_fields = {
        "user": (user, ["skills", "skill_levels", "time_commitment", "experience"]),
        "project": (project, ["required_skills", "time_requirement", "project_type"]),
    }
    if any(field not in data for data, fields in required_fields.values() for field in fields):
        return {"success": False, "message": "数据不完整"}

    return {"success": True, **_calculate_match_scores(user, project)}


@app.get("/api/match_list/{user_id}")
def get_match_list(
    user_id: int,
    scope: str | None = None,
    db: Session = Depends(get_db),
):
    user_profile = db.scalar(
        select(UserProfile).where(UserProfile.user_id == user_id)
    )
    if not user_profile:
        return {"success": False, "message": "请先填写画像"}

    current_user = db.get(User, user_id)
    if not current_user:
        return {"success": False, "message": "用户不存在"}

    query = (
        select(Project, ProjectProfile, User)
        .join(ProjectProfile, ProjectProfile.project_id == Project.id)
        .join(User, User.id == Project.owner_id)
        .where(
            Project.status == "recruiting",
            Project.moderation_status == "active",
        )
    )
    if scope == "same_school":
        if not current_user.school:
            return {"success": True, "matches": []}
        query = query.where(User.school == current_user.school)

    user_data = {
        "skills": user_profile.skills or [],
        "skill_levels": user_profile.skill_levels or {},
        "experience": user_profile.experience or [],
        "interests": user_profile.interests or [],
        "time_commitment": user_profile.time_commitment or "未知",
    }
    matches = []
    experience_cache: dict[tuple[int, int], float] = {}

    try:
        for project, project_profile, owner in db.execute(query).all():
            project_data = {
                "required_skills": project_profile.required_skills or [],
                "time_requirement": project_profile.time_requirement or "未知",
                "project_type": project_profile.project_type or "",
                "background": project_profile.background or "",
            }
            cache_key = (user_id, project.id)
            record = db.scalars(
                select(MatchRecord)
                .where(
                    MatchRecord.user_id == user_id,
                    MatchRecord.project_id == project.id,
                )
                .limit(1)
            ).first()
            if cache_key not in experience_cache:
                experience_cache[cache_key] = (
                    record.experience_match
                    if record is not None
                    and record.explanation != "尚未计算匹配度"
                    else judge_experience_relevance(
                        user_experience=user_data["experience"],
                        project_type=project_data["project_type"],
                        project_background=project_data["background"],
                    )
                )

            scores = _calculate_match_scores(
                user_data,
                project_data,
                experience_score=experience_cache[cache_key],
            )
            if record is None:
                record = MatchRecord(user_id=user_id, project_id=project.id, **scores)
                db.add(record)
            else:
                for field in (
                    "total_score",
                    "skill_match",
                    "time_match",
                    "experience_match",
                    "explanation",
                ):
                    setattr(record, field, scores[field])

            matches.append(
                {
                    "project_id": project.id,
                    "project_name": project.name,
                    "owner_school": owner.school or "",
                    **scores,
                    "scope": project.scope,
                    "status": record.status or "pending",
                    "interested": record.status == "interested",
                }
            )

        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return {"success": False, "message": "匹配结果保存失败"}

    matches.sort(key=lambda item: item["total_score"], reverse=True)
    return {"success": True, "matches": matches}
