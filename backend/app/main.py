
# ============================================================
# THE-GUARDIAN
# Main FastAPI Application
# ============================================================

import os
import json
import uuid
import logging
import asyncio
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Optional, Any

from dotenv import load_dotenv
load_dotenv()

from fastapi import (
    FastAPI,
    Request,
    Depends,
    Form,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import (
    or_,
    func,
    inspect,
    text,
    update,
)
from sqlalchemy.exc import SQLAlchemyError

from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext

from backend.app.core.config import settings
from backend.app.models.transaction import TransactionRequest
from backend.app.services.fraud_detector import detector
from backend.app.db.database import engine, Base, get_db
from backend.app.db import models

from backend.app.db.models import (
    User,
    Transaction,
    Report,
    ActivityLog,
    InvestigationCase,
    WalletLedger,
    SavingsGoal, GuardianCard, SecurityAlert,
)


# ============================================================
# CONFIGURATION
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("THE-GUARDIAN")

APP_NAME = "THE-GUARDIAN"
AI_NAME = "AI NYASHA"

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
if not ADMIN_PASSWORD:
    if os.getenv("RENDER"):
        raise RuntimeError("Set ADMIN_PASSWORD in Render environment variables.")
    ADMIN_PASSWORD = "change-this-local-admin-password"

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    if os.getenv("RENDER"):
        raise RuntimeError(
            "SECRET_KEY must be configured in production."
        )
    SECRET_KEY = "development-only-change-this-secret"

COOKIE_SECURE = os.getenv(
    "COOKIE_SECURE",
    "false"
).lower() == "true"

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

templates = Jinja2Templates(
    directory="backend/app/templates"
)


# ============================================================
# DATABASE INITIALIZATION AND MIGRATION
# ============================================================

Base.metadata.create_all(bind=engine)


def run_database_migrations():
    """
    Adds balance_ngwee to existing users tables.

    Existing ZMW balances are migrated into integer ngwee.
    """

    inspector = inspect(engine)

    if not inspector.has_table("users"):
        return

    columns = {
        column["name"]
        for column in inspector.get_columns("users")
    }

    if "balance_ngwee" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE users "
                    "ADD COLUMN balance_ngwee "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            )

            connection.execute(
                text("""
                    UPDATE users
                    SET balance_ngwee = CAST(
                        ROUND(COALESCE(balance, 0) * 100)
                        AS INTEGER
                    )
                """)
            )

        logger.info(
            "Existing wallet balances migrated to ngwee."
        )


run_database_migrations()


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title=APP_NAME,
    description="Mobile Money Fraud Detection and Wallet Platform",
    version="2.0.0",
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="guardian_session",
    same_site="lax",
    https_only=COOKIE_SECURE,
    max_age=60 * 60 * 24,
)

cors_origins = [
    item.strip()
    for item in os.getenv(
        "CORS_ORIGINS",
        ""
    ).split(",")
    if item.strip()
]

if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
    )


# ============================================================
# GENERAL HELPERS
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_password(password: str) -> str:
    return pwd_context.hash(password[:72])


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(password[:72], hashed)
    except Exception:
        return False


def amount_to_ngwee(value: Any) -> int:
    """
    Converts a monetary amount into integer ngwee.

    Rejects amounts with more than two decimal places.
    """

    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Invalid transaction amount."
        )

    if not amount.is_finite() or amount <= 0:
        raise HTTPException(
            status_code=400,
            detail="Amount must be greater than zero."
        )

    if amount != amount.quantize(Decimal("0.01")):
        raise HTTPException(
            status_code=400,
            detail="Amount cannot have more than two decimal places."
        )

    return int(amount * 100)


def ngwee_to_kwacha(value: int) -> float:
    return round(int(value) / 100, 2)


def enum_value(value):
    return value.value if hasattr(value, "value") else str(value)


def serialize_factors(factors):
    result = []

    for factor in factors or []:
        if hasattr(factor, "model_dump"):
            result.append(factor.model_dump())
        elif hasattr(factor, "dict"):
            result.append(factor.dict())
        elif isinstance(factor, dict):
            result.append(factor)

    return result


def get_user_phone(user: User) -> str:
    return user.phone or user.username


def log_activity(
    db: Session,
    action: str,
    user_phone: Optional[str] = None,
    details: Optional[str] = None,
):
    """
    Adds an activity record without committing.

    The caller controls the database transaction.
    """

    db.add(
        ActivityLog(
            user_phone=user_phone,
            action=action,
            details=details,
        )
    )


def create_transaction_record(
    db: Session,
    tx_request: TransactionRequest,
    fraud_result,
    transaction_type: str = "TRANSFER",
    location: Optional[str] = None,
):
    record = Transaction(
        transaction_id=tx_request.transaction_id,
        amount=float(tx_request.amount),
        currency=tx_request.currency,
        sender_msisdn=tx_request.sender_msisdn,
        receiver_msisdn=tx_request.receiver_msisdn,
        transaction_type=transaction_type,
        channel=tx_request.channel,
        location=location,
        location_lat=tx_request.location_lat,
        location_lon=tx_request.location_lon,
        device_id=tx_request.sender_device_id,
        risk_score=float(fraud_result.risk_score),
        risk_level=str(fraud_result.risk_level),
        decision=enum_value(fraud_result.decision),
        recommendation=fraud_result.recommendation,
        factors=json.dumps(
            serialize_factors(fraud_result.factors)
        ),
        created_at=utc_now(),
        processed_at=utc_now(),
    )

    db.add(record)
    return record


def get_transaction_location_fields(request: Request):
    return {
        "location_lat": None,
        "location_lon": None,
    }


def calculate_sender_activity(
    db: Session,
    phone: str,
):
    now = utc_now()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(hours=24)

    one_hour_count = db.query(Transaction).filter(
        Transaction.sender_msisdn == phone,
        Transaction.created_at >= hour_ago,
    ).count()

    daily_records = db.query(Transaction).filter(
        Transaction.sender_msisdn == phone,
        Transaction.created_at >= day_ago,
        Transaction.decision == "ALLOW",
    ).all()

    daily_amount = sum(
        float(item.amount or 0)
        for item in daily_records
    )

    return {
        "sender_tx_count_last_1h": one_hour_count,
        "sender_tx_count_last_24h": len(daily_records),
        "sender_total_amount_last_24h": daily_amount,
    }


def broadcast_dashboard_event(event: dict):
    """
    Broadcasts an event to connected admin dashboards.
    """

    async def send_event():
        disconnected = []

        for websocket in list(active_admin_connections):
            try:
                await websocket.send_json(event)
            except Exception:
                disconnected.append(websocket)

        for websocket in disconnected:
            active_admin_connections.discard(websocket)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(send_event())
    except RuntimeError:
        pass



def _safe_json_list(value):
    try:
        parsed = json.loads(value or "[]")
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError, json.JSONDecodeError):
        return []


def serialize_transaction(transaction: Transaction):
    return {
        "id": transaction.id,
        "transaction_id": transaction.transaction_id,
        "amount": float(transaction.amount),
        "currency": transaction.currency,
        "sender": transaction.sender_msisdn,
        "receiver": transaction.receiver_msisdn,
        "sender_msisdn": transaction.sender_msisdn,
        "receiver_msisdn": transaction.receiver_msisdn,
        "transaction_type": transaction.transaction_type,
        "channel": transaction.channel,
        "risk_score": float(transaction.risk_score),
        "risk_level": transaction.risk_level,
        "decision": transaction.decision,
        "recommendation": transaction.recommendation,
        "factors": _safe_json_list(transaction.factors),
        "location": transaction.location,
        "location_lat": transaction.location_lat,
        "location_lon": transaction.location_lon,
        "latitude": transaction.location_lat,
        "longitude": transaction.location_lon,
        "time": transaction.created_at.isoformat()
        if transaction.created_at else None,
        "created_at": transaction.created_at.isoformat()
        if transaction.created_at else None,
    }


# ============================================================
# AUTHENTICATION
# ============================================================

def get_current_admin(request: Request):
    return request.session.get("user")


def get_current_normal_user(request: Request):
    return request.session.get("normal_user")


def require_admin(request: Request):
    admin = get_current_admin(request)

    if not admin:
        raise HTTPException(
            status_code=401,
            detail="Administrator authentication required."
        )

    return admin


def require_user(request: Request):
    user = get_current_normal_user(request)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User authentication required."
        )

    return user


# ============================================================
# ADMIN WEBSOCKET
# ============================================================

active_admin_connections = set()


@app.websocket("/ws/dashboard")
async def dashboard_websocket(websocket: WebSocket):
    if not websocket.session.get("user"):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    active_admin_connections.add(websocket)

    try:
        await websocket.send_json({
            "type": "CONNECTED",
            "message": "THE-GUARDIAN live dashboard connected.",
            "time": utc_now().isoformat(),
        })

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        active_admin_connections.discard(websocket)

    except Exception:
        active_admin_connections.discard(websocket)


# ============================================================
# HOME AND HEALTH
# ============================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if request.session.get("user"):
        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    if request.session.get("normal_user"):
        return RedirectResponse(
            "/user/dashboard",
            status_code=303
        )

    return RedirectResponse(
        "/login",
        status_code=303
    )


@app.get("/health")
def health():
    return {
        "status": "online",
        "application": APP_NAME,
        "time": utc_now().isoformat(),
    }


# ============================================================
# LOGIN AND LOGOUT
# ============================================================

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    if (
        username == ADMIN_USERNAME
        and password == ADMIN_PASSWORD
    ):
        request.session.clear()
        request.session["user"] = username

        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    user = db.query(User).filter(
        or_(
            User.username == username,
            User.phone == username,
        )
    ).first()

    if (
        user
        and user.is_active
        and verify_password(password, user.password)
    ):
        request.session.clear()
        request.session["normal_user"] = {
            "id": user.id,
            "username": user.username,
        }

        user.last_login = utc_now()

        log_activity(
            db,
            "USER_LOGIN",
            get_user_phone(user),
            "Customer logged in."
        )

        db.commit()

        return RedirectResponse(
            "/user/dashboard",
            status_code=303
        )

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": "Invalid username or password.",
        },
        status_code=401,
    )


@app.get("/logout")
def admin_logout(request: Request):
    request.session.clear()

    return RedirectResponse(
        "/login",
        status_code=303
    )


@app.get("/user/logout")
def user_logout(request: Request):
    request.session.clear()

    return RedirectResponse(
        "/login",
        status_code=303
    )


# ============================================================
# CUSTOMER REGISTRATION
# ============================================================

@app.get("/user/register", response_class=HTMLResponse)
def registration_page(request: Request):
    return templates.TemplateResponse(
        "user_register.html",
        {"request": request}
    )


@app.post("/user/register")
def register_user(
    request: Request,
    full_name: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    email: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Create a customer account; the phone number is also the login username."""
    full_name = " ".join(full_name.strip().split())
    phone = phone.strip().replace(" ", "").replace("-", "")
    email = (email or "").strip().lower() or None

    def registration_error(message: str, code: int = 400):
        return templates.TemplateResponse(
            "user_register.html",
            {"request": request, "error": message, "full_name": full_name, "phone": phone, "email": email or ""},
            status_code=code,
        )

    if len(full_name) < 2 or len(full_name) > 150:
        return registration_error("Please enter your full name.")
    if not phone or len(phone) < 7 or len(phone) > 20 or not phone.replace("+", "").isdigit():
        return registration_error("Enter a valid phone number, including country code if needed.")
    if len(password) < 8:
        return registration_error("Your password must contain at least 8 characters.")
    if len(password) > 72:
        return registration_error("Password is too long. Use 72 characters or fewer.")

    duplicate = db.query(User).filter(
        or_(User.username == phone, User.phone == phone, User.email == email if email else False)
    ).first()
    if duplicate:
        return registration_error("That phone number or email is already registered. Please log in instead.", 409)

    user = User(
        username=phone,
        full_name=full_name,
        phone=phone,
        email=email,
        password=hash_password(password),
        balance=0.0,
        balance_ngwee=0,
        is_active=True,
        created_at=utc_now(),
    )
    try:
        db.add(user)
        db.flush()
        log_activity(db, "USER_REGISTERED", phone, "New customer account created.")
        db.commit()
        db.refresh(user)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Registration failed")
        return registration_error("We could not create your account just now. Please try again.", 500)

    request.session.clear()
    request.session["normal_user"] = {"id": user.id, "username": user.username}
    return RedirectResponse("/user/dashboard", status_code=303)

# ============================================================
# DASHBOARD PAGES
# ============================================================

@app.get("/dashboard", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    admin=Depends(require_admin),
):
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "admin": admin,
        }
    )


@app.get("/user/dashboard", response_class=HTMLResponse)
def user_dashboard(
    request: Request,
    current=Depends(require_user),
):
    return templates.TemplateResponse(
        "user_dashboard.html",
        {
            "request": request,
            "user": current,
        }
    )


@app.get("/user/login")
def user_login_redirect():
    return RedirectResponse(
        "/login",
        status_code=303
    )


# ============================================================
# FRAUD ANALYSIS
# ============================================================

@app.post("/api/v1/analyze")
def analyze_transaction(
    tx: TransactionRequest,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    existing = db.query(Transaction).filter(
        Transaction.transaction_id == tx.transaction_id
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Transaction ID already exists."
        )

    try:
        fraud_result = detector.analyze(tx)

        record = create_transaction_record(
            db,
            tx,
            fraud_result,
            transaction_type="FRAUD_ANALYSIS",
        )

        db.commit()
        db.refresh(record)

        broadcast_dashboard_event({
            "type": "NEW_TRANSACTION",
            "transaction": serialize_transaction(record),
        })

        return {
            "success": True,
            "transaction": serialize_transaction(record),
            "fraud_result": fraud_result.model_dump(mode="json"),
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Fraud analysis failed.")

        raise HTTPException(
            status_code=500,
            detail="Transaction analysis failed."
        )


# ============================================================
# ADMIN DASHBOARD STATISTICS
# ============================================================

@app.get("/api/v1/dashboard/stats")
def dashboard_stats(
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    total = db.query(Transaction).count()

    allowed = db.query(Transaction).filter(
        Transaction.decision == "ALLOW"
    ).count()

    review = db.query(Transaction).filter(
        Transaction.decision == "REVIEW"
    ).count()

    blocked = db.query(Transaction).filter(
        Transaction.decision == "BLOCK"
    ).count()

    def percentage(value):
        return round(
            (value / total) * 100,
            2
        ) if total else 0

    return {
        "total_transactions": total,
        "allowed": allowed,
        "review": review,
        "blocked": blocked,
        "allowed_percentage": percentage(allowed),
        "review_percentage": percentage(review),
        "blocked_percentage": percentage(blocked),
        "total_users": db.query(User).count(),
        "active_users": db.query(User).filter(
            User.is_active.is_(True)
        ).count(),
        "wallet_ledger_entries": db.query(WalletLedger).count(),
        "wallet_balance_total": round(
            db.query(func.coalesce(func.sum(User.balance_ngwee), 0)).scalar() / 100.0,
            2,
        ),
    }


@app.get("/api/v1/dashboard/recent")
def dashboard_recent(
    limit: int = 20,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    records = (
        db.query(Transaction)
        .order_by(Transaction.created_at.desc())
        .limit(min(max(limit, 1), 100))
        .all()
    )

    return [
        serialize_transaction(item)
        for item in records
    ]


# ============================================================
# ADMIN TRANSACTIONS
# ============================================================

@app.get("/api/v1/admin/transactions")
def admin_transactions(
    limit: int = 100,
    decision: Optional[str] = None,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(Transaction)

    if decision:
        query = query.filter(
            Transaction.decision == decision.upper()
        )

    records = (
        query.order_by(Transaction.created_at.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )

    return [
        serialize_transaction(item)
        for item in records
    ]


# ============================================================
# ADMIN USERS
# ============================================================

@app.get("/api/v1/admin/users")
def admin_users(
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    users = (
        db.query(User)
        .order_by(User.created_at.desc())
        .all()
    )

    return [
        {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "phone": user.phone,
            "email": user.email,
            "balance": ngwee_to_kwacha(user.balance_ngwee),
            "balance_ngwee": user.balance_ngwee,
            "is_active": user.is_active,
            "last_login": user.last_login.isoformat()
            if user.last_login else None,
            "created_at": user.created_at.isoformat()
            if user.created_at else None,
        }
        for user in users
    ]


@app.delete("/api/v1/admin/users/{user_id}")
def disable_user(
    user_id: int,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    user.is_active = False

    log_activity(
        db,
        "USER_DISABLED",
        get_user_phone(user),
        "Account disabled by administrator."
    )

    db.commit()

    return {
        "success": True,
        "message": "User account disabled."
    }


# ============================================================
# ADMIN ACTIVITY LOG
# ============================================================

@app.get("/api/v1/admin/activity")
def admin_activity(
    limit: int = 100,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    activities = (
        db.query(ActivityLog)
        .order_by(ActivityLog.created_at.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )

    return [
        {
            "id": item.id,
            "action": item.action,
            "user_phone": item.user_phone,
            "details": item.details,
            "time": item.created_at.isoformat()
            if item.created_at else None,
        }
        for item in activities
    ]


# ============================================================
# ADMIN REPORTS
# ============================================================

@app.get("/api/v1/admin/reports")
def admin_reports(
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    reports = (
        db.query(Report)
        .order_by(Report.created_at.desc())
        .all()
    )

    return [
        {
            "id": item.id,
            "user_phone": item.user_phone,
            "transaction_id": item.transaction_id,
            "reason": item.reason,
            "description": item.description,
            "status": item.status,
            "created_at": item.created_at.isoformat()
            if item.created_at else None,
        }
        for item in reports
    ]


class ReportUpdate(BaseModel):
    status: str = Field(..., min_length=2, max_length=30)


@app.patch("/api/v1/admin/reports/{report_id}")
def update_report(
    report_id: int,
    payload: ReportUpdate,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    report = db.query(Report).filter(
        Report.id == report_id
    ).first()

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found."
        )

    allowed_statuses = {
        "PENDING",
        "INVESTIGATING",
        "RESOLVED",
        "REJECTED",
    }

    new_status = payload.status.upper()

    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid report status."
        )

    report.status = new_status

    log_activity(
        db,
        "REPORT_UPDATED",
        report.user_phone,
        f"Report {report.id} changed to {new_status}."
    )

    db.commit()

    return {
        "success": True,
        "status": report.status,
    }


# ============================================================
# ADMIN INVESTIGATION CASES
# ============================================================

class CaseCreate(BaseModel):
    transaction_id: str = Field(..., min_length=1, max_length=100)
    assigned_to: Optional[str] = Field(None, max_length=100)
    priority: str = Field(default="MEDIUM", max_length=30)
    findings: Optional[str] = None


class CaseUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    priority: Optional[str] = None
    findings: Optional[str] = None
    resolution: Optional[str] = None


def serialize_case(case: InvestigationCase):
    return {
        "id": case.id,
        "transaction_id": case.transaction_id,
        "assigned_to": case.assigned_to,
        "status": case.status,
        "priority": case.priority,
        "findings": case.findings,
        "resolution": case.resolution,
        "title": f"Investigation: {case.transaction_id}",
        "description": case.findings or "",
        "created_at": case.created_at.isoformat()
        if case.created_at else None,
        "updated_at": case.updated_at.isoformat()
        if case.updated_at else None,
    }


@app.get("/api/v1/admin/cases")
def admin_cases(
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    cases = (
        db.query(InvestigationCase)
        .order_by(InvestigationCase.created_at.desc())
        .all()
    )

    return [serialize_case(case) for case in cases]


@app.post("/api/v1/admin/cases")
def create_case(
    payload: CaseCreate,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    transaction = db.query(Transaction).filter(
        Transaction.transaction_id == payload.transaction_id
    ).first()

    if not transaction:
        raise HTTPException(
            status_code=404,
            detail="Transaction not found."
        )

    case = InvestigationCase(
        transaction_id=payload.transaction_id,
        assigned_to=payload.assigned_to,
        priority=payload.priority.upper(),
        findings=payload.findings,
        status="OPEN",
    )

    db.add(case)

    log_activity(
        db,
        "INVESTIGATION_CREATED",
        transaction.sender_msisdn,
        f"Investigation opened for {payload.transaction_id}."
    )

    db.commit()
    db.refresh(case)

    return {
        "success": True,
        "case": serialize_case(case),
    }


@app.patch("/api/v1/admin/cases/{case_id}")
def update_case(
    case_id: int,
    payload: CaseUpdate,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    case = db.query(InvestigationCase).filter(
        InvestigationCase.id == case_id
    ).first()

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    if payload.status is not None:
        allowed = {
            "OPEN",
            "IN_PROGRESS",
            "RESOLVED",
            "CLOSED",
        }

        if payload.status.upper() not in allowed:
            raise HTTPException(
                status_code=400,
                detail="Invalid investigation status."
            )

        case.status = payload.status.upper()

    if payload.priority is not None:
        case.priority = payload.priority.upper()

    if payload.assigned_to is not None:
        case.assigned_to = payload.assigned_to

    if payload.findings is not None:
        case.findings = payload.findings

    if payload.resolution is not None:
        case.resolution = payload.resolution

    case.updated_at = utc_now()

    log_activity(
        db,
        "INVESTIGATION_UPDATED",
        None,
        f"Investigation case {case.id} updated."
    )

    db.commit()
    db.refresh(case)

    return {
        "success": True,
        "case": serialize_case(case),
    }


# ============================================================
# CUSTOMER AUTHENTICATION HELPER
# ============================================================

def get_authenticated_user(
    current: dict,
    db: Session,
):
    if not isinstance(current, dict) or not current.get("id"):
        raise HTTPException(status_code=401, detail="Please sign in again.")

    user = db.query(User).filter(
        User.id == current["id"]
    ).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="User account unavailable."
        )

    return user


# ============================================================
# CUSTOMER PROFILE
# ============================================================

@app.get("/api/v1/user/profile")
def user_profile(
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)

    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "phone": user.phone,
        "email": user.email,
        "balance": ngwee_to_kwacha(user.balance_ngwee),
        "balance_ngwee": user.balance_ngwee,
        "currency": "ZMW",
        "is_active": user.is_active,
    }


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(None, max_length=150)
    email: Optional[str] = Field(None, max_length=150)


@app.put("/api/v1/user/profile")
def update_profile(
    payload: ProfileUpdate,
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)

    if payload.email:
        existing = db.query(User).filter(
            User.email == payload.email,
            User.id != user.id,
        ).first()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="Email address is already in use."
            )

    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()

    if payload.email is not None:
        user.email = payload.email.strip() or None

    log_activity(
        db,
        "PROFILE_UPDATED",
        get_user_phone(user),
        "Customer profile updated."
    )

    db.commit()

    return {
        "success": True,
        "message": "Profile updated."
    }


# ============================================================
# CUSTOMER TRANSACTION HISTORY
# ============================================================

@app.get("/api/v1/user/transactions")
def user_transactions(
    limit: int = 100,
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)
    phone = get_user_phone(user)

    records = (
        db.query(Transaction)
        .filter(
            or_(
                Transaction.sender_msisdn == phone,
                Transaction.receiver_msisdn == phone,
            )
        )
        .order_by(Transaction.created_at.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )

    return [
        serialize_transaction(item)
        for item in records
    ]


@app.get("/api/v1/user/stats")
def user_stats(
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)
    phone = get_user_phone(user)

    sent = db.query(Transaction).filter(
        Transaction.sender_msisdn == phone,
        Transaction.decision == "ALLOW",
    ).all()

    received = db.query(Transaction).filter(
        Transaction.receiver_msisdn == phone,
        Transaction.decision == "ALLOW",
    ).all()

    return {
        "balance": ngwee_to_kwacha(user.balance_ngwee),
        "balance_ngwee": user.balance_ngwee,
        "total_sent": round(
            sum(float(item.amount) for item in sent),
            2
        ),
        "total_received": round(
            sum(float(item.amount) for item in received),
            2
        ),
        "transactions_count": len(sent) + len(received),
        "currency": "ZMW",
    }


# ============================================================
# WALLET REQUEST MODELS
# ============================================================

class WalletTransferRequest(BaseModel):
    recipient_phone: str = Field(..., min_length=5, max_length=20)
    amount: Decimal = Field(..., gt=0, le=500000)
    note: Optional[str] = Field(None, max_length=250)


class WalletTopUpRequest(BaseModel):
    amount: Decimal = Field(..., gt=0, le=10000)


class WalletWithdrawRequest(BaseModel):
    recipient_phone: str = Field(..., min_length=5, max_length=20)
    amount: Decimal = Field(..., gt=0, le=500000)


class AirtimePurchaseRequest(BaseModel):
    phone: str = Field(..., min_length=5, max_length=20)
    amount: Decimal = Field(..., gt=0, le=10000)
    network: str = Field(default="Airtel", max_length=30)


# ============================================================
# WALLET CORE
# ============================================================

def add_wallet_ledger(
    db: Session,
    user: User,
    transaction_id: str,
    direction: str,
    amount_ngwee: int,
    description: str,
):
    db.add(
        WalletLedger(
            transaction_id=transaction_id,
            user_id=user.id,
            direction=direction,
            amount_ngwee=amount_ngwee,
            balance_after_ngwee=user.balance_ngwee,
            description=description,
            created_at=utc_now(),
        )
    )


def run_wallet_fraud_check(
    db: Session,
    sender_phone: str,
    receiver_phone: str,
    amount_ngwee: int,
    channel: str,
    transaction_type: str,
):
    activity = calculate_sender_activity(
        db,
        sender_phone
    )

    tx_request = TransactionRequest(
        transaction_id=f"GRD-{uuid.uuid4().hex[:16].upper()}",
        amount=ngwee_to_kwacha(amount_ngwee),
        currency="ZMW",
        sender_msisdn=sender_phone,
        receiver_msisdn=receiver_phone,
        channel=channel,
        timestamp=datetime.now(timezone.utc),
        sender_tx_count_last_1h=activity[
            "sender_tx_count_last_1h"
        ],
        sender_tx_count_last_24h=activity[
            "sender_tx_count_last_24h"
        ],
        sender_total_amount_last_24h=activity[
            "sender_total_amount_last_24h"
        ],
    )

    result = detector.analyze(tx_request)

    return tx_request, result


def wallet_decision_response(result):
    decision = enum_value(result.decision)

    return {
        "success": False,
        "decision": decision,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "recommendation": result.recommendation,
        "message": (
            "Transaction blocked by THE-GUARDIAN."
            if decision == "BLOCK"
            else "Transaction held for security review."
        ),
    }


def commit_fraud_attempt(
    db: Session,
    tx_request,
    result,
    transaction_type: str,
):
    record = create_transaction_record(
        db,
        tx_request,
        result,
        transaction_type=transaction_type,
    )

    db.commit()
    db.refresh(record)

    broadcast_dashboard_event({
        "type": "FRAUD_ALERT",
        "transaction": serialize_transaction(record),
    })

    return record


# ============================================================
# WALLET TOP-UP
# ============================================================

@app.post("/api/v1/user/topup")
def wallet_topup(
    payload: WalletTopUpRequest,
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)

    try:
        amount_ngwee = amount_to_ngwee(payload.amount)

        tx_request, result = run_wallet_fraud_check(
            db=db,
            sender_phone="AIRTEL-GATEWAY",
            receiver_phone=get_user_phone(user),
            amount_ngwee=amount_ngwee,
            channel="airtel_gateway",
            transaction_type="TOPUP",
        )

        decision = enum_value(result.decision)

        if decision != "ALLOW":
            commit_fraud_attempt(
                db,
                tx_request,
                result,
                "TOPUP",
            )

            return wallet_decision_response(result)

        new_balance = user.balance_ngwee + amount_ngwee

        user.balance_ngwee = new_balance
        user.balance = ngwee_to_kwacha(new_balance)

        record = create_transaction_record(
            db,
            tx_request,
            result,
            transaction_type="TOPUP",
        )

        db.add(record)

        add_wallet_ledger(
            db,
            user,
            tx_request.transaction_id,
            "CREDIT",
            amount_ngwee,
            "Wallet top-up",
        )

        log_activity(
            db,
            "WALLET_TOPUP",
            get_user_phone(user),
            f"Wallet top-up: K{ngwee_to_kwacha(amount_ngwee):.2f}",
        )

        db.commit()
        db.refresh(user)
        db.refresh(record)

        broadcast_dashboard_event({
            "type": "WALLET_TOPUP",
            "transaction": serialize_transaction(record),
        })

        return {
            "success": True,
            "message": "Wallet balance updated successfully.",
            "wallet_environment": "DEMO",
            "transaction_id": tx_request.transaction_id,
            "amount": ngwee_to_kwacha(amount_ngwee),
            "balance": ngwee_to_kwacha(user.balance_ngwee),
            "decision": decision,
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Wallet top-up failed.")

        raise HTTPException(
            status_code=500,
            detail="Wallet top-up failed."
        )


# ============================================================
# WALLET TRANSFER
# ============================================================

@app.post("/api/v1/user/airtel-transfer")
def wallet_transfer(
    payload: WalletTransferRequest,
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)

    recipient_phone = payload.recipient_phone.strip()
    sender_phone = get_user_phone(user)

    if recipient_phone == sender_phone:
        raise HTTPException(
            status_code=400,
            detail="You cannot send money to yourself."
        )

    try:
        amount_ngwee = amount_to_ngwee(payload.amount)

        if user.balance_ngwee < amount_ngwee:
            raise HTTPException(
                status_code=400,
                detail="Insufficient wallet balance."
            )

        recipient = db.query(User).filter(
            or_(
                User.phone == recipient_phone,
                User.username == recipient_phone,
            ),
            User.is_active.is_(True),
        ).first()

        tx_request, result = run_wallet_fraud_check(
            db=db,
            sender_phone=sender_phone,
            receiver_phone=recipient_phone,
            amount_ngwee=amount_ngwee,
            channel="guardian_wallet",
            transaction_type="TRANSFER",
        )

        decision = enum_value(result.decision)

        if decision != "ALLOW":
            commit_fraud_attempt(
                db,
                tx_request,
                result,
                "TRANSFER",
            )

            return wallet_decision_response(result)

        # Conditional debit prevents spending more than the balance.
        debit_result = db.execute(
            update(User)
            .where(
                User.id == user.id,
                User.balance_ngwee >= amount_ngwee,
            )
            .values(
                balance_ngwee=User.balance_ngwee - amount_ngwee,
                balance=(
                    User.balance_ngwee - amount_ngwee
                ) / 100.0,
            )
            .execution_options(synchronize_session=False)
        )

        if debit_result.rowcount != 1:
            raise HTTPException(
                status_code=400,
                detail="Insufficient balance or wallet update failed."
            )

        if recipient:
            db.execute(
                update(User)
                .where(User.id == recipient.id)
                .values(
                    balance_ngwee=(
                        User.balance_ngwee + amount_ngwee
                    ),
                    balance=(
                        User.balance_ngwee + amount_ngwee
                    ) / 100.0,
                )
                .execution_options(synchronize_session=False)
            )

        db.flush()

        db.refresh(user)

        add_wallet_ledger(
            db,
            user,
            tx_request.transaction_id,
            "DEBIT",
            amount_ngwee,
            payload.note or "Wallet transfer",
        )

        if recipient:
            db.refresh(recipient)

            add_wallet_ledger(
                db,
                recipient,
                tx_request.transaction_id,
                "CREDIT",
                amount_ngwee,
                "Received Guardian wallet transfer",
            )

        record = create_transaction_record(
            db,
            tx_request,
            result,
            transaction_type=(
                "GUARDIAN_TRANSFER"
                if recipient
                else "EXTERNAL_TRANSFER_REQUEST"
            ),
        )

        db.add(record)

        log_activity(
            db,
            "WALLET_TRANSFER",
            sender_phone,
            (
                f"Sent K{ngwee_to_kwacha(amount_ngwee):.2f} "
                f"to {recipient_phone}."
            ),
        )

        db.commit()
        db.refresh(user)
        db.refresh(record)

        broadcast_dashboard_event({
            "type": "WALLET_TRANSFER",
            "transaction": serialize_transaction(record),
        })

        return {
            "success": True,
            "transaction_id": tx_request.transaction_id,
            "amount": ngwee_to_kwacha(amount_ngwee),
            "recipient": recipient_phone,
            "recipient_is_guardian_user": bool(recipient),
            "balance": ngwee_to_kwacha(user.balance_ngwee),
            "decision": decision,
            "message": (
                "Guardian wallet transfer completed."
                if recipient
                else "Transfer request recorded. External Airtel payout is not connected."
            ),
            "wallet_environment": "DEMO",
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Wallet transfer failed.")

        raise HTTPException(
            status_code=500,
            detail="Wallet transfer failed."
        )


# ============================================================
# WALLET WITHDRAWAL
# ============================================================

@app.post("/api/v1/user/withdraw")
def wallet_withdraw(
    payload: WalletWithdrawRequest,
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)

    phone = payload.recipient_phone.strip()

    try:
        amount_ngwee = amount_to_ngwee(payload.amount)

        if user.balance_ngwee < amount_ngwee:
            raise HTTPException(
                status_code=400,
                detail="Insufficient wallet balance."
            )

        tx_request, result = run_wallet_fraud_check(
            db,
            get_user_phone(user),
            phone,
            amount_ngwee,
            "wallet_withdrawal",
            "WITHDRAWAL",
        )

        decision = enum_value(result.decision)

        if decision != "ALLOW":
            commit_fraud_attempt(
                db,
                tx_request,
                result,
                "WITHDRAWAL",
            )

            return wallet_decision_response(result)

        debit = db.execute(
            update(User)
            .where(
                User.id == user.id,
                User.balance_ngwee >= amount_ngwee,
            )
            .values(
                balance_ngwee=User.balance_ngwee - amount_ngwee,
                balance=(
                    User.balance_ngwee - amount_ngwee
                ) / 100.0,
            )
            .execution_options(synchronize_session=False)
        )

        if debit.rowcount != 1:
            raise HTTPException(
                status_code=400,
                detail="Insufficient balance."
            )

        db.flush()
        db.refresh(user)

        add_wallet_ledger(
            db,
            user,
            tx_request.transaction_id,
            "DEBIT",
            amount_ngwee,
            "Wallet withdrawal",
        )

        record = create_transaction_record(
            db,
            tx_request,
            result,
            transaction_type="WITHDRAWAL",
        )

        db.add(record)

        log_activity(
            db,
            "WALLET_WITHDRAWAL",
            get_user_phone(user),
            f"Withdrawal request recorded for {phone}.",
        )

        db.commit()
        db.refresh(user)
        db.refresh(record)

        broadcast_dashboard_event({
            "type": "WALLET_WITHDRAWAL",
            "transaction": serialize_transaction(record),
        })

        return {
            "success": True,
            "message": "Withdrawal request recorded. External payout is not connected.",
            "wallet_environment": "DEMO",
            "transaction_id": tx_request.transaction_id,
            "amount": ngwee_to_kwacha(amount_ngwee),
            "balance": ngwee_to_kwacha(user.balance_ngwee),
            "decision": decision,
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Withdrawal failed.")

        raise HTTPException(
            status_code=500,
            detail="Withdrawal failed."
        )


# ============================================================
# AIRTIME PURCHASE
# ============================================================

@app.post("/api/v1/user/buy-airtime")
def buy_airtime(
    payload: AirtimePurchaseRequest,
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)

    phone = payload.phone.strip()
    network = payload.network.strip()

    if not network:
        raise HTTPException(
            status_code=400,
            detail="Network is required."
        )

    try:
        amount_ngwee = amount_to_ngwee(payload.amount)

        if user.balance_ngwee < amount_ngwee:
            raise HTTPException(
                status_code=400,
                detail="Insufficient wallet balance."
            )

        tx_request, result = run_wallet_fraud_check(
            db,
            get_user_phone(user),
            phone,
            amount_ngwee,
            "airtime_order",
            "AIRTIME",
        )

        decision = enum_value(result.decision)

        if decision != "ALLOW":
            commit_fraud_attempt(
                db,
                tx_request,
                result,
                "AIRTIME",
            )

            return wallet_decision_response(result)

        debit = db.execute(
            update(User)
            .where(
                User.id == user.id,
                User.balance_ngwee >= amount_ngwee,
            )
            .values(
                balance_ngwee=User.balance_ngwee - amount_ngwee,
                balance=(
                    User.balance_ngwee - amount_ngwee
                ) / 100.0,
            )
            .execution_options(synchronize_session=False)
        )

        if debit.rowcount != 1:
            raise HTTPException(
                status_code=400,
                detail="Insufficient balance."
            )

        db.flush()
        db.refresh(user)

        add_wallet_ledger(
            db,
            user,
            tx_request.transaction_id,
            "DEBIT",
            amount_ngwee,
            f"{network} airtime purchase for {phone}",
        )

        record = create_transaction_record(
            db,
            tx_request,
            result,
            transaction_type="AIRTIME",
        )

        db.add(record)

        log_activity(
            db,
            "AIRTIME_PURCHASE",
            get_user_phone(user),
            f"{network} airtime purchase request for {phone}.",
        )

        db.commit()
        db.refresh(user)
        db.refresh(record)

        broadcast_dashboard_event({
            "type": "AIRTIME_PURCHASE",
            "transaction": serialize_transaction(record),
        })

        return {
            "success": True,
            "message": "Airtime purchase request recorded. Network delivery is not connected.",
            "wallet_environment": "DEMO",
            "network": network,
            "phone": phone,
            "amount": ngwee_to_kwacha(amount_ngwee),
            "balance": ngwee_to_kwacha(user.balance_ngwee),
            "transaction_id": tx_request.transaction_id,
            "decision": decision,
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Airtime purchase failed.")

        raise HTTPException(
            status_code=500,
            detail="Airtime purchase failed."
        )


# ============================================================
# WALLET LEDGER HISTORY
# ============================================================

@app.get("/api/v1/user/wallet/ledger")
def wallet_ledger_history(
    limit: int = 100,
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)

    entries = (
        db.query(WalletLedger)
        .filter(WalletLedger.user_id == user.id)
        .order_by(WalletLedger.created_at.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )

    return [
        {
            "id": item.id,
            "transaction_id": item.transaction_id,
            "direction": item.direction,
            "amount": ngwee_to_kwacha(item.amount_ngwee),
            "amount_ngwee": item.amount_ngwee,
            "balance_after": ngwee_to_kwacha(
                item.balance_after_ngwee
            ),
            "description": item.description,
            "created_at": item.created_at.isoformat()
            if item.created_at else None,
        }
        for item in entries
    ]


# ============================================================
# CUSTOMER REPORT SUBMISSION
# ============================================================

@app.post("/api/v1/user/report")
def submit_report(
    transaction_id: str = Form(...),
    reason: str = Form(...),
    description: Optional[str] = Form(None),
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)
    phone = get_user_phone(user)

    transaction = db.query(Transaction).filter(
        Transaction.transaction_id == transaction_id,
        or_(
            Transaction.sender_msisdn == phone,
            Transaction.receiver_msisdn == phone,
        ),
    ).first()

    if not transaction:
        raise HTTPException(
            status_code=404,
            detail="Transaction not found in your account."
        )

    report = Report(
        user_phone=phone,
        transaction_id=transaction_id,
        reason=reason.strip(),
        description=description,
        status="PENDING",
        created_at=utc_now(),
    )

    db.add(report)

    log_activity(
        db,
        "TRANSACTION_REPORTED",
        phone,
        f"Transaction {transaction_id} reported."
    )

    db.commit()
    db.refresh(report)

    broadcast_dashboard_event({
        "type": "NEW_REPORT",
        "report_id": report.id,
        "transaction_id": transaction_id,
    })

    return {
        "success": True,
        "message": "Your report has been submitted.",
        "report_id": report.id,
    }


# ============================================================
# CUSTOMER NOTIFICATIONS
# ============================================================

@app.get("/api/v1/user/notifications")
def user_notifications(
    limit: int = 50,
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)
    phone = get_user_phone(user)

    notifications = (
        db.query(ActivityLog)
        .filter(ActivityLog.user_phone == phone)
        .order_by(ActivityLog.created_at.desc())
        .limit(min(max(limit, 1), 200))
        .all()
    )

    return [
        {
            "id": item.id,
            "action": item.action,
            "details": item.details,
            "time": item.created_at.isoformat()
            if item.created_at else None,
        }
        for item in notifications
    ]


# ============================================================
# AI NYASHA (Google Gemini - Fixed & Stable)
# ============================================================

import httpx

class AIChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)


@app.post("/api/v1/user/ai-chat")
async def ai_chat(
    payload: AIChatRequest,
    current=Depends(require_user),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(current, db)
    message = payload.message.strip()

    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        return {
            "success": False,
            "reply": "AI NYASHA is not configured. Please contact the administrator.",
            "message": "AI NYASHA is not configured."
        }

    # Use a stable free model
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_api_key}"

    headers = {"Content-Type": "application/json"}

    data = {
        "contents": [{
            "parts": [{
                "text": (
                    "You are AI NYASHA, a helpful and professional assistant inside THE GUARDIAN "
                    "fraud detection system in Zambia. Answer clearly, politely and keep responses short. "
                    "Help users with wallet, transactions, security and general questions. "
                    "Never ask for passwords, PINs or OTP codes.\n\n"
                    f"User: {message}"
                )
            }]
        }],
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": 700
        }
    }

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            response = await client.post(url, headers=headers, json=data)

        if response.status_code == 200:
            result = response.json()
            answer = (
                result.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "I could not generate a response right now.")
            )
        else:
            answer = "AI NYASHA is temporarily busy. Please try again in a few seconds."

    except Exception as e:
        logger.error(f"AI NYASHA Gemini error: {str(e)}")
        answer = "Sorry, AI NYASHA is temporarily unavailable. Please try again shortly."

    # Log so it shows on Admin Dashboard
    log_activity(
        db,
        "AI_NYASHA_CHAT",
        get_user_phone(user),
        f"User asked: {message[:80]}"
    )
    db.commit()

    return {
        "success": True,
        "assistant": "AI NYASHA",
        "reply": answer,
        "message": answer
    }


# ============================================================
# ADMIN WALLET OVERVIEW
# ============================================================

@app.get("/api/v1/admin/wallets")
def admin_wallets(
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    users = db.query(User).order_by(User.id.desc()).all()

    return [
        {
            "user_id": user.id,
            "full_name": user.full_name,
            "phone": get_user_phone(user),
            "balance": ngwee_to_kwacha(user.balance_ngwee),
            "balance_ngwee": user.balance_ngwee,
            "is_active": user.is_active,
        }
        for user in users
    ]


@app.get("/api/v1/admin/wallet-ledger")
def admin_wallet_ledger(
    limit: int = 200,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    entries = (
        db.query(WalletLedger)
        .order_by(WalletLedger.created_at.desc())
        .limit(min(max(limit, 1), 1000))
        .all()
    )

    return [
        {
            "id": item.id,
            "user_id": item.user_id,
            "transaction_id": item.transaction_id,
            "direction": item.direction,
            "amount": ngwee_to_kwacha(item.amount_ngwee),
            "balance_after": ngwee_to_kwacha(
                item.balance_after_ngwee
            ),
            "description": item.description,
            "created_at": item.created_at.isoformat()
            if item.created_at else None,
        }
        for item in entries
    ]


# ============================================================
# SYSTEM INFORMATION
# ============================================================

@app.get("/api/v1/system/status")
def system_status(
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    return {
        "application": APP_NAME,
        "status": "ONLINE",
        "database": "CONNECTED",
        "fraud_detector": "ACTIVE",
        "wallet_mode": "GUARDIAN_DEMO_LEDGER",
        "external_settlement": "NOT_CONNECTED",
        "airtel_live_api": "NOT_CONFIGURED",
        "ai_provider": "GOOGLE_GEMINI",
        "ai_model": os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        "ai_nyasha": (
            "CONFIGURED"
            if os.getenv("GEMINI_API_KEY")
            else "NOT_CONFIGURED"
        ),
        "users": db.query(User).count(),
        "transactions": db.query(Transaction).count(),
        "time": utc_now().isoformat(),
    }


# ============================================================
# APPLICATION STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():
    logger.info("%s starting.", APP_NAME)
    logger.info("Fraud detection engine loaded.")
    logger.info("Wallet simulation routes loaded.")
    logger.info("AI assistant name: %s", AI_NAME)


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("%s shutting down.", APP_NAME)


# ============================================================
# CUSTOMER FEATURES: SAVINGS, QR PAYMENTS, VIRTUAL CARD,
# SPENDING ANALYTICS AND SECURITY CENTRE
# ============================================================

from datetime import date
from secrets import token_urlsafe

class SavingsGoalCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    target_amount: Decimal = Field(..., gt=0, le=10000000)
    deadline: Optional[date] = None

class SavingsContribution(BaseModel):
    amount: Decimal = Field(..., gt=0, le=1000000)

class QRPaymentRequest(BaseModel):
    qr_token: str = Field(..., min_length=8, max_length=100)
    amount: Decimal = Field(..., gt=0, le=500000)
    note: Optional[str] = Field(None, max_length=250)


def create_security_alert(db: Session, user: User, alert_type: str, severity: str, title: str, message: str):
    alert = SecurityAlert(user_id=user.id, user_phone=get_user_phone(user), alert_type=alert_type,
                          severity=severity, title=title, message=message)
    db.add(alert)
    db.flush()
    return alert


@app.get("/api/v1/user/savings-goals")
def list_savings_goals(current=Depends(require_user), db: Session=Depends(get_db)):
    user=get_authenticated_user(current, db)
    goals=db.query(SavingsGoal).filter(SavingsGoal.user_id==user.id).order_by(SavingsGoal.created_at.desc()).all()
    return [{"id":g.id,"name":g.name,"target_amount":ngwee_to_kwacha(g.target_ngwee),
             "saved_amount":ngwee_to_kwacha(g.saved_ngwee),"remaining_amount":ngwee_to_kwacha(max(0,g.target_ngwee-g.saved_ngwee)),
             "progress":round(min(100,g.saved_ngwee/g.target_ngwee*100),1),"deadline":g.deadline.isoformat() if g.deadline else None,"status":g.status} for g in goals]

@app.post("/api/v1/user/savings-goals")
def create_savings_goal(payload:SavingsGoalCreate, current=Depends(require_user), db:Session=Depends(get_db)):
    user=get_authenticated_user(current, db)
    goal=SavingsGoal(user_id=user.id,name=payload.name.strip(),target_ngwee=amount_to_ngwee(payload.target_amount),deadline=datetime.combine(payload.deadline, datetime.min.time()) if payload.deadline else None)
    db.add(goal); log_activity(db,"SAVINGS_GOAL_CREATED",get_user_phone(user),f"Savings goal created: {goal.name}"); db.commit(); db.refresh(goal)
    return {"success":True,"goal_id":goal.id,"message":"Savings goal created."}

@app.post("/api/v1/user/savings-goals/{goal_id}/contribute")
def contribute_savings(
    goal_id: int,
    payload: SavingsContribution,
    current=Depends(require_user),
    db: Session=Depends(get_db),
):
    user = get_authenticated_user(current, db)
    try:
        amount = amount_to_ngwee(payload.amount)
        goal = db.query(SavingsGoal).filter(
            SavingsGoal.id == goal_id,
            SavingsGoal.user_id == user.id,
            SavingsGoal.status == "ACTIVE",
        ).first()
        if not goal:
            raise HTTPException(status_code=404, detail="Savings goal not found.")

        phone = get_user_phone(user)
        tx_request, result = run_wallet_fraud_check(
            db, phone, f"SAVINGS-GOAL-{goal.id}", amount,
            "guardian_savings", "SAVINGS_CONTRIBUTION",
        )
        decision = enum_value(result.decision)
        if decision != "ALLOW":
            commit_fraud_attempt(db, tx_request, result, "SAVINGS_CONTRIBUTION")
            return wallet_decision_response(result)

        debit = db.execute(
            update(User)
            .where(User.id == user.id, User.balance_ngwee >= amount)
            .values(
                balance_ngwee=User.balance_ngwee - amount,
                balance=(User.balance_ngwee - amount) / 100.0,
            )
            .execution_options(synchronize_session=False)
        )
        if debit.rowcount != 1:
            raise HTTPException(status_code=400, detail="Insufficient wallet balance.")

        goal.saved_ngwee += amount
        if goal.saved_ngwee >= goal.target_ngwee:
            goal.status = "COMPLETED"
        db.flush()
        db.refresh(user)

        add_wallet_ledger(
            db, user, tx_request.transaction_id, "DEBIT", amount,
            f"Contribution to savings goal: {goal.name}",
        )
        record = create_transaction_record(
            db, tx_request, result, transaction_type="SAVINGS_CONTRIBUTION",
        )
        log_activity(
            db, "SAVINGS_CONTRIBUTION", phone,
            f"Contributed K{ngwee_to_kwacha(amount):.2f} to {goal.name}.",
        )
        db.commit()
        db.refresh(user)
        db.refresh(record)
        broadcast_dashboard_event({
            "type": "WALLET_TRANSACTION",
            "transaction": serialize_transaction(record),
        })
        return {
            "success": True,
            "transaction_id": tx_request.transaction_id,
            "message": "Savings contribution recorded successfully.",
            "balance": ngwee_to_kwacha(user.balance_ngwee),
            "saved_amount": ngwee_to_kwacha(goal.saved_ngwee),
            "goal_status": goal.status,
            "decision": decision,
        }
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        logger.exception("Savings contribution failed.")
        raise HTTPException(status_code=500, detail="Savings contribution failed.")


@app.get("/api/v1/user/qr-code")
def get_payment_qr(current=Depends(require_user),db:Session=Depends(get_db)):
    user=get_authenticated_user(current,db)
    return {"qr_token":f"GUARDIAN:{user.id}:{user.username}","display_name":user.full_name or user.username,"phone":get_user_phone(user)}

@app.post("/api/v1/user/qr-pay")
def pay_by_qr(
    payload: QRPaymentRequest,
    current=Depends(require_user),
    db: Session=Depends(get_db),
):
    sender = get_authenticated_user(current, db)
    try:
        prefix, uid, _username = payload.qr_token.split(":", 2)
        recipient_id = int(uid)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid Guardian payment QR code.")

    if prefix != "GUARDIAN" or recipient_id == sender.id:
        raise HTTPException(status_code=400, detail="Invalid recipient.")

    recipient = db.query(User).filter(
        User.id == recipient_id,
        User.is_active.is_(True),
    ).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient account not found.")

    try:
        amount = amount_to_ngwee(payload.amount)
        sender_phone = get_user_phone(sender)
        recipient_phone = get_user_phone(recipient)
        tx_request, result = run_wallet_fraud_check(
            db, sender_phone, recipient_phone, amount,
            "guardian_qr", "QR_PAYMENT",
        )
        decision = enum_value(result.decision)
        if decision != "ALLOW":
            commit_fraud_attempt(db, tx_request, result, "QR_PAYMENT")
            return wallet_decision_response(result)

        debit = db.execute(
            update(User)
            .where(User.id == sender.id, User.balance_ngwee >= amount)
            .values(
                balance_ngwee=User.balance_ngwee - amount,
                balance=(User.balance_ngwee - amount) / 100.0,
            )
            .execution_options(synchronize_session=False)
        )
        if debit.rowcount != 1:
            raise HTTPException(status_code=400, detail="Insufficient wallet balance.")

        credit = db.execute(
            update(User)
            .where(User.id == recipient.id, User.is_active.is_(True))
            .values(
                balance_ngwee=User.balance_ngwee + amount,
                balance=(User.balance_ngwee + amount) / 100.0,
            )
            .execution_options(synchronize_session=False)
        )
        if credit.rowcount != 1:
            raise HTTPException(status_code=409, detail="Recipient wallet could not be credited.")

        db.flush()
        db.refresh(sender)
        db.refresh(recipient)
        note = payload.note or "Guardian QR payment"
        add_wallet_ledger(db, sender, tx_request.transaction_id, "DEBIT", amount,
                          f"{note} to {recipient_phone}")
        add_wallet_ledger(db, recipient, tx_request.transaction_id, "CREDIT", amount,
                          f"{note} from {sender_phone}")
        record = create_transaction_record(db, tx_request, result, transaction_type="QR_PAYMENT")
        log_activity(db, "QR_PAYMENT_SENT", sender_phone,
                     f"QR payment {tx_request.transaction_id} to {recipient_phone}.")
        log_activity(db, "QR_PAYMENT_RECEIVED", recipient_phone,
                     f"QR payment {tx_request.transaction_id} received from {sender_phone}.")
        db.commit()
        db.refresh(sender)
        db.refresh(record)
        event = {"type": "WALLET_TRANSACTION", "transaction": serialize_transaction(record)}
        broadcast_dashboard_event(event)
        return {
            "success": True,
            "transaction_id": tx_request.transaction_id,
            "message": "QR wallet payment completed successfully.",
            "balance": ngwee_to_kwacha(sender.balance_ngwee),
            "decision": decision,
        }
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        logger.exception("QR payment failed.")
        raise HTTPException(status_code=500, detail="QR payment failed.")


@app.get("/api/v1/user/virtual-card")
def get_virtual_card(current=Depends(require_user),db:Session=Depends(get_db)):
    user=get_authenticated_user(current,db)
    card=db.query(GuardianCard).filter(GuardianCard.user_id==user.id).first()
    if not card:
        raw=uuid.uuid4().hex[:16].upper(); card=GuardianCard(user_id=user.id,card_token=token_urlsafe(32),last_four=raw[-4:],cardholder=(user.full_name or user.username).upper())
        db.add(card); db.commit(); db.refresh(card)
    return {"cardholder":card.cardholder,"last_four":card.last_four,"status":card.status,"created_at":card.created_at.isoformat()}

@app.post("/api/v1/user/virtual-card/freeze")
def freeze_virtual_card(current=Depends(require_user),db:Session=Depends(get_db)):
    user=get_authenticated_user(current,db); card=db.query(GuardianCard).filter(GuardianCard.user_id==user.id).first()
    if not card: raise HTTPException(404,"Virtual card has not been issued.")
    card.status="FROZEN"; log_activity(db,"VIRTUAL_CARD_FROZEN",get_user_phone(user),"Virtual Guardian Card frozen.")
    create_security_alert(db,user,"CARD_STATUS","WARNING","Virtual card frozen","Your Virtual Guardian Card has been frozen.")
    db.commit(); return {"success":True,"status":card.status}

@app.post("/api/v1/user/virtual-card/unfreeze")
def unfreeze_virtual_card(current=Depends(require_user),db:Session=Depends(get_db)):
    user=get_authenticated_user(current,db); card=db.query(GuardianCard).filter(GuardianCard.user_id==user.id).first()
    if not card: raise HTTPException(404,"Virtual card has not been issued.")
    card.status="ACTIVE"; log_activity(db,"VIRTUAL_CARD_UNFROZEN",get_user_phone(user),"Virtual Guardian Card unfrozen.")
    create_security_alert(db,user,"CARD_STATUS","INFO","Virtual card activated","Your Virtual Guardian Card is active.")
    db.commit(); return {"success":True,"status":card.status}

@app.get("/api/v1/user/spending-analytics")
def spending_analytics(period:str="month",current=Depends(require_user),db:Session=Depends(get_db)):
    user=get_authenticated_user(current,db); now=utc_now()
    days={"week":7,"month":30,"year":365}.get(period)
    if not days: raise HTTPException(400,"Period must be week, month or year.")
    start=now-timedelta(days=days)
    records=db.query(Transaction).filter(Transaction.sender_msisdn==get_user_phone(user),Transaction.created_at>=start,Transaction.decision=="ALLOW").all()
    by_type={}; daily={}
    for tx in records:
        kind=(tx.transaction_type or "OTHER").upper(); by_type[kind]=round(by_type.get(kind,0)+float(tx.amount),2)
        day=tx.created_at.strftime("%Y-%m-%d"); daily[day]=round(daily.get(day,0)+float(tx.amount),2)
    return {"period":period,"total_spent":round(sum(float(x.amount) for x in records),2),"transaction_count":len(records),
            "by_type":[{"category":k,"amount":v} for k,v in sorted(by_type.items())],"daily":[{"date":k,"amount":v} for k,v in sorted(daily.items())]}

@app.get("/api/v1/user/security-alerts")
def user_security_alerts(current=Depends(require_user),db:Session=Depends(get_db)):
    user=get_authenticated_user(current,db)
    rows=db.query(SecurityAlert).filter(SecurityAlert.user_id==user.id).order_by(SecurityAlert.created_at.desc()).limit(100).all()
    return [{"id":a.id,"type":a.alert_type,"severity":a.severity,"title":a.title,"message":a.message,"is_read":a.is_read,"created_at":a.created_at.isoformat()} for a in rows]

@app.post("/api/v1/user/security-alerts/{alert_id}/read")
def mark_security_alert_read(alert_id:int,current=Depends(require_user),db:Session=Depends(get_db)):
    user=get_authenticated_user(current,db); alert=db.query(SecurityAlert).filter(SecurityAlert.id==alert_id,SecurityAlert.user_id==user.id).first()
    if not alert: raise HTTPException(404,"Security alert not found.")
    alert.is_read=True; db.commit(); return {"success":True}

@app.get("/api/v1/admin/security-alerts")
def admin_security_alerts(admin=Depends(require_admin),db:Session=Depends(get_db)):
    rows=db.query(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(500).all()
    return [{"id":a.id,"user_id":a.user_id,"user_phone":a.user_phone,"type":a.alert_type,"severity":a.severity,"title":a.title,"message":a.message,"is_read":a.is_read,"created_at":a.created_at.isoformat()} for a in rows]

@app.get("/api/v1/admin/feature-overview")
def admin_feature_overview(admin=Depends(require_admin),db:Session=Depends(get_db)):
    return {"savings_goals":db.query(SavingsGoal).count(),"savings_active":db.query(SavingsGoal).filter(SavingsGoal.status=="ACTIVE").count(),
            "virtual_cards":db.query(GuardianCard).count(),"frozen_cards":db.query(GuardianCard).filter(GuardianCard.status=="FROZEN").count(),
            "security_alerts":db.query(SecurityAlert).count(),"unread_security_alerts":db.query(SecurityAlert).filter(SecurityAlert.is_read.is_(False)).count()}
