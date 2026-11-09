
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Index,
    UniqueConstraint,
)

from backend.app.db.database import Base


class User(Base):
    """
    Guardian user account and mobile wallet profile.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(
        String(100),
        unique=True,
        index=True,
        nullable=False
    )

    full_name = Column(String(150), nullable=True)

    password = Column(String(255), nullable=False)

    phone = Column(
        String(20),
        unique=True,
        index=True,
        nullable=True
    )

    email = Column(
        String(150),
        unique=True,
        index=True,
        nullable=True
    )

    # Legacy balance field retained for existing dashboard compatibility.
    balance = Column(
        Float,
        default=0.0,
        nullable=False
    )

    # Primary wallet balance in ngwee (100 ngwee = K1).
    balance_ngwee = Column(
        Integer,
        default=0,
        nullable=False
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )

    last_login = Column(DateTime, nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )


class Transaction(Base):
    """
    Stores transactions analyzed by THE GUARDIAN.
    """

    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)

    transaction_id = Column(
        String(100),
        unique=True,
        index=True,
        nullable=False
    )

    amount = Column(Float, nullable=False)

    currency = Column(
        String(3),
        default="ZMW",
        nullable=False
    )

    sender_msisdn = Column(
        String(20),
        index=True,
        nullable=False
    )

    receiver_msisdn = Column(
        String(20),
        index=True,
        nullable=False
    )

    transaction_type = Column(
        String(50),
        default="TRANSFER",
        nullable=False
    )

    channel = Column(
        String(50),
        default="mobile_money",
        nullable=False
    )

    location = Column(String(255), nullable=True)

    location_lat = Column(Float, nullable=True)

    location_lon = Column(Float, nullable=True)

    device_id = Column(String(255), nullable=True)

    risk_score = Column(
        Float,
        default=0.0,
        nullable=False
    )

    risk_level = Column(
        String(30),
        default="LOW",
        nullable=False
    )

    decision = Column(
        String(20),
        default="ALLOW",
        nullable=False
    )

    recommendation = Column(Text, nullable=True)

    factors = Column(Text, nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    processed_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )


Index(
    "ix_transactions_sender_created",
    Transaction.sender_msisdn,
    Transaction.created_at
)


class WalletLedger(Base):
    """
    Permanent record of wallet credits and debits.

    Transfers between Guardian users should create two ledger
    entries sharing the same transaction_id.
    """

    __tablename__ = "wallet_ledger"

    id = Column(Integer, primary_key=True, index=True)

    transaction_id = Column(
        String(100),
        index=True,
        nullable=False
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        index=True,
        nullable=False
    )

    direction = Column(
        String(10),
        nullable=False
    )  # CREDIT or DEBIT

    amount_ngwee = Column(
        Integer,
        nullable=False
    )

    balance_after_ngwee = Column(
        Integer,
        nullable=False
    )

    description = Column(
        String(255),
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )


Index(
    "ix_wallet_ledger_user_created",
    WalletLedger.user_id,
    WalletLedger.created_at
)


class Report(Base):
    """
    Suspicious transaction reports submitted by users.
    """

    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)

    user_phone = Column(
        String(20),
        index=True,
        nullable=False
    )

    transaction_id = Column(
        String(100),
        index=True,
        nullable=False
    )

    reason = Column(
        String(255),
        nullable=False
    )

    description = Column(Text, nullable=True)

    status = Column(
        String(30),
        default="PENDING",
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )


class ActivityLog(Base):
    """
    Records important user and administrator activities.
    """

    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)

    user_phone = Column(
        String(50),
        index=True,
        nullable=True
    )

    action = Column(
        String(100),
        nullable=False
    )

    details = Column(Text, nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )


class InvestigationCase(Base):
    """
    Investigation records for suspicious transactions.
    """

    __tablename__ = "investigation_cases"

    id = Column(Integer, primary_key=True, index=True)

    transaction_id = Column(
        String(100),
        index=True,
        nullable=False
    )

    assigned_to = Column(
        String(100),
        nullable=True
    )

    status = Column(
        String(30),
        default="OPEN",
        nullable=False
    )

    priority = Column(
        String(30),
        default="MEDIUM",
        nullable=False
    )

    findings = Column(Text, nullable=True)

    resolution = Column(Text, nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )


class SavingsGoal(Base):
    __tablename__ = "savings_goals"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    name = Column(String(120), nullable=False)
    target_ngwee = Column(Integer, nullable=False)
    saved_ngwee = Column(Integer, default=0, nullable=False)
    deadline = Column(DateTime, nullable=True)
    status = Column(String(20), default="ACTIVE", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class GuardianCard(Base):
    __tablename__ = "guardian_cards"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, index=True, nullable=False)
    card_token = Column(String(64), unique=True, nullable=False)
    last_four = Column(String(4), nullable=False)
    cardholder = Column(String(150), nullable=False)
    status = Column(String(20), default="ACTIVE", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    user_phone = Column(String(30), index=True, nullable=True)
    alert_type = Column(String(60), nullable=False)
    severity = Column(String(20), default="INFO", nullable=False)
    title = Column(String(160), nullable=False)
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
