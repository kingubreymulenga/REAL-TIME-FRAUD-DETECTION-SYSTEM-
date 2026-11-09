from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, ConfigDict


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class TransactionRequest(BaseModel):
    """
    Incoming transaction data used by THE GUARDIAN
    fraud detection engine.
    """

    transaction_id: str = Field(
        ...,
        min_length=1,
        max_length=100
    )

    amount: float = Field(
        ...,
        gt=0,
        le=500000
    )

    currency: str = Field(
        default="ZMW",
        min_length=3,
        max_length=3
    )

    sender_msisdn: str = Field(
        ...,
        min_length=5,
        max_length=20
    )

    receiver_msisdn: str = Field(
        ...,
        min_length=5,
        max_length=20
    )

    sender_device_id: Optional[str] = Field(
        default=None,
        max_length=255
    )

    receiver_is_new: bool = False

    location_lat: Optional[float] = Field(
        default=None,
        ge=-90,
        le=90
    )

    location_lon: Optional[float] = Field(
        default=None,
        ge=-180,
        le=180
    )

    channel: str = Field(
        default="mobile_money",
        min_length=1,
        max_length=50
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    sender_tx_count_last_1h: int = Field(
        default=0,
        ge=0
    )

    sender_tx_count_last_24h: int = Field(
        default=0,
        ge=0
    )

    sender_total_amount_last_24h: float = Field(
        default=0.0,
        ge=0
    )

    is_international: bool = False

    beneficiary_risk_score: float = Field(
        default=0.0,
        ge=0,
        le=1
    )

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, value: float) -> float:
        if value > 500000:
            raise ValueError(
                "Transaction amount cannot exceed ZMW 500,000."
            )
        return value

    @field_validator("transaction_id", "sender_msisdn", "receiver_msisdn")
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("This field cannot be empty.")

        return value

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value


class RiskFactor(BaseModel):
    """
    Individual fraud risk factor detected during analysis.
    """

    name: str = Field(..., min_length=1)
    score: float = Field(..., ge=0, le=1)
    reason: str = Field(..., min_length=1)


class FraudResponse(BaseModel):
    """
    Standard response returned by THE GUARDIAN
    fraud detection engine.
    """

    transaction_id: str

    decision: Decision

    risk_score: float = Field(
        ...,
        ge=0,
        le=1
    )

    risk_level: str

    factors: List[RiskFactor] = Field(
        default_factory=list
    )

    recommendation: str

    processed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    model_config = ConfigDict(
        use_enum_values=True
    )
