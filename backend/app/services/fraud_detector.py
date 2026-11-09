from datetime import datetime, timezone
from typing import List

from backend.app.models.transaction import (
    TransactionRequest,
    FraudResponse,
    RiskFactor,
    Decision,
)
from backend.app.core.config import settings


class FraudDetector:
    """
    THE GUARDIAN
    Real-Time AI-Assisted Fraud Detection Engine

    Analyzes mobile money transactions and calculates
    a normalized fraud risk score between 0 and 1.
    """

    def __init__(self):
        self.review_threshold = float(
            getattr(settings, "REVIEW_THRESHOLD", 0.40)
        )

        self.block_threshold = float(
            getattr(settings, "BLOCK_THRESHOLD", 0.75)
        )

        self.max_transactions_per_hour = int(
            getattr(settings, "MAX_TRANSACTIONS_PER_HOUR", 10)
        )

        self.max_amount_per_day = float(
            getattr(settings, "MAX_AMOUNT_PER_DAY", 20000)
        )

        if not 0 <= self.review_threshold <= 1:
            raise ValueError("REVIEW_THRESHOLD must be between 0 and 1.")

        if not 0 <= self.block_threshold <= 1:
            raise ValueError("BLOCK_THRESHOLD must be between 0 and 1.")

        if self.review_threshold > self.block_threshold:
            raise ValueError(
                "REVIEW_THRESHOLD cannot exceed BLOCK_THRESHOLD."
            )

        if self.max_transactions_per_hour < 1:
            raise ValueError(
                "MAX_TRANSACTIONS_PER_HOUR must be at least 1."
            )

        if self.max_amount_per_day <= 0:
            raise ValueError(
                "MAX_AMOUNT_PER_DAY must be greater than zero."
            )

    @staticmethod
    def _add_factor(
        factors: List[RiskFactor],
        name: str,
        score: float,
        reason: str,
    ):
        """
        Add a normalized risk factor.
        """

        score = max(0.0, min(float(score), 1.0))

        factors.append(
            RiskFactor(
                name=name,
                score=score,
                reason=reason,
            )
        )

    @staticmethod
    def _get_timestamp(value: datetime) -> datetime:
        """
        Ensure timestamps can be evaluated consistently.
        """

        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)

    def analyze(self, tx: TransactionRequest) -> FraudResponse:
        """
        Analyze a transaction and return a fraud decision.
        """

        factors: List[RiskFactor] = []
        risk_score = 0.0

        transaction_time = self._get_timestamp(tx.timestamp)

        # --------------------------------------------------
        # 1. HIGH TRANSACTION AMOUNT
        # --------------------------------------------------

        if tx.amount >= 5000:
            score = min(0.45, 0.20 + (tx.amount / 500000) * 0.25)

            risk_score += score

            self._add_factor(
                factors,
                "HIGH_TRANSACTION_AMOUNT",
                score,
                f"Transaction amount of {tx.currency} {tx.amount:,.2f} "
                "is unusually high.",
            )

        # --------------------------------------------------
        # 2. TRANSACTION VELOCITY
        # --------------------------------------------------

        if (
            tx.sender_tx_count_last_1h
            >= self.max_transactions_per_hour
        ):
            score = 0.40
            risk_score += score

            self._add_factor(
                factors,
                "HIGH_TRANSACTION_VELOCITY",
                score,
                "Sender has exceeded the configured hourly transaction limit.",
            )

        elif tx.sender_tx_count_last_1h >= 5:
            score = 0.22
            risk_score += score

            self._add_factor(
                factors,
                "ELEVATED_TRANSACTION_VELOCITY",
                score,
                "Sender has made several transactions within one hour.",
            )

        # --------------------------------------------------
        # 3. DAILY TRANSACTION AMOUNT
        # --------------------------------------------------

        projected_daily_amount = (
            tx.sender_total_amount_last_24h + tx.amount
        )

        if projected_daily_amount > self.max_amount_per_day:
            score = 0.35
            risk_score += score

            self._add_factor(
                factors,
                "DAILY_AMOUNT_LIMIT_EXCEEDED",
                score,
                "Projected daily transaction amount exceeds the configured limit.",
            )

        # --------------------------------------------------
        # 4. NEW BENEFICIARY
        # --------------------------------------------------

        if tx.receiver_is_new:
            score = 0.28
            risk_score += score

            self._add_factor(
                factors,
                "NEW_BENEFICIARY",
                score,
                "The receiver has not previously been identified as a beneficiary.",
            )

        # --------------------------------------------------
        # 5. UNUSUAL TRANSACTION TIME
        # --------------------------------------------------

        hour = transaction_time.hour

        if hour >= 23 or hour < 5:
            score = 0.18
            risk_score += score

            self._add_factor(
                factors,
                "UNUSUAL_TRANSACTION_TIME",
                score,
                "Transaction occurred between 23:00 and 04:59 UTC.",
            )

        # --------------------------------------------------
        # 6. INTERNATIONAL TRANSACTION
        # --------------------------------------------------

        if tx.is_international:
            score = 0.25
            risk_score += score

            self._add_factor(
                factors,
                "INTERNATIONAL_TRANSACTION",
                score,
                "Transaction is marked as international.",
            )

        # --------------------------------------------------
        # 7. BENEFICIARY RISK
        # --------------------------------------------------

        if tx.beneficiary_risk_score > 0.6:
            score = tx.beneficiary_risk_score * 0.30

            risk_score += score

            self._add_factor(
                factors,
                "HIGH_RISK_BENEFICIARY",
                score,
                "The beneficiary has an elevated historical risk score.",
            )

        # --------------------------------------------------
        # 8. DEVICE AND BENEFICIARY COMBINATION
        # --------------------------------------------------

        if (
            tx.sender_device_id
            and tx.amount > 2000
            and tx.receiver_is_new
        ):
            score = 0.32
            risk_score += score

            self._add_factor(
                factors,
                "DEVICE_BENEFICIARY_RISK",
                score,
                "A transaction from a recorded device involves a new beneficiary and a high amount.",
            )

        # --------------------------------------------------
        # 9. FINAL RISK SCORE
        # --------------------------------------------------

        risk_score = round(
            min(max(risk_score, 0.0), 1.0),
            4,
        )

        # --------------------------------------------------
        # 10. FRAUD DECISION
        # --------------------------------------------------

        if risk_score >= self.block_threshold:
            decision = Decision.BLOCK
            risk_level = "CRITICAL"

            recommendation = (
                "BLOCK TRANSACTION. Critical fraud indicators detected. "
                "Refer the transaction for security investigation."
            )

        elif risk_score >= self.review_threshold:
            decision = Decision.REVIEW
            risk_level = "HIGH"

            recommendation = (
                "HOLD TRANSACTION FOR REVIEW. Additional verification "
                "is required before funds are released."
            )

        elif risk_score >= 0.20:
            decision = Decision.ALLOW
            risk_level = "MEDIUM"

            recommendation = (
                "Proceed with monitoring. Some risk indicators were detected."
            )

        else:
            decision = Decision.ALLOW
            risk_level = "LOW"

            recommendation = (
                "Transaction appears normal. Allow transaction and continue monitoring."
            )

        # --------------------------------------------------
        # 11. RETURN FRAUD RESPONSE
        # --------------------------------------------------

        return FraudResponse(
            transaction_id=tx.transaction_id,
            decision=decision,
            risk_score=risk_score,
            risk_level=risk_level,
            factors=factors,
            recommendation=recommendation,
            processed_at=datetime.now(timezone.utc),
        )


# ------------------------------------------------------
# GLOBAL FRAUD DETECTOR INSTANCE
# ------------------------------------------------------

detector = FraudDetector()
