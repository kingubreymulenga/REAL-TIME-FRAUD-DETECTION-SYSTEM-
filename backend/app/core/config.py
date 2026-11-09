from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "The Guardian - Fraud Detection API"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"

    # Risk thresholds
    BLOCK_THRESHOLD: float = 0.85
    REVIEW_THRESHOLD: float = 0.55

    # Velocity limits
    MAX_TRANSACTIONS_PER_HOUR: int = 8
    MAX_AMOUNT_PER_DAY: float = 15000.0

    model_config = {
        "env_file": ".env"
    }

settings = Settings()