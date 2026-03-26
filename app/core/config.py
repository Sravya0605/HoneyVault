import os
from dataclasses import dataclass, field
from typing import List


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}

@dataclass
class Settings:
    APP_ENV: str = os.getenv("APP_ENV", "development")

    # Encryption
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-do-not-use-in-production")

    # Honey Encryption / DTE
    FAKE_KEY_COUNT: int = int(os.getenv("FAKE_KEY_COUNT", "50"))
    
    # API Key Format (AWS-like)
    KEY_PREFIX: str = "AKIA"
    KEY_LENGTH: int = 20

    # Password-to-key derivation (memory-hard)
    KDF_N: int = int(os.getenv("KDF_N", str(2**14)))
    KDF_R: int = int(os.getenv("KDF_R", "8"))
    KDF_P: int = int(os.getenv("KDF_P", "1"))
    KDF_DKLEN: int = int(os.getenv("KDF_DKLEN", "32"))
    
    # MongoDB
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    DB_NAME: str = "honeyvault"
    
    # System behavior
    ENABLE_LOGGING: bool = True
    ENABLE_DECEPTION_FOR_UNKNOWN_KEYS: bool = True
    MAX_LOG_FETCH: int = int(os.getenv("MAX_LOG_FETCH", "500"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    SINKHOLE_RATE_LIMIT: int = int(os.getenv("SINKHOLE_RATE_LIMIT", "120"))
    DECRYPT_RATE_LIMIT: int = int(os.getenv("DECRYPT_RATE_LIMIT", "30"))
    METRICS_AUTH_ENABLED: bool = _env_bool("METRICS_AUTH_ENABLED", True)
    ADMIN_API_TOKEN: str = os.getenv("ADMIN_API_TOKEN", "dev-admin-token")
    SERVICE_API_TOKEN: str = os.getenv("SERVICE_API_TOKEN", "dev-service-token")
    SLO_AVAILABILITY_TARGET: float = float(os.getenv("SLO_AVAILABILITY_TARGET", "0.995"))

    # Security
    CORS_ORIGINS: List[str] = field(default_factory=lambda: [
        origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()
    ])

    def __post_init__(self):
        if self.APP_ENV.lower() == "production" and self.SECRET_KEY == "dev-secret-key-do-not-use-in-production":
            raise ValueError("SECRET_KEY must be overridden in production")

        if self.APP_ENV.lower() == "production" and self.ADMIN_API_TOKEN == "dev-admin-token":
            raise ValueError("ADMIN_API_TOKEN must be overridden in production")

        if self.APP_ENV.lower() == "production" and self.SERVICE_API_TOKEN == "dev-service-token":
            raise ValueError("SERVICE_API_TOKEN must be overridden in production")

        if self.FAKE_KEY_COUNT < 10:
            raise ValueError("FAKE_KEY_COUNT must be at least 10 for meaningful deception diversity")

        if not (0.8 <= self.SLO_AVAILABILITY_TARGET < 1.0):
            raise ValueError("SLO_AVAILABILITY_TARGET must be between 0.8 and 1.0")

settings = Settings()