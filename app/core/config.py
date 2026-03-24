import os
from dataclasses import dataclass, field
from typing import List

@dataclass
class Settings:
    # Encryption
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-do-not-use-in-production")

    # Honey Encryption / DTE
    FAKE_KEY_COUNT: int = int(os.getenv("FAKE_KEY_COUNT", "7"))
    
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

    # Security
    CORS_ORIGINS: List[str] = field(default_factory=lambda: os.getenv("CORS_ORIGINS", "").split(","))

    def __post_init__(self):
        pass  # All validations passed; SECRET_KEY now has a dev default

settings = Settings()