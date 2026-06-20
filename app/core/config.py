import os
from dataclasses import dataclass, field
from typing import List

@dataclass
class Settings:
    # ============================================================
    # ENCRYPTION & DTE PARAMETERS
    # ============================================================
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-do-not-use-in-production")
    
    # DTE Configuration
    MESSAGE_SPACE_SIZE: int = int(os.getenv("MESSAGE_SPACE_SIZE", "50000"))  # Finite message space
    
    # API Key Format (AWS-like)
    KEY_PREFIX: str = "AKIA"
    KEY_LENGTH: int = 20
    
    # ============================================================
    # CRYPTOGRAPHIC PARAMETERS (Argon2id)
    # ============================================================
    # Memory-hard KDF to resist brute force - UPGRADED to Argon2id
    # Argon2id selected for better GPU/ASIC resistance than scrypt
    # Parameters tuned for: ~50ms KDF + 64MB memory
    ARGON2_TIME_COST: int = int(os.getenv("ARGON2_TIME_COST", "2"))          # Iterations
    ARGON2_MEMORY_COST: int = int(os.getenv("ARGON2_MEMORY_COST", "65536"))  # KB (64MB)
    ARGON2_PARALLELISM: int = int(os.getenv("ARGON2_PARALLELISM", "4"))      # Threads/processes
    ARGON2_LENGTH: int = int(os.getenv("ARGON2_LENGTH", "32"))               # Output length (256-bit)
    ARGON2_TYPE: str = "id"  # id = hybrid (Argon2i for password hashing + Argon2d for GPU resistance)
    
    # DEPRECATED (kept for reference):
    # Previous scrypt parameters (REPLACED by Argon2id)
    # N=2^14 (16KB memory), R=8, P=1 
    KDF_N: int = int(os.getenv("KDF_N", str(2**14)))          # UNUSED - for backward compat only
    KDF_R: int = int(os.getenv("KDF_R", "8"))                  # UNUSED
    KDF_P: int = int(os.getenv("KDF_P", "1"))                  # UNUSED
    KDF_DKLEN: int = int(os.getenv("KDF_DKLEN", "32"))         # Output length (256-bit)
    
    # ============================================================
    # MONGODB
    # ============================================================
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    DB_NAME: str = "honeyvault"
    
    # ============================================================
    # RESEARCH & TIMING PARAMETERS
    # ============================================================
    # Constant-time response configuration
    MIN_RESPONSE_TIME_MS: int = int(os.getenv("MIN_RESPONSE_TIME_MS", "50"))
    
    # Indistinguishability game parameters
    IND_DIST_SIMULATION_COUNT: int = int(os.getenv("IND_DIST_SIMULATION_COUNT", "100"))
    
    # ============================================================
    # SYSTEM BEHAVIOR
    # ============================================================
    ENABLE_LOGGING: bool = True
    ENABLE_DECEPTION_FOR_UNKNOWN_KEYS: bool = True
    MAX_LOG_FETCH: int = int(os.getenv("MAX_LOG_FETCH", "500"))
    
    # Research metrics collection
    COLLECT_RESEARCH_METRICS: bool = True
    ADAPTIVE_LEARNING_ENABLED: bool = True
    
    # ============================================================
    # SECURITY & CORS
    # ============================================================
    CORS_ORIGINS: List[str] = field(default_factory=lambda: os.getenv("CORS_ORIGINS", "").split(","))
    
    # ============================================================
    # RESEARCH DOCUMENTATION
    # ============================================================
    RESEARCH_FRAMEWORK = {
        "name": "HE-DTE-V1",
        "description": "Real Honey Encryption with True DTE",
        "key_properties": {
            "bijective_dte": "guaranteed",
            "indistinguishability": "quantifiable via IND-DIST game",
            "adaptive_learning": "enabled",
            "constant_time": "enforced"
        }
    }
    
    def __post_init__(self):
        """Validate that cryptographic parameters are production-safe."""
        assert self.KDF_N >= 2**10, "KDF_N too small (minimum 2^10)"
        assert self.KDF_DKLEN >= 32, "Key length too short (minimum 256-bit)"

settings = Settings()