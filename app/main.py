from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
from app.api.router import api_router
from app.db.mongo import mongo
from app.core.config import settings

# ============================================================
# LIFESPAN CONTEXT MANAGER (FastAPI 0.93+)
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan: startup and shutdown logic.
    
    Replaces deprecated @app.on_event("startup") and @app.on_event("shutdown").
    """
    # Startup
    print("=" * 60)
    print("  HoneyVault v5.0 Starting...")
    print("=" * 60)
    try:
        await mongo.connect()
        print(" MongoDB connected")
        db = mongo.get_database()
        print(f"Database: {db.name}")
    except Exception as e:
        print(f" MongoDB connection warning: {e}")
    print("=" * 60)
    
    yield  # Application runs here
    
    # Shutdown
    print(" HoneyVault shutting down...")
    try:
        await mongo.close()
    except Exception as e:
        print(f" Shutdown warning: {e}")

# ============================================================
# APP INITIALIZATION
# ============================================================
app = FastAPI(
    title="HoneyVault",
    lifespan=lifespan  # Use new lifespan context manager
)

# ============================================================
# MIDDLEWARE
# ============================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# ROUTES
# ============================================================
app.include_router(api_router, prefix="/api")

# ============================================================
# STARTUP & SHUTDOWN
# ============================================================
# Now handled by lifespan context manager above

# ============================================================
# SYSTEM ENDPOINTS
# ============================================================
@app.get("/")
async def root():
    """Root endpoint with system status."""
    db = mongo.get_database()
    vault_count = await db["vaults"].count_documents({})
    log_count = await db["logs"].count_documents({})
    # Use await for async MongoDB driver (no blocking sync calls in async context)
    cred_count = await db["real_credentials"].count_documents({})
    
    return {
        "service": "HoneyVault v5.0",
        "status": "Running",
        "encryption": "Real Honey Encryption with True DTE",
        "database": {
            "vaults": vault_count,
            "logs": log_count,
            "real_credentials": cred_count
        },
        "features": {
            "honey_encryption": True,
            "dte": "bijective_true",
            "sinkhole": True,
            "logging": True,
            "adaptive_learning": True,
            "research_metrics": True
        }
    }

@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

@app.get("/docs/api")
async def api_documentation():
    """Quick reference for all endpoints."""
    return {
        "encryption": {
            "POST /api/encrypt": "Create vault with real credential",
            "POST /api/decrypt": "Decrypt vault with any password (HE property)"
        },
        "sinkhole": {
            "GET /api/cloud/instances": "Sinkhole endpoint (checks registry)",
            "GET /api/storage/buckets": "Sinkhole endpoint"
        }
    }

# -----------------------------
# Run Server (for local dev)
# -----------------------------
if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )