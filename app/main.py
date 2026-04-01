from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from app.api.router import api_router
from app.db.mongo import mongo
from app.core.config import settings

# -----------------------------
# App Initialization
# -----------------------------
app = FastAPI(
    title="HoneyVault API",
    description="Deception-Driven Encryption with Honey Encryption + Sinkhole Architecture",
    version="1.0.0"
)

# -----------------------------
# Middleware (CORS)
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Include API Routes
# -----------------------------
app.include_router(api_router, prefix="/api")

# -----------------------------
# Startup Event
# -----------------------------
@app.on_event("startup")
async def startup_event():
    print("Starting HoneyVault System...")
    try:
        await mongo.connect()
        print("MongoDB connected successfully")
        # Note: indexes are created lazily on first insert; skipping explicit creation
    except Exception as e:
        print(f"Warning: MongoDB connection issue: {e}")
        print("(Ensure MongoDB is running at " + settings.MONGO_URI + ")")

# -----------------------------
# Shutdown Event
# -----------------------------
@app.on_event("shutdown")
async def shutdown_event():
    print("Shutting down HoneyVault System...")
    try:
        await mongo.close()
    except Exception as e:
        print(f"Warning during shutdown: {e}")

# -----------------------------
# Root Endpoint
# -----------------------------
@app.get("/")
async def root():
    db = mongo.get_database()

    vault_count = await db["vaults"].count_documents({})
    log_count = await db["logs"].count_documents({})

    return {
        "service": "HoneyVault",
        "status": "running",
        "database": "connected",
        "collections": {
            "vaults": vault_count,
            "logs": log_count
        },
        "features": {
            "honey_encryption": True,
            "sinkhole": True,
            "logging": True
        }
    }

# -----------------------------
# Health Check (Important)
# -----------------------------
@app.get("/health")
def health_check():
    # In a real-world scenario, this might also check db connectivity
    return {
        "status": "healthy"
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