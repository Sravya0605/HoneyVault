from fastapi import FastAPI
from fastapi import HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uuid
from time import perf_counter
import uvicorn
from app.api.router import api_router
from app.db.mongo import mongo
from app.core.config import settings
from app.services.observability_service import observability

@asynccontextmanager
async def lifespan(_: FastAPI):
    print("Starting HoneyVault System...")
    try:
        await mongo.connect()
        print("MongoDB connected successfully")
    except Exception as e:
        print(f"Warning: MongoDB connection issue: {e}")
        print("(Ensure MongoDB is running at " + settings.MONGO_URI + ")")

    yield

    print("Shutting down HoneyVault System...")
    try:
        await mongo.close()
    except Exception as e:
        print(f"Warning during shutdown: {e}")


# -----------------------------
# App Initialization
# -----------------------------
app = FastAPI(
    title="HoneyVault API",
    description="Deception-Driven Encryption with Honey Encryption + Sinkhole Architecture",
    version="1.0.0",
    lifespan=lifespan,
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


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    start = perf_counter()
    response = await call_next(request)
    latency_ms = (perf_counter() - start) * 1000.0
    observability.record_request(response.status_code, latency_ms)

    response.headers["X-Request-ID"] = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response

# -----------------------------
# Include API Routes
# -----------------------------
app.include_router(api_router, prefix="/api")

# -----------------------------
# Root Endpoint
# -----------------------------
@app.get("/")
def root():
    return {
        "message": "HoneyVault API is running",
        "version": "1.0.0",
        "status": "active"
    }

# -----------------------------
# Health Check (Important)
# -----------------------------
@app.get("/health")
async def health_check():
    db_ok = await mongo.ping()
    return {
        "status": "healthy" if db_ok else "degraded",
        "checks": {
            "database": "up" if db_ok else "down",
        },
    }


@app.get("/ready")
async def readiness_check():
    db_ok = await mongo.ping()
    if not db_ok:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not-ready",
                "checks": {"database": "down"},
            },
        )
    return {
        "status": "ready",
        "checks": {
            "database": "up",
        },
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