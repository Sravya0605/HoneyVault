from fastapi import APIRouter, Header, Request
from app.services.sinkhole_service import SinkholeService

router = APIRouter()
sinkhole_service = SinkholeService()

@router.get("/cloud/instances")
async def list_instances(request: Request, x_api_key: str = Header(...)):
    return await sinkhole_service.handle_request(
        api_key=x_api_key,
        endpoint="/cloud/instances",
        method="GET",
        source_ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "unknown"),
    )

@router.get("/storage/buckets")
async def list_buckets(request: Request, x_api_key: str = Header(...)):
    return await sinkhole_service.handle_request(
        api_key=x_api_key,
        endpoint="/storage/buckets",
        method="GET",
        source_ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "unknown"),
    )

@router.post("/cloud/start-instance")
async def start_instance(request: Request, x_api_key: str = Header(...)):
    return await sinkhole_service.handle_request(
        api_key=x_api_key, 
        endpoint="/cloud/start-instance", 
        method="POST",
        source_ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "unknown"),
    )