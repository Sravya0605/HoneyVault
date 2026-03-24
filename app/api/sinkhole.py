from fastapi import APIRouter, Header, HTTPException, Depends
from app.services.sinkhole_service import SinkholeService

router = APIRouter()
sinkhole_service = SinkholeService()

@router.get("/cloud/instances")
async def list_instances(x_api_key: str = Header(...)):
    return await sinkhole_service.handle_request(
        api_key=x_api_key,
        endpoint="/cloud/instances",
        method="GET",
    )

@router.get("/storage/buckets")
async def list_buckets(x_api_key: str = Header(...)):
    return await sinkhole_service.handle_request(
        api_key=x_api_key,
        endpoint="/storage/buckets",
        method="GET",
    )

@router.post("/cloud/start-instance")
async def start_instance(x_api_key: str = Header(...)):
    return await sinkhole_service.handle_request(
        api_key=x_api_key, 
        endpoint="/cloud/start-instance", 
        method="POST"
    )