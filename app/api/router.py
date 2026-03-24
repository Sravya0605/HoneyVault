from fastapi import APIRouter 
from app.api import encrypt, decrypt, sinkhole 

api_router = APIRouter() 

api_router.include_router(encrypt.router, tags=["Encryption"]) 
api_router.include_router(decrypt.router, tags=["Decryption"]) 
api_router.include_router(sinkhole.router, tags=["Sinkhole"]) 