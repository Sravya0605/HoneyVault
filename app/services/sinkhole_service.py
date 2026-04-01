from app.services.logging_service import LoggingService
from app.db.mongo import mongo
from app.utils.security_utils import is_valid_api_key_format
from app.core.config import settings
import hashlib
import random


class SinkholeService:
    def __init__(self):
        self.logger = LoggingService()

    def _vaults(self):
        return mongo.get_database()["vaults"]

    def _session_id(self, api_key: str):
        return hashlib.sha256(api_key.encode()).hexdigest()[:12]

    async def _is_real(self, api_key: str):
        hashed = hashlib.sha256(api_key.encode()).hexdigest() 
        return await self._vaults().find_one({"real_api_key": hashed})

    def _fake_response(self, endpoint):
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": f"i-{random.randint(10**15, 10**16-1)}",
                            "InstanceType": random.choice(["t2.micro", "t3.small"]),
                            "State": {"Name": random.choice(["running", "stopped"])},
                            "Region": "us-east-1",
                        }
                    ]
                }
            ],
            "ResponseMetadata": {
                "RequestId": str(random.randint(10**10, 10**11-1)),
                "HTTPStatusCode": 200
            },
            "source": "sinkhole"
        }

    def _real_response(self, endpoint):
        return {
            "status": "success",
            "endpoint": endpoint,
            "source": "real"
        }

    async def handle_request(self, api_key: str, endpoint: str, method: str):
        session = self._session_id(api_key)

        if not is_valid_api_key_format(api_key):
            return {"error": "Invalid key"}

        real = await self._is_real(api_key)

        if real:
            is_fake = False
            response = self._real_response(endpoint)
        else:
            is_fake = True
            response = self._fake_response(endpoint)

        await self.logger.log_access(
            api_key=api_key,
            endpoint=endpoint,
            method=method,
            is_fake=is_fake,
            session_id=session,
            response_kind="fake" if is_fake else "real",
        )

        return response