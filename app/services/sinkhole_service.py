from app.services.logging_service import LoggingService
from app.db.mongo import mongo
from app.utils.security_utils import is_valid_api_key_format
from app.core.config import settings
import hashlib


class SinkholeService:
    def __init__(self):
        self.logger = LoggingService()

    def _vaults(self):
        return mongo.get_database()["vaults"]

    def _session_id_for_key(self, api_key: str) -> str:
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        return f"sess-{digest[:12]}"

    async def _classify_key(self, api_key: str):
        """
        Returns: ("real" | "fake" | "unknown")
        """
        collection = self._vaults()

        # Check fake keys
        fake = await collection.find_one({"fake_keys": api_key})
        if fake:
            return "fake"

        # Check real keys
        real = await collection.find_one({"real_api_key": api_key})
        if real:
            return "real"

        return "unknown"

    def _decoy_response(self, endpoint: str, method: str) -> dict:
        if endpoint == "/cloud/instances" and method == "GET":
            return {
                "instances": [
                    {"id": "i-123456", "status": "running"},
                    {"id": "i-789012", "status": "stopped"},
                ],
                "source": "sinkhole",
            }

        if endpoint == "/storage/buckets":
            return {
                "buckets": [
                    {"name": "financial-records-2025"},
                    {"name": "customer-ssh-keys-backup"},
                ],
                "source": "sinkhole",
            }

        return {"status": "ok", "source": "sinkhole"}

    def _real_response(self, endpoint: str, method: str) -> dict:
        return {
            "status": "success",
            "message": "Valid API key",
            "endpoint": endpoint,
            "method": method,
            "source": "real",
        }

    async def handle_request(self, api_key: str, endpoint: str, method: str) -> dict:
        session_id = self._session_id_for_key(api_key)

        if not is_valid_api_key_format(api_key):
            await self.logger.log_access(
                api_key=api_key,
                endpoint=endpoint,
                method=method,
                is_fake=False,
                response_status="rejected",
                response_code=401,
                response_kind="invalid",
                session_id=session_id,
                event_type="invalid_key",
            )
            return {"error": "Invalid API key"}

        classification = await self._classify_key(api_key)

        if classification == "unknown" and settings.ENABLE_DECEPTION_FOR_UNKNOWN_KEYS:
            classification = "fake"

        is_fake = classification == "fake"

        response = (
            self._decoy_response(endpoint, method)
            if is_fake
            else self._real_response(endpoint, method)
        )

        await self.logger.log_access(
            api_key=api_key,
            endpoint=endpoint,
            method=method,
            is_fake=is_fake,
            response_status="success",
            response_code=200,
            response_kind=classification,
            session_id=session_id,
            event_type="sinkhole_interaction",
        )

        return response