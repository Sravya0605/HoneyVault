from app.services.logging_service import LoggingService
from app.db.mongo import mongo
from app.utils.security_utils import is_valid_api_key_format
import hashlib

class SinkholeService:
    def __init__(self):
        self.logger = LoggingService()

    def _vaults(self):
        return mongo.get_database()["vaults"]

    async def _is_honey_token(self, api_key: str) -> bool:
        """
        Check if the key exists in the 'fake_keys' list of any vault.
        """
        result = await self._vaults().find_one({"fake_keys": api_key})
        return result is not None

    def _session_id_for_key(self, api_key: str) -> str:
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        return f"sess-{digest[:12]}"

    def _decoy_response(self, endpoint: str, method: str) -> dict:
        if endpoint == "/cloud/instances" and method == "GET":
            return {
                "instances": [
                    {"id": "i-123456", "status": "running", "tags": {"Name": "Prod-Web-Server"}},
                    {"id": "i-789012", "status": "stopped", "tags": {"Name": "Backup-DB"}},
                ],
                "source": "sinkhole",
            }

        if endpoint == "/storage/buckets" and method == "GET":
            return {
                "buckets": [
                    {"name": "financial-records-2025", "region": "us-east-1"},
                    {"name": "customer-ssh-keys-backup", "region": "us-east-1"},
                ],
                "source": "sinkhole",
            }

        if endpoint == "/cloud/start-instance" and method == "POST":
            return {
                "status": "success",
                "message": "Instance start scheduled",
                "operation_id": "op-sink-001",
                "source": "sinkhole",
            }

        return {"status": "success", "message": "Operation allowed", "source": "sinkhole"}

    def _real_response(self, endpoint: str, method: str) -> dict:
        # In research mode we avoid touching real cloud and return a neutral success.
        return {
            "status": "accepted",
            "message": "Key treated as non-honey token",
            "endpoint": endpoint,
            "method": method,
            "source": "real-path-simulated",
        }

    async def handle_request(self, api_key: str, endpoint: str, method: str) -> dict:
        session_id = self._session_id_for_key(api_key)
        is_fake = await self._is_honey_token(api_key)
        is_valid_format = is_valid_api_key_format(api_key)

        if not is_valid_format:
            await self.logger.log_access(
                api_key=api_key,
                endpoint=endpoint,
                method=method,
                is_fake=False,
                response_status="rejected",
                response_code=401,
                response_kind="rejected",
                session_id=session_id,
                event_type="invalid_key_attempt",
            )
            return {
                "status": "error",
                "message": "Invalid API key format",
                "code": 401,
            }

        response_kind = "decoy" if is_fake else "real"
        response = self._decoy_response(endpoint, method) if is_fake else self._real_response(endpoint, method)

        await self.logger.log_access(
            api_key=api_key,
            endpoint=endpoint,
            method=method,
            is_fake=is_fake,
            response_status="success",
            response_code=200,
            response_kind=response_kind,
            session_id=session_id,
            event_type="sinkhole_interaction" if is_fake else "real_interaction",
        )
        return response