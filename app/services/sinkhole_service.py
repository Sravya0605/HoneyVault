from app.services.logging_service import LoggingService
from app.db.mongo import mongo
from app.utils.security_utils import is_valid_api_key_format
from app.utils.rate_limiter import InMemoryRateLimiter
from app.core.config import settings
import hashlib
import random
from fastapi import HTTPException

class SinkholeService:
    def __init__(self):
        self.logger = LoggingService()
        self.rate_limiter = InMemoryRateLimiter(
            max_requests=settings.SINKHOLE_RATE_LIMIT,
            window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
        )

    def _vaults(self):
        return mongo.get_database()["vaults"]

    def _logs(self):
        return mongo.get_database()["logs"]

    async def _is_honey_token(self, api_key: str) -> bool:
        """
        Check if the key exists in the 'fake_keys' list of any vault.
        """
        result = await self._vaults().find_one({"fake_keys": api_key})
        return result is not None

    def _session_id_for_key(self, api_key: str) -> str:
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        return f"sess-{digest[:12]}"

    def _rng_for_request(self, api_key: str, endpoint: str, method: str) -> random.Random:
        seed_material = f"{api_key}:{endpoint}:{method}"
        seed = int(hashlib.sha256(seed_material.encode()).hexdigest(), 16)
        return random.Random(seed)

    async def _session_lure_level(self, session_id: str) -> int:
        interactions = await self._logs().count_documents(
            {
                "session_id": session_id,
                "response_kind": "decoy",
                "event_type": "sinkhole_interaction",
            }
        )
        if interactions < 2:
            return 1
        if interactions < 5:
            return 2
        return 3

    async def _decoy_response(self, api_key: str, endpoint: str, method: str, lure_level: int) -> dict:
        rng = self._rng_for_request(api_key, endpoint, method)

        if endpoint == "/cloud/instances" and method == "GET":
            count = 1 if lure_level == 1 else 2 if lure_level == 2 else 3
            ids = [f"i-{rng.randint(100000, 999999)}" for _ in range(count)]
            names = [
                "Prod-Web-Server",
                "Analytics-Worker",
                "Payments-API",
                "Backup-DB",
                "Batch-Processor",
            ]
            instances = []
            for instance_id in ids:
                instances.append(
                    {
                        "id": instance_id,
                        "status": "running" if rng.random() > 0.35 else "stopped",
                        "tags": {"Name": rng.choice(names)},
                    }
                )
            return {
                "instances": instances,
                "lure_level": lure_level,
                "source": "sinkhole",
            }

        if endpoint == "/storage/buckets" and method == "GET":
            prefixes = ["financial-records", "customer-archive", "build-artifacts", "ssh-keys-backup"]
            years = ["2023", "2024", "2025", "2026"]
            regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
            count = 1 if lure_level == 1 else 2 if lure_level == 2 else 3
            buckets = []
            for _ in range(count):
                buckets.append(
                    {
                        "name": f"{rng.choice(prefixes)}-{rng.choice(years)}",
                        "region": rng.choice(regions),
                    }
                )
            return {
                "buckets": buckets,
                "lure_level": lure_level,
                "source": "sinkhole",
            }

        if endpoint == "/cloud/start-instance" and method == "POST":
            op_digest = hashlib.sha256(f"op:{api_key}".encode()).hexdigest()[:10]
            return {
                "status": "success",
                "message": "Instance start scheduled",
                "operation_id": f"op-sink-{op_digest}",
                "lure_level": lure_level,
                "estimated_wait_seconds": 5 if lure_level == 1 else 12 if lure_level == 2 else 20,
                "source": "sinkhole",
            }

        return {
            "status": "success",
            "message": "Operation allowed",
            "lure_level": lure_level,
            "source": "sinkhole",
        }

    def _real_response(self, endpoint: str, method: str) -> dict:
        # In research mode we avoid touching real cloud and return a neutral success.
        return {
            "status": "accepted",
            "message": "Key treated as non-honey token",
            "endpoint": endpoint,
            "method": method,
            "source": "real-path-simulated",
        }

    async def handle_request(
        self,
        api_key: str,
        endpoint: str,
        method: str,
        source_ip: str = "unknown",
        user_agent: str = "unknown",
    ) -> dict:
        session_id = self._session_id_for_key(api_key)
        rate_limit_key = f"{source_ip}:{endpoint}"
        if not self.rate_limiter.allow(rate_limit_key):
            await self.logger.log_access(
                api_key=api_key,
                endpoint=endpoint,
                method=method,
                is_fake=False,
                response_status="throttled",
                response_code=429,
                response_kind="throttled",
                session_id=session_id,
                event_type="rate_limited",
                source_ip=source_ip,
                user_agent=user_agent,
            )
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

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
                source_ip=source_ip,
                user_agent=user_agent,
            )
            raise HTTPException(status_code=401, detail="Invalid API key format")

        response_kind = "decoy" if is_fake else "real"
        lure_level = await self._session_lure_level(session_id) if is_fake else None
        response = (
            await self._decoy_response(api_key, endpoint, method, lure_level)
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
            response_kind=response_kind,
            session_id=session_id,
            event_type="sinkhole_interaction" if is_fake else "real_interaction",
            source_ip=source_ip,
            user_agent=user_agent,
        )
        return response