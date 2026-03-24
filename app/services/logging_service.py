from app.models.logs import AccessLog
from app.db.mongo import mongo
from datetime import datetime, timezone


class LoggingService:
    def _collection(self):
        return mongo.get_database()["logs"]

    async def log_access(
        self,
        api_key: str,
        endpoint: str,
        method: str,
        is_fake: bool,
        response_status: str = "success",
        response_code: int = 200,
        response_kind: str = "unknown",
        session_id: str | None = None,
        event_type: str = "api_access",
    ):
        log = AccessLog(
            api_key=api_key,
            endpoint=endpoint,
            method=method,
            is_fake=is_fake,
            response_status=response_status,
            response_code=response_code,
            response_kind=response_kind,
            session_id=session_id,
            event_type=event_type,
        )

        await self._collection().insert_one(log.model_dump(by_alias=True))

    async def get_logs(self, limit: int = 50):
        cursor = self._collection().find().sort("timestamp", -1).limit(limit)
        logs = await cursor.to_list(length=limit)

        for log in logs:
            log["_id"] = str(log["_id"])

        return logs

    async def compute_detection_latency_seconds(self) -> float | None:
        first_event = await self._collection().find_one(sort=[("timestamp", 1)])
        first_fake = await self._collection().find_one({"is_fake": True}, sort=[("timestamp", 1)])

        if not first_event or not first_fake:
            return None

        return (first_fake["timestamp"] - first_event["timestamp"]).total_seconds()

    async def compute_average_dwell_time_seconds(self) -> float | None:
        cursor = self._collection().find({"is_fake": True}).sort("timestamp", 1)
        fake_logs = await cursor.to_list(length=None)
        if len(fake_logs) < 2:
            return None

        start = fake_logs[0]["timestamp"]
        end = fake_logs[-1]["timestamp"]
        return (end - start).total_seconds()

    async def compute_indistinguishability_proxy(self) -> dict:
        total = await self._collection().count_documents({})
        if total == 0:
            return {
                "total_events": 0,
                "fake_ratio": 0.0,
                "real_ratio": 0.0,
                "score": 0.0,
            }

        fake_count = await self._collection().count_documents({"is_fake": True})
        real_count = total - fake_count

        # Proxy score: higher when fake/real traffic appears balanced.
        # Ideal indistinguishability proxy is near a 50/50 observable mix.
        fake_ratio = fake_count / total
        balance_penalty = abs(0.5 - fake_ratio) * 2
        score = max(0.0, 1.0 - balance_penalty)

        return {
            "total_events": total,
            "fake_ratio": round(fake_ratio, 4),
            "real_ratio": round(real_count / total, 4),
            "score": round(score, 4),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }