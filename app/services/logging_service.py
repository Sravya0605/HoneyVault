from app.models.logs import AccessLog
from app.db.mongo import mongo
from datetime import datetime, timezone
import hashlib
from app.utils.security_utils import mask_key


class LoggingService:
    def _collection(self):
        return mongo.get_database()["logs"]

    async def _latest_chain_hash(self) -> str:
        latest = await self._collection().find_one(sort=[("timestamp", -1), ("_id", -1)])
        if not latest:
            return "GENESIS"
        return latest.get("chain_hash", "GENESIS")

    def _compute_chain_hash(
        self,
        *,
        prev_chain_hash: str,
        api_key_hash: str,
        endpoint: str,
        method: str,
        is_fake: bool,
        response_status: str,
        response_code: int,
        response_kind: str,
        session_id: str | None,
        event_type: str,
        source_ip: str | None,
        user_agent: str | None,
        timestamp_iso: str,
    ) -> str:
        canonical = "|".join(
            [
                prev_chain_hash,
                api_key_hash,
                endpoint,
                method,
                str(is_fake),
                response_status,
                str(response_code),
                response_kind,
                session_id or "",
                event_type,
                source_ip or "",
                user_agent or "",
                timestamp_iso,
            ]
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

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
        source_ip: str | None = None,
        user_agent: str | None = None,
    ):
        prev_chain_hash = await self._latest_chain_hash()
        timestamp = datetime.now(timezone.utc)
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        chain_hash = self._compute_chain_hash(
            prev_chain_hash=prev_chain_hash,
            api_key_hash=api_key_hash,
            endpoint=endpoint,
            method=method,
            is_fake=is_fake,
            response_status=response_status,
            response_code=response_code,
            response_kind=response_kind,
            session_id=session_id,
            event_type=event_type,
            source_ip=source_ip,
            user_agent=user_agent,
            timestamp_iso=timestamp.isoformat(),
        )

        log = AccessLog(
            api_key=None,
            api_key_masked=mask_key(api_key),
            api_key_hash=api_key_hash,
            prev_chain_hash=prev_chain_hash,
            chain_hash=chain_hash,
            endpoint=endpoint,
            method=method,
            is_fake=is_fake,
            response_status=response_status,
            response_code=response_code,
            response_kind=response_kind,
            session_id=session_id,
            event_type=event_type,
            source_ip=source_ip,
            user_agent=user_agent,
            timestamp=timestamp,
        )

        # Exclude None _id so MongoDB can auto-generate unique ObjectIds.
        payload = log.model_dump(by_alias=True, exclude={"id"})
        await self._collection().insert_one(payload)

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

    async def compute_session_behavior_scores(self, limit: int = 20000) -> list[dict]:
        logs = await self.get_logs(limit=limit)
        grouped: dict[str, list[dict]] = {}

        for log in logs:
            session_id = log.get("session_id")
            if not session_id:
                continue
            grouped.setdefault(session_id, []).append(log)

        summaries: list[dict] = []
        for session_id, entries in grouped.items():
            request_count = len(entries)
            unique_endpoints = {entry.get("endpoint") for entry in entries if entry.get("endpoint")}
            unique_methods = {entry.get("method") for entry in entries if entry.get("method")}
            decoy_hits = sum(1 for entry in entries if entry.get("response_kind") == "decoy")
            invalid_attempts = sum(1 for entry in entries if entry.get("event_type") == "invalid_key_attempt")
            action_attempts = sum(
                1
                for entry in entries
                if entry.get("method") == "POST" and entry.get("endpoint") == "/cloud/start-instance"
            )

            score = 0
            score += min(40, decoy_hits * 8)
            score += min(20, len(unique_endpoints) * 8)
            score += min(20, action_attempts * 10)
            score += min(10, max(0, request_count - 2) * 2)
            score += min(10, invalid_attempts * 2)

            risk_level = "high" if score >= 70 else "medium" if score >= 40 else "low"
            latest = max(entries, key=lambda entry: entry.get("timestamp"))

            summaries.append(
                {
                    "session_id": session_id,
                    "score": score,
                    "risk_level": risk_level,
                    "request_count": request_count,
                    "decoy_hits": decoy_hits,
                    "invalid_attempts": invalid_attempts,
                    "action_attempts": action_attempts,
                    "endpoint_diversity": len(unique_endpoints),
                    "method_diversity": len(unique_methods),
                    "latest_source_ip": latest.get("source_ip"),
                    "last_seen": latest.get("timestamp").isoformat() if latest.get("timestamp") else None,
                }
            )

        summaries.sort(key=lambda item: item["score"], reverse=True)
        return summaries

    async def verify_log_chain_integrity(self, limit: int = 50000) -> dict:
        cursor = self._collection().find().sort("timestamp", 1)
        logs = await cursor.to_list(length=limit)

        if not logs:
            return {
                "status": "ok",
                "total_logs": 0,
                "validated_logs": 0,
                "broken_links": 0,
            }

        expected_prev = "GENESIS"
        broken_links = 0
        first_broken_id = None
        validated_logs = 0
        legacy_logs = 0

        for log in logs:
            if "chain_hash" not in log or "prev_chain_hash" not in log:
                legacy_logs += 1
                expected_prev = "GENESIS"
                continue

            timestamp_val = log.get("timestamp")
            timestamp_iso = timestamp_val.isoformat() if timestamp_val else ""

            computed = self._compute_chain_hash(
                prev_chain_hash=log.get("prev_chain_hash", ""),
                api_key_hash=log.get("api_key_hash", ""),
                endpoint=log.get("endpoint", ""),
                method=log.get("method", ""),
                is_fake=bool(log.get("is_fake", False)),
                response_status=log.get("response_status", ""),
                response_code=int(log.get("response_code", 0)),
                response_kind=log.get("response_kind", ""),
                session_id=log.get("session_id"),
                event_type=log.get("event_type", ""),
                source_ip=log.get("source_ip"),
                user_agent=log.get("user_agent"),
                timestamp_iso=timestamp_iso,
            )

            if log.get("prev_chain_hash") != expected_prev or log.get("chain_hash") != computed:
                broken_links += 1
                if first_broken_id is None:
                    first_broken_id = str(log.get("_id"))

            expected_prev = log.get("chain_hash", expected_prev)
            validated_logs += 1

        return {
            "status": "ok" if broken_links == 0 else "corrupt",
            "total_logs": len(logs),
            "validated_logs": validated_logs,
            "legacy_logs": legacy_logs,
            "broken_links": broken_links,
            "first_broken_log_id": first_broken_id,
        }