from dataclasses import dataclass
from threading import Lock
from time import perf_counter
from app.core.config import settings


@dataclass
class ObservabilitySnapshot:
    total_requests: int
    server_errors: int
    client_errors: int
    uptime_seconds: float
    avg_latency_ms: float
    availability: float
    error_budget_remaining_ratio: float


class ObservabilityService:
    def __init__(self):
        self._lock = Lock()
        self._started = perf_counter()
        self._total_requests = 0
        self._server_errors = 0
        self._client_errors = 0
        self._total_latency_ms = 0.0
        self._status_buckets: dict[str, int] = {}

    def record_request(self, status_code: int, latency_ms: float) -> None:
        with self._lock:
            self._total_requests += 1
            self._total_latency_ms += latency_ms
            bucket = f"{status_code // 100}xx"
            self._status_buckets[bucket] = self._status_buckets.get(bucket, 0) + 1

            if 500 <= status_code <= 599:
                self._server_errors += 1
            elif 400 <= status_code <= 499:
                self._client_errors += 1

    def snapshot(self) -> ObservabilitySnapshot:
        with self._lock:
            total = self._total_requests
            server_errors = self._server_errors
            client_errors = self._client_errors
            avg_latency = (self._total_latency_ms / total) if total else 0.0

        uptime = perf_counter() - self._started
        availability = 1.0 - (server_errors / total) if total else 1.0

        allowed_error_rate = 1.0 - settings.SLO_AVAILABILITY_TARGET
        observed_error_rate = (server_errors / total) if total else 0.0
        if allowed_error_rate <= 0:
            budget_remaining = 0.0
        else:
            budget_remaining = max(0.0, 1.0 - (observed_error_rate / allowed_error_rate))

        return ObservabilitySnapshot(
            total_requests=total,
            server_errors=server_errors,
            client_errors=client_errors,
            uptime_seconds=uptime,
            avg_latency_ms=avg_latency,
            availability=availability,
            error_budget_remaining_ratio=budget_remaining,
        )

    def status_buckets(self) -> dict[str, int]:
        with self._lock:
            return dict(self._status_buckets)


observability = ObservabilityService()
