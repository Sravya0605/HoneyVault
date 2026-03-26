from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from app.services.logging_service import LoggingService
from app.core.auth import require_admin_token, require_service_or_admin_token
from app.services.observability_service import observability
from app.core.config import settings

router = APIRouter()
logger = LoggingService()


@router.get("/metrics/summary", dependencies=[Depends(require_admin_token)])
async def metrics_summary():
    logs = await logger.get_logs(limit=10000)
    session_scores = await logger.compute_session_behavior_scores(limit=10000)

    unique_sessions = len({log.get("session_id") for log in logs if log.get("session_id")})
    unique_ips = len({log.get("source_ip") for log in logs if log.get("source_ip")})

    decoy_hits = sum(1 for log in logs if log.get("response_kind") == "decoy")
    total_hits = len(logs)
    decoy_engagement_ratio = (decoy_hits / total_hits) if total_hits else 0.0
    runtime = observability.snapshot()

    return {
        "indistinguishability": await logger.compute_indistinguishability_proxy(),
        "detection_latency_seconds": await logger.compute_detection_latency_seconds(),
        "average_dwell_time_seconds": await logger.compute_average_dwell_time_seconds(),
        "unique_sessions": unique_sessions,
        "unique_source_ips": unique_ips,
        "decoy_engagement_ratio": round(decoy_engagement_ratio, 4),
        "total_events": total_hits,
        "top_session_risks": session_scores[:5],
        "slo": {
            "availability_target": settings.SLO_AVAILABILITY_TARGET,
            "availability_observed": round(runtime.availability, 6),
            "error_budget_remaining_ratio": round(runtime.error_budget_remaining_ratio, 6),
            "avg_latency_ms": round(runtime.avg_latency_ms, 3),
            "uptime_seconds": round(runtime.uptime_seconds, 2),
            "server_errors": runtime.server_errors,
            "client_errors": runtime.client_errors,
            "request_count": runtime.total_requests,
            "status_buckets": observability.status_buckets(),
        },
    }


@router.get("/metrics/integrity", dependencies=[Depends(require_admin_token)])
async def metrics_integrity():
    return await logger.verify_log_chain_integrity()


@router.get(
    "/metrics/prometheus",
    dependencies=[Depends(require_service_or_admin_token)],
    response_class=PlainTextResponse,
)
async def metrics_prometheus():
    summary = await metrics_summary()
    integrity = await logger.verify_log_chain_integrity()
    slo = summary["slo"]

    ind = summary["indistinguishability"]
    lines = [
        "# HELP honeyvault_total_events Total observed HoneyVault events",
        "# TYPE honeyvault_total_events gauge",
        f"honeyvault_total_events {summary['total_events']}",
        "# HELP honeyvault_decoy_engagement_ratio Ratio of decoy responses",
        "# TYPE honeyvault_decoy_engagement_ratio gauge",
        f"honeyvault_decoy_engagement_ratio {summary['decoy_engagement_ratio']}",
        "# HELP honeyvault_indistinguishability_score Balance-based indistinguishability proxy",
        "# TYPE honeyvault_indistinguishability_score gauge",
        f"honeyvault_indistinguishability_score {ind['score']}",
        "# HELP honeyvault_detection_latency_seconds Time to first fake-key detection",
        "# TYPE honeyvault_detection_latency_seconds gauge",
        f"honeyvault_detection_latency_seconds {summary['detection_latency_seconds'] or 0}",
        "# HELP honeyvault_log_chain_broken_links Number of broken links in tamper-evident log chain",
        "# TYPE honeyvault_log_chain_broken_links gauge",
        f"honeyvault_log_chain_broken_links {integrity['broken_links']}",
        "# HELP honeyvault_slo_availability_target Configured availability SLO target",
        "# TYPE honeyvault_slo_availability_target gauge",
        f"honeyvault_slo_availability_target {slo['availability_target']}",
        "# HELP honeyvault_slo_availability_observed Observed runtime availability",
        "# TYPE honeyvault_slo_availability_observed gauge",
        f"honeyvault_slo_availability_observed {slo['availability_observed']}",
        "# HELP honeyvault_slo_error_budget_remaining_ratio Remaining error budget ratio",
        "# TYPE honeyvault_slo_error_budget_remaining_ratio gauge",
        f"honeyvault_slo_error_budget_remaining_ratio {slo['error_budget_remaining_ratio']}",
        "# HELP honeyvault_request_latency_avg_ms Average request latency in milliseconds",
        "# TYPE honeyvault_request_latency_avg_ms gauge",
        f"honeyvault_request_latency_avg_ms {slo['avg_latency_ms']}",
    ]

    return "\n".join(lines) + "\n"


@router.get("/metrics/slo", dependencies=[Depends(require_admin_token)])
async def metrics_slo():
    summary = await metrics_summary()
    return summary["slo"]
