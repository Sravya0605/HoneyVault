from app.services.logging_service import LoggingService
from app.services.vault_service import CredentialRegistry
from app.utils.security_utils import is_valid_api_key_format
from app.core.config import settings
import hashlib
import secrets
import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import numpy as np
import inspect


class SinkholeService:
    def __init__(self):
        self.logger = LoggingService()
        self.registry = CredentialRegistry()

    def _session_id(self, api_key: str) -> str:
        """Generate deterministic session ID from key."""
        return hashlib.sha256(api_key.encode()).hexdigest()[:12]

    def _fake_response(self, endpoint: str) -> dict:
        """Generate realistic fake AWS EC2 response."""
        # Real AWS EC2 instance IDs: i- followed by 8 or 17 hex digits
        # Use 17 hex chars for modern format
        instance_id = "i-" + "".join(secrets.choice("0123456789abcdef") for _ in range(17))
        
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": instance_id,
                            "InstanceType": secrets.choice(["t2.micro", "t3.small", "t2.small"]),
                            "State": {"Name": secrets.choice(["running", "stopped"])},
                            "Region": "us-east-1",
                        }
                    ]
                }
            ],
            "ResponseMetadata": {
                "RequestId": "".join(secrets.choice("0123456789abcdef") for _ in range(16)),
                "HTTPStatusCode": 200
            }
            # REMOVED: "source": "sinkhole" - do not announce honeypot
        }

    def _real_response(self, endpoint: str) -> dict:
        """Generate real backend response."""
        return {
            "status": "success",
            "endpoint": endpoint,
            "timestamp": int(time.time())
        }

    async def handle_request(self, api_key: str, endpoint: str, method: str) -> dict:
        """
        Route API request to real backend or sinkhole.
        
        Check: is this api_key in the real credential registry?
        Real → backend
        Fake → sinkhole
        """
        session = self._session_id(api_key)

        # Validate format
        if not is_valid_api_key_format(api_key):
            return {
                "error": "Invalid key format"
                # REMOVED: "source": "sinkhole" - do not announce honeypot
            }

        # Check credential registry
        is_real = await self.registry.is_real(api_key)

        if is_real:
            response = self._real_response(endpoint)
            response_kind = "real"
        else:
            response = self._fake_response(endpoint)
            response_kind = "fake"

        # Log this access
        await self.logger.log_access(
            api_key=api_key,
            endpoint=endpoint,
            method=method,
            is_fake=(not is_real),
            session_id=session,
            response_kind=response_kind,
        )

        return response

    async def compute_cross_session_correlations(self, limit_seconds: int = 3600) -> Dict:
        """
        Detect patterns across multiple attack sessions (PRIORITY 3).
        
        Analyzes logs to identify:
        1. Multi-IP attacks (same credentials accessed from different IPs)
        2. Time-spread attacks (credentials accessed with suspicious spacing)
        3. Credential reuse patterns (fake credentials accessed in coordinated manner)
        4. Attack progression patterns (reconnaissance → enumeration → exploitation)
        
        Args:
            limit_seconds: Look back window for correlation analysis (default: 1 hour)
        
        Returns:
            {
                "total_sessions": int,
                "fake_credential_count": int,
                "unique_sessions": int,
                "correlations_detected": List[Dict],
                "attack_patterns": List[Dict],
                "temporal_analysis": Dict,
                "risk_score": float (0-1),
            }
        """
        logs_result = self.logger.get_logs(limit=1000)
        if inspect.isawaitable(logs_result):
            logs = await logs_result
        else:
            logs = logs_result
        
        # Filter to recent fake credential accesses
        cutoff_time = time.time() - limit_seconds
        fake_accesses = [
            log for log in logs
            if log.get("is_fake", False) and log.get("timestamp", 0) > cutoff_time
        ]
        
        if not fake_accesses:
            return {
                "total_sessions": 0,
                "fake_credential_count": 0,
                "correlations_detected": [],
                "risk_score": 0.0,
                "message": "No fake credentials accessed in timeframe"
            }
        
        # Group by session
        sessions_by_id = defaultdict(list)
        credentials_by_session = defaultdict(set)
        
        for log in fake_accesses:
            session_id = log.get("session_id", "unknown")
            sessions_by_id[session_id].append(log)
            credentials_by_session[session_id].add(log.get("api_key", "unknown"))
        
        correlations = self._analyze_session_correlations(
            sessions_by_id,
            credentials_by_session
        )
        
        attack_patterns = self._detect_attack_patterns(fake_accesses)
        temporal_analysis = self._analyze_temporal_distribution(fake_accesses)
        
        risk_score = self._compute_distributed_attack_risk(
            len(sessions_by_id),
            len(fake_accesses),
            len(correlations),
            temporal_analysis
        )
        
        return {
            "total_sessions": len(sessions_by_id),
            "fake_credential_count": len(fake_accesses),
            "unique_fake_credentials": sum(len(creds) for creds in credentials_by_session.values()),
            "correlations_detected": correlations,
            "attack_patterns": attack_patterns,
            "temporal_analysis": temporal_analysis,
            "risk_score": risk_score,
            "detection_window_seconds": limit_seconds,
        }

    def _analyze_session_correlations(self,
                                     sessions_by_id: Dict[str, List],
                                     credentials_by_session: Dict[str, set]) -> List[Dict]:
        """
        Detect correlations between sessions (multi-IP attacks).
        
        Returns list of correlation findings.
        """
        correlations = []
        
        # Look for credential reuse across sessions
        credential_to_sessions = defaultdict(list)
        for session_id, creds in credentials_by_session.items():
            for cred in creds:
                credential_to_sessions[cred].append(session_id)
        
        # Credentials accessed in multiple sessions = coordinated attack indicator
        multi_session_creds = {
            cred: sessions for cred, sessions in credential_to_sessions.items()
            if len(sessions) > 1
        }
        
        if multi_session_creds:
            correlations.append({
                "type": "credential_reuse",
                "severity": "high",
                "credential_count": len(multi_session_creds),
                "session_count": len(set(s for sessions in multi_session_creds.values() for s in sessions)),
                "details": f"{len(multi_session_creds)} credentials accessed across multiple sessions",
                "recommendation": "Investigate coordinated attack involving multiple IP addresses or actors"
            })
        
        # Look for session clustering (sessions close in time)
        session_times = []
        for session_id, logs in sessions_by_id.items():
            if logs:
                min_time = min(log.get("timestamp", 0) for log in logs)
                session_times.append((session_id, min_time))
        
        session_times.sort(key=lambda x: x[1])
        
        # Find sessions within 60 seconds (suspicious clustering)
        for i in range(len(session_times) - 1):
            if session_times[i+1][1] - session_times[i][1] < 60:
                correlations.append({
                    "type": "temporal_clustering",
                    "severity": "medium",
                    "session_1": session_times[i][0],
                    "session_2": session_times[i+1][0],
                    "time_delta_seconds": session_times[i+1][1] - session_times[i][1],
                    "details": "Multiple attack sessions detected within 60 seconds",
                    "recommendation": "Likely coordinated multi-threaded attack"
                })
        
        return correlations

    def _detect_attack_patterns(self, fake_accesses: List) -> List[Dict]:
        """
        Detect attack progression patterns (reconnaissance → enumeration → exploitation).
        
        Returns list of detected attack patterns.
        """
        patterns = []
        
        if not fake_accesses:
            return patterns
        
        # Analyze access rate over time
        timestamps = sorted([log.get("timestamp", time.time()) for log in fake_accesses])
        
        if len(timestamps) < 5:
            return patterns
        
        # Split into time windows
        time_deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_delta = np.mean(time_deltas)
        std_delta = np.std(time_deltas)
        
        # Detection: accelerating access rate (time_delta decreasing) = attack escalation
        early_deltas = time_deltas[:len(time_deltas)//2]
        late_deltas = time_deltas[len(time_deltas)//2:]
        
        if early_deltas and late_deltas:
            early_avg = np.mean(early_deltas)
            late_avg = np.mean(late_deltas)
            
            if late_avg < early_avg * 0.7:  # >30% acceleration
                patterns.append({
                    "type": "escalating_attack",
                    "severity": "high",
                    "early_avg_interval": float(early_avg),
                    "late_avg_interval": float(late_avg),
                    "acceleration_factor": float(early_avg / late_avg) if late_avg > 0 else float('inf'),
                    "details": "Access rate increasing over time (attack escalation)",
                    "recommendation": "Immediate blocking of suspicious IPs/credentials recommended"
                })
        
        # Analyze endpoints accessed
        endpoints = defaultdict(int)
        for log in fake_accesses:
            endpoints[log.get("endpoint", "unknown")] += 1
        
        if len(endpoints) > 5:
            patterns.append({
                "type": "service_reconnaissance",
                "severity": "medium",
                "unique_endpoints": len(endpoints),
                "top_endpoints": list(sorted(endpoints.items(), key=lambda x: x[1], reverse=True)[:5]),
                "details": "Multiple different AWS services being probed",
                "recommendation": "Indicates reconnaissance phase - prepare for lateral movement"
            })
        
        return patterns

    def _analyze_temporal_distribution(self, fake_accesses: List) -> Dict:
        """
        Analyze temporal characteristics of fake credential access.
        
        Returns temporal analysis metrics.
        """
        if not fake_accesses:
            return {"total_accesses": 0}
        
        timestamps = [log.get("timestamp", time.time()) for log in fake_accesses]
        
        return {
            "total_accesses": len(fake_accesses),
            "first_access": min(timestamps),
            "last_access": max(timestamps),
            "duration_seconds": max(timestamps) - min(timestamps),
            "accesses_per_minute": len(fake_accesses) / max((max(timestamps) - min(timestamps)) / 60, 1),
            "burst_detected": self._detect_burst_pattern(timestamps),
        }

    @staticmethod
    def _detect_burst_pattern(timestamps: List[float]) -> bool:
        """Detect if access pattern shows suspicious bursting."""
        if len(timestamps) < 10:
            return False
        
        deltas = sorted([timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)])
        median_delta = np.median(deltas)
        
        # Burst if most accesses are very close together (delta < 1 second)
        burst_accesses = sum(1 for d in deltas if d < 1.0)
        
        return burst_accesses > len(deltas) * 0.3  # >30% sub-second intervals

    @staticmethod
    def _compute_distributed_attack_risk(
        session_count: int,
        access_count: int,
        correlation_count: int,
        temporal_analysis: Dict
    ) -> float:
        """
        Compute risk score for distributed attack (0-1).
        
        Factors:
        - Multiple sessions (0-0.3)
        - High access rate (0-0.3)
        - Correlations detected (0-0.3)
        - Accesses per minute (0-0.1)
        """
        risk = 0.0
        
        # Factor 1: Multiple sessions
        if session_count > 1:
            risk += min(0.3, (session_count - 1) * 0.1)
        
        # Factor 2: High access count
        if access_count > 50:
            risk += min(0.3, (access_count - 50) / 150)
        
        # Factor 3: Correlations
        risk += min(0.3, correlation_count * 0.15)
        
        # Factor 4: Access rate
        rate = temporal_analysis.get("accesses_per_minute", 0)
        if rate > 10:
            risk += min(0.1, (rate - 10) / 40)
        
        return min(1.0, risk)