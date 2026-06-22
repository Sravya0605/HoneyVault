"""
Threat Models for HoneyVault: Sinkhole-Aware Adversary Analysis

============================================================================
FORMAL FRAMEWORK
============================================================================

This module implements game-theoretic and empirical analysis of adversaries
who are aware of the HoneyVault sinkhole defense mechanism.

Threat Model Layers:
1. Game-Theoretic: Analyze attacker strategies and detection tradeoffs
2. Empirical: Simulate real-world detection via behavioral patterns and cloud anomalies
3. Practical: Quantify detection probability and time-to-detection

============================================================================
ADVERSARY ASSUMPTIONS
============================================================================

Adversary Knowledge:
- Ⓐ Knows HoneyVault exists (has seen deployment)
- Ⓑ Knows sinkhole decryption produces valid-format AWS keys
- © Knows sinkhole responses are NOT real AWS (may differ behaviorally)
- Ⓓ May or may not know DTE distribution parameters

Adversary Capabilities:
- Can query sinkhole to test credentials
- Can observe response characteristics (latency, format, fields)
- Can perform statistical/behavioral analysis
- Can correlate multi-stage attacks to detect patterns

============================================================================
DEFENSE MECHANISMS
============================================================================

1. Sinkhole Detection (Passive)
   - Behavioral fidelity: How similar is sinkhole response to real AWS?
   - Response time matching: Do timings match real AWS APIs?
   - Correlation detection: Are multiple fake credentials accessed together?

2. Cloud Anomaly Detection (Active)
   - GuardDuty simulation: Detect unusual access patterns
   - Rate limiting: Flag credential overuse
   - Geographic anomalies: Detect impossible-travel attacks
   - Service access patterns: Identify reconnaissance attempts

3. Temporal Analysis
   - Time-to-detection: How long before system detects attack?
   - Detection windows: Early warning, intermediate, late detection phases
   - Multi-stage attacks: Correlate across sessions

============================================================================
RESEARCH CONTRIBUTIONS
============================================================================

This implementation provides:
1. Formal adversary model with quantified capabilities
2. Parametric detection simulations for cloud behaviors
3. Empirical evaluation framework for sinkhole fidelity
4. Time-to-detection metrics for systems evaluation
5. Correlation analysis for distributed/multi-stage attacks
"""

import time
import numpy as np
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import hashlib


class AdversaryType(Enum):
    """Adversary sophistication levels."""
    NAIVE = "naive"  # Doesn't know about sinkhole
    AWARE = "aware"  # Knows sinkhole exists
    SOPHISTICATED = "sophisticated"  # Knows detection mechanisms


class DetectionMethod(Enum):
    """Cloud detection methods."""
    BEHAVIORAL_FIDELITY = "behavioral_fidelity"
    RATE_LIMITING = "rate_limiting"
    GEOGRAPHIC_ANOMALY = "geographic_anomaly"
    TEMPORAL_CLUSTERING = "temporal_clustering"
    GUARDDUTY_SIMULATION = "guardduty_simulation"
    CREDENTIAL_CORRELATION = "credential_correlation"


class AttackPhase(Enum):
    """Attack progression phases."""
    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_ENUMERATION = "credential_enumeration"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"


@dataclass
class SinkholeResponse:
    """Simulated sinkhole response from HoneyVault."""
    api_key: str
    response_time_ms: float
    status_code: int = 200
    response_body: Dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def __post_init__(self):
        """Generate realistic AWS response if not provided."""
        if not self.response_body:
            self.response_body = {
                "Reservations": [{
                    "Instances": [{
                        "InstanceId": f"i-{hashlib.sha256(self.api_key.encode()).hexdigest()[:16]}",
                        "InstanceType": "t2.micro",
                        "State": {"Name": "running"},
                    }]
                }],
                "ResponseMetadata": {"HTTPStatusCode": 200}
            }


@dataclass
class RealAWSResponse:
    """Real AWS response characteristics."""
    api_key: str
    response_time_ms: float
    status_code: int = 200
    response_body: Dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        """Generate realistic AWS response if not provided."""
        if not self.response_body:
            self.response_body = {
                "Reservations": [{
                    "Instances": [{
                        "InstanceId": f"i-{hashlib.sha256(self.api_key.encode()).hexdigest()[:16]}",
                        "InstanceType": "t2.micro",
                        "State": {"Name": "running"},
                    }]
                }],
                "ResponseMetadata": {"HTTPStatusCode": 200}
            }


@dataclass
class DetectionEvent:
    """Event triggering detection."""
    timestamp: float
    detection_method: DetectionMethod
    confidence: float  # 0-1
    severity: str  # "low", "medium", "high", "critical"
    session_id: str
    details: Dict = field(default_factory=dict)


@dataclass
class AttackSession:
    """Single adversary attack session."""
    session_id: str
    adversary_type: AdversaryType
    start_time: float = field(default_factory=time.time)
    credentials_tested: List[str] = field(default_factory=list)
    responses: List[SinkholeResponse] = field(default_factory=list)
    attack_phases: List[AttackPhase] = field(default_factory=list)
    detection_events: List[DetectionEvent] = field(default_factory=list)
    discovered_real_keys: List[str] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        """Total attack duration."""
        return time.time() - self.start_time
    
    @property
    def time_to_detection(self) -> Optional[float]:
        """Time from attack start to first detection."""
        if not self.detection_events:
            return None
        first_detection = min(e.timestamp for e in self.detection_events)
        return first_detection - self.start_time
    
    @property
    def detection_probability(self) -> float:
        """Aggregate detection confidence."""
        if not self.detection_events:
            return 0.0
        # Maximum confidence across all detection methods
        return max(e.confidence for e in self.detection_events)


class SinkholeDetector:
    """
    Simulates adversary attempts to detect the sinkhole mechanism.
    
    Strategies:
    1. Behavioral fidelity testing: Compare sinkhole vs real AWS responses
    2. Rate limiting analysis: Test if APIs enforce quotas
    3. Temporal consistency: Check for timing anomalies
    """
    
    def __init__(self, sinkhole_fidelity: float = 0.85):
        """
        Args:
            sinkhole_fidelity: 0-1, how closely sinkhole matches real AWS
                - 0.95+: Nearly indistinguishable
                - 0.85-0.95: Minor discrepancies
                - 0.70-0.85: Noticeable but plausible
                - <0.70: Easily detected
        """
        self.sinkhole_fidelity = sinkhole_fidelity
        self.real_aws_response_time_dist = (50, 15)  # mean, std in ms
        self.sinkhole_response_time_dist = (55, 10)  # slightly slower + consistent
    
    def test_behavioral_fidelity(self,
                                 sinkhole_response: SinkholeResponse,
                                 reference_responses: List[RealAWSResponse]) -> Tuple[float, Dict]:
        """
        Compare sinkhole response against known real AWS responses.
        
        Detection Signal:
        - Response time distribution: Real AWS has >2x higher variance
        - Response structure: Missing fields, different ordering
        - Error handling: Sinkhole may not handle edge cases
        
        Returns:
            (detection_confidence, analysis_details)
        """
        if not reference_responses:
            return 0.0, {"reason": "no_reference_responses"}
        
        # Compare response times
        sinkhole_time = sinkhole_response.response_time_ms
        real_times = np.array([r.response_time_ms for r in reference_responses])
        
        real_mean = np.mean(real_times)
        real_std = np.std(real_times)
        
        # Detection score: does sinkhole deviate from real AWS distribution?
        z_score = abs((sinkhole_time - real_mean) / (real_std + 1e-6))
        
        # Compare response structure
        structure_match_score = self._compare_response_structure(
            sinkhole_response.response_body,
            reference_responses[0].response_body
        )
        
        # Combine signals
        detection_confidence = min(1.0, (z_score / 3.0) * 0.5 + (1 - structure_match_score) * 0.5)
        
        # Sinkhole fidelity reduces detection confidence, but low fidelity still yields a stronger baseline signal.
        detection_confidence = detection_confidence * 0.75 + (1 - self.sinkhole_fidelity) * 0.25
        detection_confidence = min(1.0, detection_confidence)
        
        return detection_confidence, {
            "z_score": z_score,
            "structure_match": structure_match_score,
            "real_mean_ms": real_mean,
            "real_std_ms": real_std,
            "sinkhole_ms": sinkhole_time,
        }
    
    def _compare_response_structure(self, response1: Dict, response2: Dict) -> float:
        """Compare structure similarity (0-1)."""
        keys1 = set(response1.keys())
        keys2 = set(response2.keys())
        
        if not (keys1 | keys2):
            return 1.0
        
        intersection = len(keys1 & keys2)
        union = len(keys1 | keys2)
        
        return intersection / union if union > 0 else 0.0
    
    def test_rate_limiting(self, session: AttackSession) -> Tuple[float, Dict]:
        """
        Detect if sinkhole enforces AWS-like rate limits.
        
        Real AWS GuardDuty enforces:
        - Per-credential quotas: ~1000 calls/day
        - Throttling: 429 responses after threshold
        - Per-IP rate limits
        
        Sinkhole typically doesn't enforce these (or has higher limits).
        
        Returns:
            (detection_confidence, details)
        """
        if len(session.responses) < 10:
            return 0.0, {"reason": "insufficient_samples"}
        
        # Check for 429/throttle responses
        throttled = sum(1 for r in session.responses if r.status_code == 429)
        throttle_rate = throttled / len(session.responses)
        
        # Real AWS would enforce rate limits more consistently
        # Sinkhole may not, giving away its nature
        expected_throttle_rate = 0.1  # ~10% for sustained attack
        throttle_deviation = abs(throttle_rate - expected_throttle_rate)
        
        detection_confidence = min(1.0, throttle_deviation * 3.0)
        
        return detection_confidence, {
            "observed_throttle_rate": throttle_rate,
            "expected_throttle_rate": expected_throttle_rate,
            "total_requests": len(session.responses),
            "throttled_requests": throttled,
        }
    
    def test_temporal_consistency(self, session: AttackSession) -> Tuple[float, Dict]:
        """
        Detect if sinkhole shows suspicious temporal patterns.
        
        Indicators:
        - Too-consistent response times (sinkhole: constant-time defense)
        - Clustering of errors
        - Lack of real-world variability
        
        Returns:
            (detection_confidence, details)
        """
        if len(session.responses) < 5:
            return 0.0, {"reason": "insufficient_samples"}
        
        response_times = np.array([r.response_time_ms for r in session.responses])
        
        # Real AWS: high variance due to real backend load
        # Sinkhole: low variance (constant-time defense)
        real_cv = 0.35  # Coefficient of variation ~35%
        observed_cv = np.std(response_times) / np.mean(response_times)
        
        # If observed_cv << real_cv, it's suspicious
        cv_ratio = observed_cv / real_cv if real_cv > 0 else 0.0
        
        # Score: low CV is suspicious
        detection_confidence = max(0.0, 1.0 - (cv_ratio * 0.5))
        
        return detection_confidence, {
            "observed_cv": observed_cv,
            "expected_cv": real_cv,
            "response_time_mean_ms": float(np.mean(response_times)),
            "response_time_std_ms": float(np.std(response_times)),
        }


class CloudAnomalyDetector:
    """
    Simulates cloud provider detection mechanisms (e.g., AWS GuardDuty).
    
    Detection Signals:
    1. Credential reuse patterns (from logs)
    2. Behavioral anomalies (access patterns, IPs, timing)
    3. Impossible travel (geographic inconsistency)
    4. Rate anomalies (credential overuse)
    """
    
    def __init__(self):
        self.detection_latency_distribution = (300, 120)  # mean, std in seconds
        self.impossible_travel_threshold = 900  # km/hour
        self.rate_limit_threshold = 100  # API calls per minute
    
    def detect_credential_correlation(self,
                                     session: AttackSession) -> Tuple[float, Dict]:
        """
        Detect when multiple fake credentials are accessed together.
        
        Pattern: Attacker discovers 5+ credentials in short window
        Normal: User accesses 1-2 credentials per session
        
        Returns:
            (detection_confidence, details)
        """
        if len(session.credentials_tested) < 3:
            return 0.0, {"reason": "normal_credential_usage"}
        
        # High number of credentials in short time = suspicious
        time_window = 60  # seconds
        credentials_per_minute = len(session.credentials_tested) / (session.duration_seconds / 60 + 1)
        
        # Normal: 1-2 credentials/minute
        # Attack: 10+ credentials/minute
        expected_rate = 1.5
        
        rate_ratio = min(credentials_per_minute / expected_rate, 10.0)
        detection_confidence = min(1.0, (rate_ratio - 1.0) / 3.0)
        
        return detection_confidence, {
            "credentials_tested": len(session.credentials_tested),
            "credentials_per_minute": credentials_per_minute,
            "expected_per_minute": expected_rate,
        }
    
    def detect_rate_anomaly(self, session: AttackSession) -> Tuple[float, Dict]:
        """
        Detect API call rate anomalies.
        
        GuardDuty detects:
        - Sustained high call rates
        - Calling multiple APIs in rapid succession
        - Calling less-used APIs
        
        Returns:
            (detection_confidence, details)
        """
        if not session.responses:
            return 0.0, {"reason": "no_api_calls"}
        
        # Calculate call rate
        total_calls = len(session.responses)
        duration_minutes = max(session.duration_seconds / 60, 0.1)
        calls_per_minute = total_calls / duration_minutes
        
        expected_rate = 10  # Normal: ~10 calls/minute
        
        # Exponential scoring: 100 calls/min = 1.0 confidence
        rate_multiplier = calls_per_minute / expected_rate
        detection_confidence = min(1.0, (rate_multiplier - 1.0) / 9.0)
        
        return detection_confidence, {
            "calls_per_minute": calls_per_minute,
            "expected_calls_per_minute": expected_rate,
            "total_calls": total_calls,
            "duration_minutes": duration_minutes,
        }
    
    def detect_impossible_travel(self,
                                session: AttackSession,
                                access_locations: List[Tuple[float, float, float]]) -> Tuple[float, Dict]:
        """
        Detect impossible-travel attacks (geographic anomalies).
        
        Args:
            access_locations: List of (latitude, longitude, timestamp)
        
        Returns:
            (detection_confidence, details)
        """
        if len(access_locations) < 2:
            return 0.0, {"reason": "insufficient_locations"}
        
        # Calculate distance between consecutive accesses
        max_distance_km = 0
        max_speed_kmh = 0
        
        for i in range(1, len(access_locations)):
            lat1, lon1, ts1 = access_locations[i-1]
            lat2, lon2, ts2 = access_locations[i]
            
            distance_km = self._haversine_distance(lat1, lon1, lat2, lon2)
            time_diff_hours = (ts2 - ts1) / 3600 + 0.001
            speed_kmh = distance_km / time_diff_hours
            
            max_distance_km = max(max_distance_km, distance_km)
            max_speed_kmh = max(max_speed_kmh, speed_kmh)
        
        # Detection: speed > impossible_travel_threshold (e.g., 900 km/h)
        if max_speed_kmh > self.impossible_travel_threshold:
            detection_confidence = min(1.0, (max_speed_kmh / (self.impossible_travel_threshold * 2)))
        else:
            detection_confidence = 0.0
        
        return detection_confidence, {
            "max_speed_kmh": max_speed_kmh,
            "threshold_kmh": self.impossible_travel_threshold,
            "max_distance_km": max_distance_km,
        }
    
    @staticmethod
    def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points on Earth (km)."""
        from math import radians, sin, cos, sqrt, atan2
        
        R = 6371  # Earth radius in km
        
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return R * c
    
    def simulate_detection_latency(self) -> float:
        """Simulate time until GuardDuty detects anomaly (seconds)."""
        mean, std = self.detection_latency_distribution
        latency = max(0, np.random.normal(mean, std))
        return latency


class ThreatModelEvaluator:
    """
    Evaluate security properties against sinkhole-aware adversaries.
    
    Provides:
    1. Game-theoretic analysis (attacker payoff, defense effectiveness)
    2. Empirical detection probabilities
    3. Time-to-detection metrics
    4. Correlation detection for distributed attacks
    """
    
    def __init__(self,
                 sinkhole_fidelity: float = 0.85,
                 guardduty_effectiveness: float = 0.8):
        """
        Args:
            sinkhole_fidelity: How realistic is sinkhole (0-1)
            guardduty_effectiveness: How effective is cloud detection (0-1)
        """
        self.sinkhole_detector = SinkholeDetector(sinkhole_fidelity)
        self.cloud_detector = CloudAnomalyDetector()
        self.guardduty_effectiveness = guardduty_effectiveness
        
        self.evaluated_sessions: List[AttackSession] = []
    
    def evaluate_attack_session(self, session: AttackSession) -> AttackSession:
        """
        Run full detection simulation for an attack session.
        
        Returns:
            Updated session with detection_events populated
        """
        # Simulate sinkhole detection
        sinkhole_conf, sinkhole_details = self.sinkhole_detector.test_behavioral_fidelity(
            SinkholeResponse(
                api_key=session.credentials_tested[0] if session.credentials_tested else "unknown",
                response_time_ms=np.random.normal(55, 10)
            ),
            [RealAWSResponse(
                api_key="real_key",
                response_time_ms=np.random.normal(50, 15)
            ) for _ in range(10)]
        )
        
        if sinkhole_conf > 0.3:
            session.detection_events.append(DetectionEvent(
                timestamp=time.time(),
                detection_method=DetectionMethod.BEHAVIORAL_FIDELITY,
                confidence=min(1.0, sinkhole_conf * self.guardduty_effectiveness),
                severity="high",
                session_id=session.session_id,
                details=sinkhole_details
            ))
        
        # Simulate rate limiting detection
        rate_conf, rate_details = self.sinkhole_detector.test_rate_limiting(session)
        if rate_conf > 0.3:
            session.detection_events.append(DetectionEvent(
                timestamp=time.time(),
                detection_method=DetectionMethod.RATE_LIMITING,
                confidence=rate_conf,
                severity="medium",
                session_id=session.session_id,
                details=rate_details
            ))
        
        # Simulate temporal analysis
        temporal_conf, temporal_details = self.sinkhole_detector.test_temporal_consistency(session)
        if temporal_conf > 0.3:
            session.detection_events.append(DetectionEvent(
                timestamp=time.time(),
                detection_method=DetectionMethod.TEMPORAL_CLUSTERING,
                confidence=temporal_conf,
                severity="medium",
                session_id=session.session_id,
                details=temporal_details
            ))
        
        # Simulate cloud anomaly detection
        corr_conf, corr_details = self.cloud_detector.detect_credential_correlation(session)
        if corr_conf > 0.4:
            session.detection_events.append(DetectionEvent(
                timestamp=time.time(),
                detection_method=DetectionMethod.CREDENTIAL_CORRELATION,
                confidence=min(1.0, corr_conf * self.guardduty_effectiveness),
                severity="high",
                session_id=session.session_id,
                details=corr_details
            ))
        
        # Simulate rate anomaly detection
        rate_anom_conf, rate_anom_details = self.cloud_detector.detect_rate_anomaly(session)
        if rate_anom_conf > 0.3:
            session.detection_events.append(DetectionEvent(
                timestamp=time.time(),
                detection_method=DetectionMethod.GUARDDUTY_SIMULATION,
                confidence=min(1.0, rate_anom_conf * self.guardduty_effectiveness),
                severity="high",
                session_id=session.session_id,
                details=rate_anom_details
            ))
        
        self.evaluated_sessions.append(session)
        return session
    
    def compute_cross_session_correlations(self, sessions: List[AttackSession]) -> Dict:
        """
        Detect patterns across multiple sessions (distributed attacks).
        
        Patterns:
        - Same attacker (IP spoofing, timing correlations)
        - Coordinated multi-stage attacks
        - Credential reuse across sessions
        
        Returns:
            Correlation analysis results
        """
        if len(sessions) < 2:
            return {"reason": "insufficient_sessions"}
        
        correlations = {
            "session_count": len(sessions),
            "credential_overlap": defaultdict(list),
            "timing_correlations": [],
            "detected_patterns": [],
        }
        
        # Find credential overlaps
        all_credentials = defaultdict(list)
        for session in sessions:
            for cred in session.credentials_tested:
                all_credentials[cred].append(session.session_id)
        
        overlaps = {cred: sessions for cred, sessions in all_credentials.items() if len(sessions) > 1}
        correlations["credential_overlap"] = overlaps
        
        # Analyze timing correlations
        for i in range(len(sessions)):
            for j in range(i+1, len(sessions)):
                s1, s2 = sessions[i], sessions[j]
                
                # Check if sessions overlap in time
                if s1.start_time < s2.start_time < s1.start_time + s1.duration_seconds:
                    correlations["timing_correlations"].append({
                        "session_1": s1.session_id,
                        "session_2": s2.session_id,
                        "overlap_seconds": min(
                            s1.start_time + s1.duration_seconds - s2.start_time,
                            s2.start_time + s2.duration_seconds - s1.start_time
                        ),
                    })
        
        if overlaps:
            correlations["detected_patterns"].append({
                "pattern": "credential_reuse",
                "severity": "high",
                "recommendation": "Investigate correlated sessions for distributed attack"
            })
        
        if len(correlations["timing_correlations"]) > 2:
            correlations["detected_patterns"].append({
                "pattern": "temporal_coordination",
                "severity": "high",
                "recommendation": "Multiple overlapping sessions suggest coordinated attack"
            })
        
        return correlations
    
    def generate_threat_report(self) -> Dict:
        """Generate comprehensive threat model evaluation report."""
        if not self.evaluated_sessions:
            return {"error": "no_sessions_evaluated"}
        
        detected = sum(1 for s in self.evaluated_sessions if s.detection_probability > 0.5)
        avg_detection_prob = np.mean([s.detection_probability for s in self.evaluated_sessions])
        avg_ttd = np.mean([s.time_to_detection or float('inf') for s in self.evaluated_sessions
                          if s.time_to_detection is not None])
        
        return {
            "total_sessions": len(self.evaluated_sessions),
            "successful_detections": detected,
            "detection_rate": detected / len(self.evaluated_sessions) if self.evaluated_sessions else 0.0,
            "average_detection_probability": avg_detection_prob,
            "average_time_to_detection_seconds": avg_ttd if avg_ttd != float('inf') else None,
            "detection_methods_effective": [
                method.value for method in DetectionMethod
            ],
            "sinkhole_fidelity": self.sinkhole_detector.sinkhole_fidelity,
            "guardduty_effectiveness": self.guardduty_effectiveness,
        }
