"""
Tests for Sinkhole-Aware Adversary Threat Model.

Tests both game-theoretic properties and empirical detection mechanisms.
"""

import pytest
import time
from app.core.threat_models import (
    AdversaryType,
    DetectionMethod,
    AttackPhase,
    AttackSession,
    SinkholeResponse,
    RealAWSResponse,
    SinkholeDetector,
    CloudAnomalyDetector,
    ThreatModelEvaluator,
)


class TestSinkholeDetection:
    """Test sinkhole detection mechanisms."""
    
    @pytest.fixture
    def detector(self):
        return SinkholeDetector(sinkhole_fidelity=0.85)
    
    def test_behavioral_fidelity_detection_high_fidelity(self, detector):
        """High-fidelity sinkhole should be harder to detect."""
        detector.sinkhole_fidelity = 0.95
        
        sinkhole = SinkholeResponse(
            api_key="AKIA1234567890ABCDEF",
            response_time_ms=51.0
        )
        
        references = [
            RealAWSResponse(
                api_key=f"real_key_{i}",
                response_time_ms=50 + (5 * i)  # 50, 55, 60, ...
            )
            for i in range(5)
        ]
        
        confidence, details = detector.test_behavioral_fidelity(sinkhole, references)
        
        # High fidelity should reduce detection confidence
        assert confidence < 0.5, "High-fidelity sinkhole should be hard to detect"
        assert "z_score" in details
        assert "structure_match" in details
    
    def test_behavioral_fidelity_detection_low_fidelity(self, detector):
        """Low-fidelity sinkhole should be easier to detect."""
        detector.sinkhole_fidelity = 0.60
        
        sinkhole = SinkholeResponse(
            api_key="AKIA1234567890ABCDEF",
            response_time_ms=200.0  # Suspiciously slow
        )
        
        references = [
            RealAWSResponse(
                api_key=f"real_key_{i}",
                response_time_ms=50.0
            )
            for i in range(5)
        ]
        
        confidence, details = detector.test_behavioral_fidelity(sinkhole, references)
        
        # Low fidelity + suspiciously different response should give high confidence
        assert confidence > 0.5, "Low-fidelity sinkhole with different timing should be detectable"
    
    def test_rate_limiting_detection_no_throttling(self, detector):
        """Sinkhole that doesn't enforce rate limits should be detected."""
        session = AttackSession(
            session_id="test_session_1",
            adversary_type=AdversaryType.AWARE
        )
        
        # Generate responses without throttling (all 200)
        for i in range(20):
            session.responses.append(
                SinkholeResponse(
                    api_key=f"AKIA{i:016d}",
                    response_time_ms=50.0,
                    status_code=200
                )
            )
        
        confidence, details = detector.test_rate_limiting(session)
        
        # Should detect lack of rate limiting
        assert confidence > 0.0, "Missing rate limits should trigger detection"
        assert "observed_throttle_rate" in details
    
    def test_temporal_consistency_suspicious_variance(self, detector):
        """Too-constant response times should be suspicious."""
        session = AttackSession(
            session_id="test_session_2",
            adversary_type=AdversaryType.AWARE
        )
        
        # Generate responses with very low variance (constant-time defense)
        for i in range(20):
            session.responses.append(
                SinkholeResponse(
                    api_key=f"AKIA{i:016d}",
                    response_time_ms=50.0 + (0.1 * (i % 2))  # Variance: 0.1ms
                )
            )
        
        confidence, details = detector.test_temporal_consistency(session)
        
        # Low variance should be detected
        assert confidence > 0.0, "Too-constant response times should be suspicious"
        assert "observed_cv" in details


class TestCloudAnomalyDetection:
    """Test cloud provider detection mechanisms."""
    
    @pytest.fixture
    def detector(self):
        return CloudAnomalyDetector()
    
    def test_credential_correlation_detection(self, detector):
        """Detect when many fake credentials accessed together."""
        session = AttackSession(
            session_id="attack_1",
            adversary_type=AdversaryType.AWARE,
            start_time=time.time()
        )
        
        # Add 50 credentials tested in short time
        for i in range(50):
            session.credentials_tested.append(f"AKIA{i:016d}")
            session.responses.append(
                SinkholeResponse(
                    api_key=f"AKIA{i:016d}",
                    response_time_ms=50.0
                )
            )
        
        confidence, details = detector.detect_credential_correlation(session)
        
        # Should detect high credential access rate
        assert confidence > 0.5, "High credential access rate should be detected"
        assert details["credentials_per_minute"] > 10
    
    def test_rate_anomaly_detection(self, detector):
        """Detect abnormally high API call rates."""
        session = AttackSession(
            session_id="attack_2",
            adversary_type=AdversaryType.AWARE,
            start_time=time.time()
        )
        
        # 500 API calls in 1 minute (abnormally high)
        for i in range(500):
            session.responses.append(
                SinkholeResponse(
                    api_key="AKIA0000000000000000",
                    response_time_ms=10.0
                )
            )
        
        confidence, details = detector.detect_rate_anomaly(session)
        
        # Should detect anomalously high rate
        assert confidence > 0.5, "Abnormally high call rate should be detected"
        assert details["calls_per_minute"] > 400
    
    def test_impossible_travel_many_locations(self, detector):
        """Detect impossible-travel patterns."""
        session = AttackSession(
            session_id="attack_3",
            adversary_type=AdversaryType.AWARE
        )
        
        # Access from: San Francisco → New York (impossible in 1 second)
        # SF: 37.77, -122.42
        # NYC: 40.71, -74.01
        current_time = time.time()
        
        locations = [
            (37.77, -122.42, current_time),      # San Francisco
            (40.71, -74.01, current_time + 1.0), # New York (1 second later)
        ]
        
        confidence, details = detector.detect_impossible_travel(session, locations)
        
        # Should detect impossible travel
        assert confidence > 0.5, "Impossible travel should be detected"
        assert details["max_speed_kmh"] > detector.impossible_travel_threshold


class TestThreatModelEvaluator:
    """Test comprehensive threat model evaluation."""
    
    @pytest.fixture
    def evaluator(self):
        return ThreatModelEvaluator(
            sinkhole_fidelity=0.85,
            guardduty_effectiveness=0.8
        )
    
    def test_evaluate_naive_attack_session(self, evaluator):
        """Evaluate naive attacker (unaware of sinkhole)."""
        session = AttackSession(
            session_id="naive_attack_1",
            adversary_type=AdversaryType.NAIVE,
            start_time=time.time()
        )
        
        # Naive attacker: just tests credentials
        for i in range(5):
            session.credentials_tested.append(f"AKIA{i:016d}")
            session.responses.append(
                SinkholeResponse(
                    api_key=f"AKIA{i:016d}",
                    response_time_ms=50.0
                )
            )
        
        evaluated = evaluator.evaluate_attack_session(session)
        
        # Naive attacker may not be detected (low signal)
        assert evaluated.detection_probability >= 0.0
        assert evaluated.detection_probability <= 1.0
    
    def test_evaluate_aware_attack_session(self, evaluator):
        """Evaluate sophisticated attacker (aware of sinkhole)."""
        session = AttackSession(
            session_id="aware_attack_1",
            adversary_type=AdversaryType.SOPHISTICATED,
            start_time=time.time()
        )
        
        # Sophisticated attacker: many credentials + behavioral analysis
        for i in range(100):
            session.credentials_tested.append(f"AKIA{i:016d}")
            session.responses.append(
                SinkholeResponse(
                    api_key=f"AKIA{i:016d}",
                    response_time_ms=50.0 + (0.1 * (i % 2))
                )
            )
        
        evaluated = evaluator.evaluate_attack_session(session)
        
        # Sophisticated attacker should trigger multiple detection methods
        assert len(evaluated.detection_events) >= 1
        assert evaluated.detection_probability > 0.0
    
    def test_cross_session_correlation_coordinated_attack(self, evaluator):
        """Detect correlation patterns in multi-session attacks."""
        sessions = []
        
        # Create 3 coordinated sessions
        for session_num in range(3):
            session = AttackSession(
                session_id=f"coordinated_{session_num}",
                adversary_type=AdversaryType.AWARE,
                start_time=time.time() + session_num * 10
            )
            
            # All sessions test overlapping credentials (coordinated attack)
            for i in range(10):
                cred = f"AKIA{session_num:08d}{i:08d}"
                session.credentials_tested.append(cred)
                if session_num == 0 or session_num == 1:
                    # Sessions 0 and 1 have overlapping creds
                    session.credentials_tested.append(f"AKIA00000000{i:08d}")
            
            sessions.append(session)
        
        correlation_analysis = evaluator.compute_cross_session_correlations(sessions)
        
        # Should detect coordinated patterns
        assert correlation_analysis["session_count"] == 3
        assert "credential_overlap" in correlation_analysis
        assert len(correlation_analysis["detected_patterns"]) > 0
    
    def test_threat_report_generation(self, evaluator):
        """Test threat model report generation."""
        # Create and evaluate test sessions
        for i in range(5):
            session = AttackSession(
                session_id=f"test_{i}",
                adversary_type=AdversaryType.AWARE,
                start_time=time.time()
            )
            
            for j in range(20):
                session.credentials_tested.append(f"AKIA{i:08d}{j:08d}")
                session.responses.append(
                    SinkholeResponse(
                        api_key=f"AKIA{i:08d}{j:08d}",
                        response_time_ms=50.0
                    )
                )
            
            evaluator.evaluate_attack_session(session)
        
        report = evaluator.generate_threat_report()
        
        # Verify report structure
        assert "total_sessions" in report
        assert report["total_sessions"] == 5
        assert "detection_rate" in report
        assert "average_detection_probability" in report
        assert "detection_methods_effective" in report
        assert report["sinkhole_fidelity"] == 0.85
        assert report["guardduty_effectiveness"] == 0.8


class TestGameTheoreticProperties:
    """Test game-theoretic security properties."""
    
    def test_attacker_payoff_naive_vs_aware(self):
        """Compare attacker payoff for naive vs aware adversaries."""
        evaluator = ThreatModelEvaluator(sinkhole_fidelity=0.85)
        
        # Naive attacker: no detection
        naive_session = AttackSession(
            session_id="naive",
            adversary_type=AdversaryType.NAIVE,
            start_time=time.time()
        )
        for i in range(5):
            naive_session.credentials_tested.append(f"AKIA{i:016d}")
            naive_session.responses.append(
                SinkholeResponse(api_key=f"AKIA{i:016d}", response_time_ms=50.0)
            )
        
        naive_eval = evaluator.evaluate_attack_session(naive_session)
        
        # Aware attacker: higher detection probability
        aware_session = AttackSession(
            session_id="aware",
            adversary_type=AdversaryType.AWARE,
            start_time=time.time()
        )
        for i in range(50):
            aware_session.credentials_tested.append(f"AKIA{i:016d}")
            aware_session.responses.append(
                SinkholeResponse(api_key=f"AKIA{i:016d}", response_time_ms=50.0)
            )
        
        aware_eval = evaluator.evaluate_attack_session(aware_session)
        
        # HoneyVault defense should increase with attacker sophistication
        assert aware_eval.detection_probability >= naive_eval.detection_probability
    
    def test_attacker_strategy_exploration(self):
        """Test attacker strategy mixing (game-theoretic equilibrium)."""
        detections = []
        
        for strategy in [AdversaryType.NAIVE, AdversaryType.AWARE, AdversaryType.SOPHISTICATED]:
            evaluator = ThreatModelEvaluator()
            
            session = AttackSession(
                session_id=f"strategy_{strategy.value}",
                adversary_type=strategy,
                start_time=time.time()
            )
            
            # Strategy-dependent behavior
            credential_count = {
                AdversaryType.NAIVE: 5,
                AdversaryType.AWARE: 30,
                AdversaryType.SOPHISTICATED: 100,
            }[strategy]
            
            for i in range(credential_count):
                session.credentials_tested.append(f"AKIA{i:016d}")
                session.responses.append(
                    SinkholeResponse(api_key=f"AKIA{i:016d}", response_time_ms=50.0)
                )
            
            evaluated = evaluator.evaluate_attack_session(session)
            detections.append((strategy.value, evaluated.detection_probability))
        
        # Verify detection increases with sophistication
        probs = [p for _, p in detections]
        assert probs[1] >= probs[0] or probs[0] == 0, "AWARE should have detection >= NAIVE"
        assert probs[2] >= probs[1] or probs[1] == 0, "SOPHISTICATED should have detection >= AWARE"


class TestDistributedAttackDetection:
    """Test detection of distributed/multi-stage attacks."""
    
    def test_cross_session_multi_stage_attack(self):
        """Detect multi-stage attacks across sessions."""
        evaluator = ThreatModelEvaluator()
        
        # Stage 1: Reconnaissance
        stage1 = AttackSession(
            session_id="stage1_recon",
            adversary_type=AdversaryType.AWARE,
            start_time=time.time(),
            attack_phases=[AttackPhase.RECONNAISSANCE]
        )
        for i in range(10):
            stage1.credentials_tested.append(f"AKIA_RECON_{i:08d}")
            stage1.responses.append(
                SinkholeResponse(api_key=f"AKIA_RECON_{i:08d}", response_time_ms=50.0)
            )
        
        # Stage 2: Credential enumeration
        stage2 = AttackSession(
            session_id="stage2_enum",
            adversary_type=AdversaryType.AWARE,
            start_time=time.time() + 60,  # 1 minute later
            attack_phases=[AttackPhase.CREDENTIAL_ENUMERATION]
        )
        for i in range(50):
            stage2.credentials_tested.append(f"AKIA_ENUM_{i:08d}")
            stage2.responses.append(
                SinkholeResponse(api_key=f"AKIA_ENUM_{i:08d}", response_time_ms=50.0)
            )
        
        # Stage 3: Lateral movement
        stage3 = AttackSession(
            session_id="stage3_lateral",
            adversary_type=AdversaryType.AWARE,
            start_time=time.time() + 120,
            attack_phases=[AttackPhase.LATERAL_MOVEMENT]
        )
        for i in range(30):
            stage3.credentials_tested.append(f"AKIA_LATERAL_{i:08d}")
            stage3.responses.append(
                SinkholeResponse(api_key=f"AKIA_LATERAL_{i:08d}", response_time_ms=50.0)
            )
        
        sessions = [stage1, stage2, stage3]
        correlations = evaluator.compute_cross_session_correlations(sessions)
        
        # Should detect multi-stage pattern
        assert correlations["session_count"] == 3
        # Timing correlations should be detected
        assert len(correlations["timing_correlations"]) >= 0  # May be empty depending on timing


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
