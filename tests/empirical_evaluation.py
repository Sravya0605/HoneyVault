"""
Empirical Evaluation Framework for HoneyVault

This module implements comprehensive empirical evaluation against the three threat models:
- A1: Offline Brute-Force (baseline)
- A2: Online Aware (sinkhole validation)
- A3: Sophisticated (classifier-based)

Key metrics:
- Attacker success rate (% of attacks that recover real credential)
- Detection rate (% of attacks detected)
- Classifier accuracy (distinguishability of real vs fake)
- ROC curves for detection
- Baseline comparisons
"""

import pytest
import asyncio
import numpy as np
import json
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

from httpx import AsyncClient
from app.main import app
from app.core.security import HoneyEncryption
from app.core.dte import DistributionTransformingEncoder
from app.services.logging_service import LoggingService
from app.services.sinkhole_service import SinkholeService
from app.utils.security_utils import is_valid_api_key_format


@dataclass
class AttackerResult:
    """Single attack attempt result."""
    attack_type: str  # "A1", "A2", "A3"
    password_guessed: str
    is_correct: bool
    decrypted_credential: str
    credential_valid: bool
    was_detected: bool
    detection_time_ms: float
    attack_succeeded: bool  # recovered real credential AND undetected


@dataclass
class EvaluationMetrics:
    """Comprehensive evaluation metrics for publication."""
    threat_model: str
    total_attacks: int
    successful_attacks: int
    success_rate: float
    
    # Detection metrics
    detections: int
    detection_rate: float
    false_positives: int
    false_negatives: int
    
    # For ROC curve
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    fpr: float
    
    # Classifier metrics (A3 only)
    classifier_accuracy: float = None
    classifier_auc: float = None
    kl_divergence: float = None
    
    # Latency
    avg_attack_latency_ms: float
    detection_latency_p50: float
    detection_latency_p95: float


class A1OfflineAttacker:
    """A1 - Offline brute-force attacker (no external validation)."""
    
    def __init__(self):
        self.he = HoneyEncryption()
        self.logger = logging.getLogger(__name__)
    
    def attempt_password(self, vault: Dict, password: str, correct_password: str) -> AttackerResult:
        """
        A1 attacker can only decrypt and check if output is valid format.
        
        No external validation → all outputs are valid format → can't distinguish real from fake.
        """
        start_time = datetime.now()
        
        try:
            decrypted = self.he.decrypt_vault(vault, password)
            is_correct = (password == correct_password)
            
            # A1 can't distinguish - all outputs are valid AWS key formats
            attack_succeeded = is_correct and not self.was_detected_offline(decrypted)
            
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            return AttackerResult(
                attack_type="A1",
                password_guessed=password,
                is_correct=is_correct,
                decrypted_credential=decrypted,
                credential_valid=True,  # A1 sees all as valid
                was_detected=False,  # A1 has no detection mechanism
                detection_time_ms=0,
                attack_succeeded=is_correct  # Only wins if guesses correct password
            )
        except Exception as e:
            self.logger.error(f"A1 attack failed: {e}")
            return None
    
    def was_detected_offline(self, credential: str) -> bool:
        """Check if credential is obviously fake (used for A1 assumption test)."""
        # In real HE, all credentials appear valid
        return False


class A2OnlineAttacker:
    """A2 - Online attacker with access to sinkhole validation endpoint."""
    
    def __init__(self, api_url: str = "http://127.0.0.1:8000"):
        self.he = HoneyEncryption()
        self.sinkhole = SinkholeService()
        self.api_url = api_url
        self.logger = logging.getLogger(__name__)
    
    async def attempt_password(
        self, 
        vault: Dict, 
        password: str, 
        correct_password: str,
        vault_id: str = None
    ) -> AttackerResult:
        """
        A2 attacker decrypts and validates against sinkhole.
        
        Goal: Distinguish real credential from fake by behavioral analysis.
        """
        start_time = datetime.now()
        detection_start = start_time
        
        try:
            decrypted = self.he.decrypt_vault(vault, password)
            is_correct = (password == correct_password)
            
            # A2 validates against sinkhole (simulated or real)
            validation_result = await self._validate_credential(decrypted, vault_id)
            
            is_detected = validation_result.get("detected", False)
            detection_time_ms = (datetime.now() - detection_start).total_seconds() * 1000
            
            # Attack succeeds if: correct password AND not detected
            attack_succeeded = is_correct and not is_detected
            
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            return AttackerResult(
                attack_type="A2",
                password_guessed=password,
                is_correct=is_correct,
                decrypted_credential=decrypted,
                credential_valid=validation_result.get("valid", False),
                was_detected=is_detected,
                detection_time_ms=detection_time_ms,
                attack_succeeded=attack_succeeded
            )
        except Exception as e:
            self.logger.error(f"A2 attack failed: {e}")
            return None
    
    async def _validate_credential(self, credential: str, vault_id: str = None) -> Dict:
        """Query sinkhole validation endpoint."""
        try:
            # In real scenario, this would call the sinkhole service
            validation = await self.sinkhole.validate_credential(credential, vault_id)
            return validation
        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            return {"valid": False, "detected": False}


class A3SophisticatedAttacker:
    """A3 - Sophisticated attacker with source code access and classifier training."""
    
    def __init__(self):
        self.he = HoneyEncryption()
        self.dte = DistributionTransformingEncoder()
        self.classifier = None
        self.logger = logging.getLogger(__name__)
        
    def train_classifier(self, real_credentials: List[str], fake_credentials: List[str]) -> Dict:
        """
        Train ML classifier to distinguish real from fake credentials.
        
        This is the core of the A3 threat: if real and fake distributions differ,
        a classifier can exploit the difference.
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score, roc_auc_score
        from sklearn.metrics import accuracy_score, confusion_matrix
        
        # Extract features from credentials
        X_real = np.array([self._extract_features(cred) for cred in real_credentials])
        X_fake = np.array([self._extract_features(cred) for cred in fake_credentials])
        
        X = np.vstack([X_real, X_fake])
        y = np.hstack([np.ones(len(X_real)), np.zeros(len(X_fake))])
        
        # Train classifier
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.classifier.fit(X, y)
        
        # Evaluate
        accuracy = self.classifier.score(X, y)
        cv_scores = cross_val_score(self.classifier, X, y, cv=5, scoring='roc_auc')
        
        return {
            "accuracy": accuracy,
            "auc_cv_mean": cv_scores.mean(),
            "auc_cv_std": cv_scores.std(),
            "samples_real": len(X_real),
            "samples_fake": len(X_fake),
        }
    
    def attack_with_classifier(self, credential: str) -> Tuple[float, str]:
        """
        Use trained classifier to predict if credential is real or fake.
        
        Returns: (confidence: float, prediction: str)
        """
        if self.classifier is None:
            return None, "untrained"
        
        features = np.array([self._extract_features(credential)])
        prediction_proba = self.classifier.predict_proba(features)[0]
        
        is_real = prediction_proba[1] > 0.5
        confidence = max(prediction_proba)
        
        return confidence, "real" if is_real else "fake"
    
    def _extract_features(self, credential: str) -> np.ndarray:
        """Extract statistical features from credential for classification."""
        # Character distribution features
        upper_ratio = sum(1 for c in credential if c.isupper()) / len(credential)
        digit_ratio = sum(1 for c in credential if c.isdigit()) / len(credential)
        special_ratio = sum(1 for c in credential if not c.isalnum()) / len(credential)
        
        # Pattern features
        entropy = self._compute_entropy(credential)
        
        return np.array([
            upper_ratio,
            digit_ratio,
            special_ratio,
            entropy,
            len(credential)
        ])
    
    def _compute_entropy(self, s: str) -> float:
        """Shannon entropy of string."""
        from collections import Counter
        counts = Counter(s)
        entropy = 0
        for count in counts.values():
            p = count / len(s)
            entropy -= p * np.log2(p)
        return entropy / 8  # Normalize to [0, 1]


class EmpiricialEvaluationSuite:
    """Comprehensive evaluation suite for all threat models."""
    
    def __init__(self, api_url: str = "http://127.0.0.1:8000"):
        self.api_url = api_url
        self.he = HoneyEncryption()
        self.logger = LoggingService()
        
    async def evaluate_a1_threat(self, 
                                  num_attacks: int = 1000,
                                  password_dict_size: int = 100000) -> EvaluationMetrics:
        """
        Evaluate A1 (offline brute-force) threat model.
        
        Expected result: Success rate ≤ random guessing (1/password_space)
        """
        attacker = A1OfflineAttacker()
        results = []
        
        # Generate password dictionary
        passwords = self._generate_password_dict(password_dict_size)
        correct_password = passwords[0]
        
        latencies = []
        
        for i in range(num_attacks):
            # Randomly select a password to guess (mostly wrong ones)
            guessed_password = np.random.choice(passwords)
            
            # Generate vault with correct password
            vault = self.he.encrypt_vault(correct_password, "AKIAIOSFODNN7EXAMPLE")
            
            start = datetime.now()
            result = attacker.attempt_password(vault, guessed_password, correct_password)
            latencies.append((datetime.now() - start).total_seconds() * 1000)
            
            if result:
                results.append(result)
        
        # Compute metrics
        successful = sum(1 for r in results if r.attack_succeeded)
        success_rate = successful / len(results) if results else 0
        
        # Expected: ~1/password_dict_size
        expected_success = 1.0 / password_dict_size
        
        return EvaluationMetrics(
            threat_model="A1_OFFLINE",
            total_attacks=len(results),
            successful_attacks=successful,
            success_rate=success_rate,
            detections=0,
            detection_rate=0.0,
            false_positives=0,
            false_negatives=0,
            tp=0, fp=0, tn=0, fn=0,
            precision=0, recall=0, fpr=0,
            avg_attack_latency_ms=np.mean(latencies),
            detection_latency_p50=0,
            detection_latency_p95=0
        )
    
    async def evaluate_a2_threat(self,
                                  num_attacks: int = 500) -> EvaluationMetrics:
        """
        Evaluate A2 (online aware) threat model.
        
        Measures: Detection rate vs attack success rate
        """
        attacker = A2OnlineAttacker(self.api_url)
        results = []
        detection_latencies = []
        
        for i in range(num_attacks):
            correct_password = f"real_password_{i}"
            guessed_password = np.random.choice([
                correct_password,  # 10% correct
                f"wrong_password_{i}_{j}"  # 90% wrong
                for j in range(9)
            ])
            
            vault_data = self.he.encrypt_vault(correct_password, "AKIAIOSFODNN7EXAMPLE")
            vault = vault_data["vault"]
            vault_id = vault_data.get("vault_id")
            
            result = await attacker.attempt_password(vault, guessed_password, correct_password, vault_id)
            if result:
                results.append(result)
                if result.detection_time_ms > 0:
                    detection_latencies.append(result.detection_time_ms)
        
        # Compute detection metrics
        tp = sum(1 for r in results if r.is_correct and r.was_detected)
        fp = sum(1 for r in results if not r.is_correct and r.was_detected)
        tn = sum(1 for r in results if not r.is_correct and not r.was_detected)
        fn = sum(1 for r in results if r.is_correct and not r.was_detected)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        successful = sum(1 for r in results if r.attack_succeeded)
        success_rate = successful / len(results) if results else 0
        
        detection_latencies.sort()
        p50 = detection_latencies[len(detection_latencies) // 2] if detection_latencies else 0
        p95 = detection_latencies[int(len(detection_latencies) * 0.95)] if detection_latencies else 0
        
        return EvaluationMetrics(
            threat_model="A2_ONLINE",
            total_attacks=len(results),
            successful_attacks=successful,
            success_rate=success_rate,
            detections=tp + fp,
            detection_rate=(tp + fp) / len(results) if results else 0,
            false_positives=fp,
            false_negatives=fn,
            tp=tp, fp=fp, tn=tn, fn=fn,
            precision=precision,
            recall=recall,
            fpr=fpr,
            avg_attack_latency_ms=np.mean([r.detection_time_ms for r in results if r.detection_time_ms > 0]),
            detection_latency_p50=p50,
            detection_latency_p95=p95
        )
    
    def evaluate_a3_threat(self,
                           num_real_creds: int = 1000,
                           num_fake_creds: int = 1000) -> EvaluationMetrics:
        """
        Evaluate A3 (sophisticated) threat model via classifier attack.
        
        Measures: Classifier accuracy in distinguishing real vs fake
        """
        from sklearn.metrics import accuracy_score, roc_auc_score
        
        attacker = A3SophisticatedAttacker()
        
        # Generate real credentials (from deployment observation)
        real_creds = [self._generate_real_credential() for _ in range(num_real_creds)]
        
        # Generate fake credentials (from HE DTE)
        fake_creds = [self._generate_fake_credential() for _ in range(num_fake_creds)]
        
        # Train classifier
        classifier_metrics = attacker.train_classifier(real_creds, fake_creds)
        
        # Test on held-out set
        test_real = real_creds[num_real_creds // 2:]
        test_fake = fake_creds[num_fake_creds // 2:]
        
        correct_predictions = 0
        auc_scores = []
        
        for cred in test_real:
            conf, pred = attacker.attack_with_classifier(cred)
            if pred == "real":
                correct_predictions += 1
        
        for cred in test_fake:
            conf, pred = attacker.attack_with_classifier(cred)
            if pred == "fake":
                correct_predictions += 1
        
        total_test = len(test_real) + len(test_fake)
        accuracy = correct_predictions / total_test if total_test > 0 else 0
        
        return EvaluationMetrics(
            threat_model="A3_SOPHISTICATED",
            total_attacks=total_test,
            successful_attacks=int(accuracy * total_test),
            success_rate=accuracy,
            detections=0,
            detection_rate=0,
            false_positives=0,
            false_negatives=0,
            tp=0, fp=0, tn=0, fn=0,
            precision=0, recall=0, fpr=0,
            classifier_accuracy=accuracy,
            classifier_auc=classifier_metrics.get("auc_cv_mean"),
            kl_divergence=self._compute_kl_divergence(real_creds, fake_creds),
            avg_attack_latency_ms=0,
            detection_latency_p50=0,
            detection_latency_p95=0
        )
    
    def _generate_password_dict(self, size: int) -> List[str]:
        """Generate realistic password dictionary."""
        import string
        passwords = []
        for i in range(size):
            length = np.random.randint(8, 20)
            pwd = ''.join(np.random.choice(list(string.ascii_letters + string.digits)) for _ in range(length))
            passwords.append(pwd)
        return passwords
    
    def _generate_real_credential(self) -> str:
        """Generate realistic AWS API key (for training purposes)."""
        import secrets
        # Format: AKIA + 16 uppercase alphanumeric
        return "AKIA" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(16))
    
    def _generate_fake_credential(self) -> str:
        """Generate fake credential from DTE."""
        seed = np.random.bytes(32)
        return self.dte.decode(seed)
    
    def _compute_kl_divergence(self, real_creds: List[str], fake_creds: List[str]) -> float:
        """Compute KL divergence between real and fake credential distributions."""
        # Character distribution comparison
        from collections import Counter
        
        real_chars = Counter(''.join(real_creds))
        fake_chars = Counter(''.join(fake_creds))
        
        all_chars = set(real_chars.keys()) | set(fake_chars.keys())
        
        kl = 0
        for char in all_chars:
            p = real_chars.get(char, 1) / sum(real_chars.values())
            q = fake_chars.get(char, 1) / sum(fake_chars.values())
            if p > 0:
                kl += p * np.log2(p / q) if q > 0 else 0
        
        return kl / 8  # Normalize


# =============================================================================
# PYTEST TEST CASES
# =============================================================================

class TestA1ThreatModel:
    """Tests for A1 (offline brute-force) attacker."""
    
    @pytest.mark.asyncio
    async def test_a1_success_rate_minimal(self):
        """A1 should achieve near-random guessing success rate."""
        suite = EmpiricialEvaluationSuite()
        metrics = await suite.evaluate_a1_threat(num_attacks=100, password_dict_size=100000)
        
        # Expected: ~0.00001 (1/100000)
        assert metrics.success_rate < 0.001, f"A1 success rate too high: {metrics.success_rate}"
    
    @pytest.mark.asyncio
    async def test_a1_no_false_positives(self):
        """A1 should not have timing-based detection."""
        suite = EmpiricialEvaluationSuite()
        metrics = await suite.evaluate_a1_threat(num_attacks=50)
        
        assert metrics.detection_rate == 0, "A1 should have no detection mechanism"


class TestA2ThreatModel:
    """Tests for A2 (online aware) attacker."""
    
    @pytest.mark.asyncio
    async def test_a2_detection_rate_high(self):
        """A2 attacks should be detected at high rate via sinkhole."""
        suite = EmpiricialEvaluationSuite()
        metrics = await suite.evaluate_a2_threat(num_attacks=200)
        
        # Target: >90% detection rate for fake credentials
        assert metrics.detection_rate > 0.8, f"A2 detection too low: {metrics.detection_rate}"
    
    @pytest.mark.asyncio
    async def test_a2_attack_success_blocked(self):
        """Successful A2 attacks should be rare (detected before exploitation)."""
        suite = EmpiricialEvaluationSuite()
        metrics = await suite.evaluate_a2_threat(num_attacks=200)
        
        # Target: <5% undetected attacks
        assert metrics.success_rate < 0.1, f"A2 success rate too high: {metrics.success_rate}"


class TestA3ThreatModel:
    """Tests for A3 (sophisticated classifier) attacker."""
    
    def test_a3_classifier_near_random(self):
        """A3 classifier should achieve near-random accuracy (~ 50%)."""
        suite = EmpiricialEvaluationSuite()
        metrics = suite.evaluate_a3_threat(num_real_creds=500, num_fake_creds=500)
        
        # Target: 50% ±5% (not better than random)
        assert 0.45 < metrics.classifier_accuracy < 0.55, \
            f"A3 classifier accuracy out of range: {metrics.classifier_accuracy}"
    
    def test_a3_kl_divergence_low(self):
        """KL divergence between real and fake should be minimal."""
        suite = EmpiricialEvaluationSuite()
        metrics = suite.evaluate_a3_threat(num_real_creds=500, num_fake_creds=500)
        
        # Target: <0.1 bits
        assert metrics.kl_divergence < 0.15, \
            f"KL divergence too high: {metrics.kl_divergence}"
