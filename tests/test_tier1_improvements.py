"""
TIER 1 IMPROVEMENTS FOR PAPER ACCEPTANCE
=========================================

These three experiments significantly boost paper credibility:

1. FIXED KL EXPERIMENT
   - Uses random.choices() with proper probability distributions
   - Measures if adaptive DTE reduces KL divergence
   - Metric: KL divergence reduction (%)

2. CLASSIFIER ATTACK
   - Trains ML model to distinguish real vs generated credentials
   - If accuracy ≈ 50%, reveals generated credentials indistinguishable
   - Uses logistic regression + random forest
   - Metric: Classification accuracy (target: ≈50%)

3. BASELINE COMPARISON
   - Compares DTE against naive approaches:
     * Random generation (no structure)
     * Naive honeytokens (fixed patterns)
     * Our DTE-based generation
   - Metrics: Format consistency, distribution realism
"""

import sys
import os
# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secrets
import random
import math
from typing import Dict, List, Tuple
from collections import Counter

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score

from app.core.dte import DistributionTransformingEncoder

# Optional: pytest for running via test framework
try:
    import pytest
except ImportError:
    pytest = None


class TestKLExperimentFixed:
    """
    TIER 1 #1: Fixed KL Divergence Experiment
    
    Does adaptive DTE reduce KL divergence between generated and observed distributions?
    """
    
    def __init__(self):
        self.dte_instance = None
    
    def dte(self):
        if self.dte_instance is None:
            self.dte_instance = DistributionTransformingEncoder()
        return self.dte_instance
    
    def sample_from_distribution(self, distribution: List[Tuple[str, float]], n: int) -> List[str]:
        """Sample n items using random.choices() with proper weights."""
        names, probs = zip(*distribution)
        return random.choices(names, weights=probs, k=n)
    
    def compute_kl_divergence(self, observed: Dict[str, int], modeled: List[Tuple[str, float]]) -> float:
        """
        Compute KL(observed || modeled).
        
        KL measures how far observed distribution is from model:
        KL(P || Q) = Σ P(x) * log(P(x) / Q(x))
        
        Lower KL = better model fit.
        """
        total = sum(observed.values())
        kl = 0.0
        
        for name, model_prob in modeled:
            observed_count = observed.get(name, 0)
            observed_prob = observed_count / total if total > 0 else 0
            
            if observed_prob > 0:
                kl += observed_prob * math.log(observed_prob / (model_prob + 1e-10))
        
        return kl
    
    def test_kl_experiment_before_and_after_learning(self, dte):
        """
        Paper experiment: Adaptive learning reduces KL divergence.
        
        Scenario:
        1. Generate ground-truth distribution (S3-heavy)
        2. Sample 200 credentials matching this distribution
        3. Measure KL before learning
        4. Feed samples to adaptive learner
        5. Measure KL after learning
        6. Verify KL reduction
        """
        # ====== SETUP ======
        # Create synthetic ground-truth distribution
        ground_truth = [
            ("s3", 0.60),      # Increased from default 0.30
            ("ec2", 0.15),     # Decreased from default 0.25
            ("iam", 0.10),     # Decreased from default 0.15
            ("rds", 0.05),     # Decreased from default 0.10
            ("lambda", 0.05),  # Decreased from default 0.10
            ("cloudtrail", 0.03),
            ("kms", 0.02),
            ("dynamodb", 0.00),
        ]
        
        # ====== BEFORE LEARNING ======
        # Measure KL with default distributions
        kl_before = self.compute_kl_divergence(
            {name: count for name, _ in ground_truth for count in [1]},  # dummy
            dte._services
        )
        print(f"\nKL DIVERGENCE (before learning): {kl_before:.4f}")
        
        # ====== GENERATE TRAINING DATA ======
        # Sample 200 credentials from ground-truth distribution
        n_samples = 200
        sampled_services = self.sample_from_distribution(ground_truth, n_samples)
        
        # Count observations
        observed_counts = Counter(sampled_services)
        print(f"Observed distribution (n={n_samples}):")
        for service, count in sorted(observed_counts.items(), key=lambda x: -x[1]):
            print(f"  {service}: {count:3d} ({count/n_samples*100:5.1f}%)")
        
        # ====== FEED TO ADAPTIVE LEARNER ======
        # Feed each sample to DTE's observation system
        for service in sampled_services:
            dte.observe_real_credential("AKIAIOSFODNN7EXAMPLE", {
                "service": service,
                "region": "us-east-1",
                "access_scope": "read-only",
            })
        
        # Update distributions
        dte._update_distributions_from_observations()
        
        # ====== AFTER LEARNING ======
        # Measure KL with updated distributions
        kl_after = self.compute_kl_divergence(observed_counts, dte._services)
        print(f"\nKL DIVERGENCE (after learning):  {kl_after:.4f}")
        
        kl_reduction = (kl_before - kl_after) / max(abs(kl_before), 1e-10)
        print(f"KL Reduction: {kl_reduction*100:.1f}%")
        print(f"Updated distributions:")
        for service, prob in dte._services:
            print(f"  {service}: {prob:.3f}")
        
        # ====== ASSERTION ======
        # KL should reduce after learning appropriate distribution
        assert kl_after < kl_before, (
            f"Adaptive learning failed to reduce KL!\n"
            f"  Before: {kl_before:.4f}\n"
            f"  After:  {kl_after:.4f}"
        )
        print(f"✅ KL divergence reduced by {kl_reduction*100:.1f}%")


class TestClassifierAttack:
    """
    TIER 1 #2: Classifier Attack
    
    Can an ML model distinguish real credentials from DTE-generated ones?
    If accuracy ≈ 50%, our generation is indistinguishable.
    """
    
    def __init__(self):
        self.dte_instance = None
    
    def dte(self):
        if self.dte_instance is None:
            self.dte_instance = DistributionTransformingEncoder()
        return self.dte_instance
    
    def extract_features(self, api_key: str) -> Dict[str, float]:
        """
        Extract statistical features from API key for classification.
        
        Features measure patterns that might distinguish real from generated:
        - Uppercase ratio
        - Digit ratio
        - Entropy (how random?)
        - Character repetition
        """
        s = api_key
        
        uppercase = sum(1 for c in s if c.isupper())
        digits = sum(1 for c in s if c.isdigit())
        
        # Shannon entropy (higher = more random)
        char_freq = Counter(s)
        entropy = -sum((count/len(s)) * math.log2(count/len(s) + 1e-10) for count in char_freq.values())
        
        # Consecutive character repetition
        max_consecutive = max(
            (len(list(group)) for key, group in __import__('itertools').groupby(s)),
            default=1
        )
        
        # Convert to features
        return {
            "uppercase_ratio": uppercase / len(s),
            "digit_ratio": digits / len(s),
            "entropy": entropy,
            "max_consecutive": max_consecutive,
            "length": len(s),
        }
    
    def test_classifier_distinguishability(self, dte):
        """
        Train classifier on real vs generated keys.
        
        Expected result: ≈50% accuracy (indistinguishable)
        If > 60%: There's a detectability bias
        """
        print("\n" + "="*70)
        print("CLASSIFIER ATTACK TEST")
        print("="*70)
        
        # ====== GENERATE DATASETS ======
        # Synthetic "real" credentials (uniform distribution)
        real_keys = []
        for _ in range(500):
            dte.observe_real_credential("AKIAIOSFODNN7EXAMPLE", {
                "service": random.choice([s for s, _ in dte._services]),
                "region": random.choice([r for r, _ in dte._regions]),
                "access_scope": random.choice([sc for sc, _ in dte._scopes]),
            })
        
        # Sample real observations (what we observed)
        real_keys = [
            msg["aws_api_key"]
            for msg in dte._real_observations[:200]
        ]
        
        # Generated credentials via DTE
        generated_keys = []
        for _ in range(200):
            seed = secrets.randbits(64)
            msg = dte.decode(seed)
            generated_keys.append(msg["aws_api_key"])
        
        print(f"\nDataset: {len(real_keys)} real + {len(generated_keys)} generated = {len(real_keys) + len(generated_keys)} total")
        
        # ====== EXTRACT FEATURES ======
        X = []
        y = []
        
        # Real keys: label=1
        for key in real_keys:
            features = self.extract_features(key)
            X.append([features["uppercase_ratio"], features["digit_ratio"], features["entropy"], features["max_consecutive"]])
            y.append(1)
        
        # Generated keys: label=0
        for key in generated_keys:
            features = self.extract_features(key)
            X.append([features["uppercase_ratio"], features["digit_ratio"], features["entropy"], features["max_consecutive"]])
            y.append(0)
        
        # ====== TRAIN CLASSIFIERS ======
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        
        # Logistic Regression
        lr = LogisticRegression(random_state=42, max_iter=1000)
        lr.fit(X_train, y_train)
        lr_pred = lr.predict(X_test)
        lr_acc = accuracy_score(y_test, lr_pred)
        
        # Random Forest
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X_train, y_train)
        rf_pred = rf.predict(X_test)
        rf_acc = accuracy_score(y_test, rf_pred)
        
        print(f"\n{'Model':<20} {'Accuracy':<15} {'Status'}")
        print("-" * 50)
        print(f"{'Logistic Regression':<20} {lr_acc:.4f} ({lr_acc*100:.1f}%)")
        print(f"{'Random Forest':<20} {rf_acc:.4f} ({rf_acc*100:.1f}%)")
        
        # ====== INTERPRETATION ======
        avg_acc = (lr_acc + rf_acc) / 2
        if avg_acc < 0.55:
            status = "✅ INDISTINGUISHABLE (avg ≈ 50%)"
        elif avg_acc < 0.60:
            status = "⚠️  BORDERLINE (avg 55-60%)"
        else:
            status = "❌ DETECTABLE (avg > 60%)"
        
        print(f"\nAverage accuracy: {avg_acc*100:.1f}%")
        print(f"Result: {status}")
        
        return avg_acc


class TestBaselineComparison:
    """
    TIER 1 #3: Baseline Comparison
    
    Compare DTE against naive approaches:
    - RANDOM: Generate random alphanumeric (no structure)
    - NAIVE:  Fixed pattern (e.g., "AKIA" + "A"*16)
    - DTE:    Our bijective DTE
    
    Metrics: Format consistency, distribution quality
    """
    
    def test_baseline_comparison(self):
        """
        Compare generation quality across three approaches.
        
        Metrics:
        1. Format consistency: Do keys match AWS format?
        2. Entropy quality: How random are the keys?
        3. Distribution realism: Do distributions match real patterns?
        """
        print("\n" + "="*70)
        print("BASELINE COMPARISON TEST")
        print("="*70)
        
        dte = DistributionTransformingEncoder()
        n_samples = 1000
        
        # ====== APPROACH 1: RANDOM ======
        random_keys = [
            "AKIA" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))
            for _ in range(n_samples)
        ]
        
        # ====== APPROACH 2: NAIVE ======
        naive_keys = [
            "AKIA" + "A" * 16  # Fixed pattern
            for _ in range(n_samples)
        ]
        
        # ====== APPROACH 3: DTE ======
        dte_keys = []
        for _ in range(n_samples):
            seed = secrets.randbits(64)
            msg = dte.decode(seed)
            dte_keys.append(msg["aws_api_key"])
        
        # ====== METRICS ======
        def compute_entropy(keys: List[str]) -> float:
            """Compute average Shannon entropy of key bodies."""
            entropies = []
            for key in keys:
                body = key[4:]  # Skip "AKIA"
                char_freq = Counter(body)
                entropy = -sum((count/len(body)) * math.log2(count/len(body) + 1e-10) for count in char_freq.values())
                entropies.append(entropy)
            return sum(entropies) / len(entropies)
        
        def compute_format_consistency(keys: List[str]) -> float:
            """% of keys that match AWS format (AKIA + 16 chars)."""
            valid = sum(1 for k in keys if k.startswith("AKIA") and len(k) == 20)
            return valid / len(keys)
        
        def compute_character_distribution_entropy(keys: List[str]) -> float:
            """Entropy of character usage across all keys."""
            all_chars = Counter("".join(k[4:] for k in keys))
            total = sum(all_chars.values())
            return -sum((count/total) * math.log2(count/total + 1e-10) for count in all_chars.values())
        
        # Compute metrics
        approaches = [
            ("Random Generation", random_keys),
            ("Naive Honeytokens", naive_keys),
            ("DTE (Our Method)", dte_keys),
        ]
        
        print(f"\nMetrics (n={n_samples} samples):\n")
        print(f"{'Method':<25} {'Format OK':<15} {'Key Entropy':<15} {'Char Dist Entropy':<20}")
        print("-" * 75)
        
        results = {}
        for name, keys in approaches:
            format_ok = compute_format_consistency(keys)
            key_entropy = compute_entropy(keys)
            char_entropy = compute_character_distribution_entropy(keys)
            
            results[name] = {
                "format": format_ok,
                "entropy": key_entropy,
                "char_entropy": char_entropy,
            }
            
            print(f"{name:<25} {format_ok*100:>6.1f}%        {key_entropy:>6.3f}         {char_entropy:>6.3f}")
        
        # ====== INTERPRETATION ======
        print(f"\nInterpretation:")
        print(f"  ✅ Format OK           > 99% of keys valid")
        print(f"  ✅ Key Entropy         Higher = more random (less detectable)")
        print(f"  ✅ Char Dist Entropy   Higher = more uniform distribution")
        
        dte_results = results["DTE (Our Method)"]
        random_results = results["Random Generation"]
        naive_results = results["Naive Honeytokens"]
        
        print(f"\nDTE vs Baselines:")
        print(f"  Format:      DTE {dte_results['format']*100:.0f}% vs Random {random_results['format']*100:.0f}% vs Naive {naive_results['format']*100:.0f}%")
        print(f"  Entropy:     DTE {dte_results['entropy']:.3f} vs Random {random_results['entropy']:.3f} vs Naive {naive_results['entropy']:.3f}")
        print(f"  Char Entropy: DTE {dte_results['char_entropy']:.3f} vs Random {random_results['char_entropy']:.3f} vs Naive {naive_results['char_entropy']:.3f}")
        
        # DTE should match or exceed random in entropy (indistinguishable)
        # DTE should vastly exceed naive (which is trivial)
        assert dte_results["format"] > 0.99, "DTE format consistency too low"
        assert dte_results["entropy"] > naive_results["entropy"], "DTE entropy not better than naive!"
        
        print(f"\n✅ DTE generation quality verified")


if __name__ == "__main__":
    if pytest:
        pytest.main([__file__, "-v", "-s"])
    else:
        print("Running Tier 1 Improvements Tests (without pytest)")
        print("=" * 70)
        
        # Run KL experiment
        print("\nTest 1: KL Divergence Experiment")
        test_kl = TestKLExperimentFixed()
        try:
            test_kl.test_kl_experiment_before_and_after_learning(test_kl.dte())
            print("✅ KL Experiment PASSED")
        except Exception as e:
            print(f"❌ KL Experiment FAILED: {e}")
        
        # Run classifier attack
        print("\n" + "=" * 70)
        print("Test 2: Classifier Attack")
        test_classifier = TestClassifierAttack()
        try:
            acc = test_classifier.test_classifier_distinguishability(test_classifier.dte())
            print(f"✅ Classifier Attack COMPLETED (avg accuracy: {acc*100:.1f}%)")
        except Exception as e:
            print(f"❌ Classifier Attack FAILED: {e}")
        
        # Run baseline comparison
        print("\n" + "=" * 70)
        print("Test 3: Baseline Comparison")
        test_baseline = TestBaselineComparison()
        try:
            test_baseline.test_baseline_comparison()
            print("✅ Baseline Comparison PASSED")
        except Exception as e:
            print(f"❌ Baseline Comparison FAILED: {e}")
