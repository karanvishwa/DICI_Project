"""
rule_based.py  –  Rule-based CTI baseline (Section VI-D).
Paper: KMeans++ achieves +30.92% F1 over this rule-based approach.
Rules derived from VirusTotal report features (expert insights).
"""
import numpy as np, pandas as pd
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logger import get_logger, load_config
from src.utils.metrics import compute_metrics
logger = get_logger(__name__)


class RuleBasedCTIClassifier:
    """Predefined heuristic rules applied uniformly across all CTI reports.
    Consistent, transparent, replicable (Section VI-D of paper).
    """
    DEFAULT_RULES = {
        "malicious_count":   3,     # stat_malicious > 3
        "malicious_ratio":   0.10,  # ratio_malicious > 10%
        "reputation":       -1,     # reputation < -1
        "votes_malicious":   2,     # votes_malicious > 2
        "suspicious_count":  5,     # stat_suspicious > 5
    }

    def __init__(self, rules=None, feature_names=None):
        self.rules = {**self.DEFAULT_RULES, **(rules or {})}
        self.feature_names = feature_names or []
        logger.info(f"[RuleBased] Thresholds: {self.rules}")

    def predict(self, X):
        X = np.asarray(X)
        preds = np.zeros(len(X), dtype=int)
        fn    = self.feature_names

        def col(name):
            return X[:, fn.index(name)] if name in fn else None

        for name, thr, op in [
            ("stat_malicious",   self.rules["malicious_count"],  "gt"),
            ("ratio_malicious",  self.rules["malicious_ratio"],  "gt"),
            ("reputation",       self.rules["reputation"],       "lt"),
            ("votes_malicious",  self.rules["votes_malicious"],  "gt"),
            ("stat_suspicious",  self.rules["suspicious_count"], "gt"),
        ]:
            c = col(name)
            if c is not None:
                preds[c > thr if op == "gt" else c < thr] = 1
        return preds

    def evaluate(self, X, y, label="RuleBased"):
        return compute_metrics(y, self.predict(X), average="binary", label=label)


def compare_ml_vs_rulebased(X_train, y_train, X_test, y_test,
                              feature_names=None, config=None) -> Tuple[dict, dict, dict]:
    """Run KMeans++ vs Rule-based comparison. Returns (km_metrics, rb_metrics, improvement)."""
    from src.cti_transfer.cti_transfer_model import CTITransferModel
    km = CTITransferModel(config=config)
    km.fit(X_train, y_train)
    km_m = km.evaluate(X_test, y_test, label="KMeans++")
    rb   = RuleBasedCTIClassifier(feature_names=feature_names)
    rb_m = rb.evaluate(X_test, y_test, label="RuleBased")
    imp  = {
        "f1_improvement":        km_m["f1"]        - rb_m["f1"],
        "precision_improvement": km_m["precision"] - rb_m["precision"],
        "recall_improvement":    km_m["recall"]    - rb_m["recall"],
    }
    logger.info(f"[Compare] KMeans++ F1={km_m['f1']:.2f}% vs RuleBased F1={rb_m['f1']:.2f}%  Δ={imp['f1_improvement']:.2f}%")
    return km_m, rb_m, imp
