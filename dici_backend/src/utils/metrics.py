"""
metrics.py  –  Evaluation metrics matching paper Section VI-A.
Primary metric: F1-score (balances precision + recall).
"""
import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score, confusion_matrix, classification_report
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logger import get_logger
logger = get_logger(__name__)


def compute_metrics(y_true, y_pred, average="binary", label=""):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    metrics = {
        "f1":        f1_score(y_true, y_pred, average=average, zero_division=0) * 100,
        "precision": precision_score(y_true, y_pred, average=average, zero_division=0) * 100,
        "recall":    recall_score(y_true, y_pred, average=average, zero_division=0) * 100,
        "accuracy":  accuracy_score(y_true, y_pred) * 100,
    }
    tag = f"[{label}] " if label else ""
    logger.info(f"{tag}F1={metrics['f1']:.2f}%  Prec={metrics['precision']:.2f}%  Rec={metrics['recall']:.2f}%")
    return metrics


def compute_false_rates(y_true, y_pred, malicious_label=1):
    """Paper Section VI-B: SVM FPR=7.70%, FNR=4.95%; KMeans FPR=42.78%, FNR=34.69%"""
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    y_t = (y_true == malicious_label).astype(int)
    y_p = (y_pred == malicious_label).astype(int)
    cm  = confusion_matrix(y_t, y_p, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (cm[0,0], 0, 0, cm[1,1] if cm.shape[0]>1 else 0)
    fpr = fp / max(fp + tn, 1) * 100
    fnr = fn / max(fn + tp, 1) * 100
    return {"fpr": fpr, "fnr": fnr, "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn)}


def print_report(y_true, y_pred, target_names=None):
    names   = target_names or ["Benign", "Malicious", "Outlier"]
    unique  = sorted(set(np.unique(y_true)) | set(np.unique(y_pred)))
    names_f = [names[i] for i in unique if i < len(names)]
    report  = classification_report(y_true, y_pred, labels=unique, target_names=names_f, zero_division=0)
    logger.info(f"\n{report}")
    return report


class MetricsTracker:
    """Track per-iteration metrics. Used to reproduce Figure 6."""
    def __init__(self):
        self.history = {"iteration": [], "f1": [], "precision": [], "recall": [], "accuracy": []}

    def update(self, iteration, metrics):
        self.history["iteration"].append(iteration)
        for k in ["f1", "precision", "recall", "accuracy"]:
            self.history[k].append(metrics.get(k, 0.0))

    def get_dataframe(self):
        import pandas as pd
        return pd.DataFrame(self.history)

    def best_f1(self):
        return max(self.history["f1"]) if self.history["f1"] else 0.0
