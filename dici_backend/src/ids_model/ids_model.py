"""
ids_model.py  –  Hybrid IDS Model (Figure 4 of paper).

Decision logic:
  S1=SVM result, S2=KMeans result
  S1=0 & S2=0  → Benign    (0)
  S1=1 & S2=1  → Malicious (1)
  S1=1 & S2=0  → Malicious (1)  ← SVM trusted
  S1=0 & S2=1  → Outlier   (2)  ← CTI lookup needed

Hyperparameters from Table 6:
  SVM:    alpha=0.1, loss='hinge', random_state=456
  KMeans: n_clusters=2, random_state=42, max_iter=100
"""
import numpy as np, joblib
from pathlib import Path
from typing import Optional
from sklearn.linear_model import SGDClassifier
from sklearn.cluster import MiniBatchKMeans
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logger import get_logger, load_config
from src.utils.metrics import compute_metrics, compute_false_rates
logger = get_logger(__name__)


class OnlineSVM:
    """SGDClassifier (hinge loss) ≡ linear SVM, supports partial_fit for online learning."""
    def __init__(self, config=None):
        cfg = (config or load_config())["ids_model"]["svm"]
        self.clf = SGDClassifier(
            loss=cfg["loss"], alpha=cfg["alpha"], penalty="l2",
            random_state=cfg["random_state"], max_iter=cfg.get("max_iter",1000),
            tol=1e-3, class_weight="balanced",
        )
        self.classes_ = np.array([0, 1])
        self._fitted  = False

    def fit(self, X, y):
        y_bin = np.where(y == 2, 0, y)
        self.clf.fit(X, y_bin)
        self._fitted = True
        logger.info("[SVM] Initial training complete.")
        return self

    def partial_fit(self, X, y):
        y_bin = np.where(y == 2, 0, y)
        unique = np.unique(y_bin)
        if len(unique) < 2:
            missing = set([0,1]) - set(unique)
            for m in missing:
                X = np.vstack([X, X[:1]])
                y_bin = np.append(y_bin, m)
        self.clf.partial_fit(X, y_bin, classes=self.classes_)
        self._fitted = True
        return self

    def predict(self, X):
        if not self._fitted: raise RuntimeError("SVM not fitted.")
        return self.clf.predict(X)

    def false_rates(self, X, y):
        preds = self.predict(X)
        y_bin = np.where(y == 2, 0, y)
        return compute_false_rates(y_bin, preds)


class IDSKMeans:
    """MiniBatchKMeans for online anomaly detection.
    Maps cluster with highest malicious-sample ratio → malicious label.
    """
    def __init__(self, config=None):
        cfg = (config or load_config())["ids_model"]["kmeans"]
        self.model = MiniBatchKMeans(
            n_clusters=cfg["n_clusters"], random_state=cfg["random_state"],
            max_iter=cfg["max_iter"], n_init=3,
        )
        self._fitted = False
        self._mal_cluster: Optional[int] = None

    def fit(self, X, y):
        self.model.fit(X)
        self._mal_cluster = self._find_mal(X, y)
        self._fitted = True
        logger.info(f"[KMeans] Fitted. Malicious cluster={self._mal_cluster}")
        return self

    def partial_fit(self, X, y):
        self.model.partial_fit(X)
        self._mal_cluster = self._find_mal(X, y)
        self._fitted = True
        return self

    def predict(self, X):
        if not self._fitted: raise RuntimeError("KMeans not fitted.")
        raw = self.model.predict(X)
        return (raw == self._mal_cluster).astype(int)

    def _find_mal(self, X, y):
        raw   = self.model.predict(X)
        y_bin = np.where(y == 2, 0, y)
        best, best_r = 0, -1.0
        for c in range(self.model.n_clusters):
            mask = raw == c
            if mask.sum() == 0: continue
            r = y_bin[mask].mean()
            if r > best_r: best_r, best = r, c
        return best

    def false_rates(self, X, y):
        preds = self.predict(X)
        y_bin = np.where(y == 2, 0, y)
        return compute_false_rates(y_bin, preds)


class HybridIDSModel:
    """Hybrid IDS = OnlineSVM + IDSKMeans (Figure 4)."""
    BENIGN, MALICIOUS, OUTLIER = 0, 1, 2

    def __init__(self, config=None):
        self.cfg    = config or load_config()
        self.svm    = OnlineSVM(config=self.cfg)
        self.kmeans = IDSKMeans(config=self.cfg)
        self._fitted = False

    def fit(self, X, y):
        logger.info(f"[HybridIDS] fit() on {len(X)} samples.")
        self.svm.fit(X, y);  self.kmeans.fit(X, y)
        self._fitted = True;  return self

    def partial_fit(self, X, y):
        logger.info(f"[HybridIDS] partial_fit() on {len(X)} samples.")
        self.svm.partial_fit(X, y);  self.kmeans.partial_fit(X, y)
        return self

    def predict(self, X):
        S1 = self.svm.predict(X)
        S2 = self.kmeans.predict(X)
        y  = np.full(len(X), self.BENIGN, dtype=int)
        y[(S1==1) & (S2==1)] = self.MALICIOUS
        y[(S1==1) & (S2==0)] = self.MALICIOUS
        y[(S1==0) & (S2==1)] = self.OUTLIER
        return y

    def get_outlier_indices(self, X):
        return np.where(self.predict(X) == self.OUTLIER)[0]

    def evaluate(self, X, y, label="IDS"):
        preds     = self.predict(X)
        y_eval    = np.where(y==2, 0, y)
        pred_eval = np.where(preds==2, 0, preds)
        m  = compute_metrics(y_eval, pred_eval, average="binary", label=label)
        fr = compute_false_rates(y_eval, pred_eval)
        m.update(fr)
        svm_fr = self.svm.false_rates(X, y)
        km_fr  = self.kmeans.false_rates(X, y)
        m["svm_fpr"]    = svm_fr["fpr"];  m["svm_fnr"]    = svm_fr["fnr"]
        m["kmeans_fpr"] = km_fr["fpr"];   m["kmeans_fnr"] = km_fr["fnr"]
        return m

    def save(self, path=None):
        p = path or self.cfg["ids_model"]["model_save_path"]
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, p)

    @classmethod
    def load(cls, path):
        return joblib.load(path)
