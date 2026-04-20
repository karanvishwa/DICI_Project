"""
cti_transfer_model.py  –  KMeans++ CTI Transfer Model (Section IV-B).

Why KMeans++ (not KMeans)?
  Model starts with empty dataset and progressively learns.
  KMeans++ proper centroid initialisation is critical for this.
  KMeans++ → +30.92% F1 over rule-based (Figure 13).

Hyperparameters Table 6: n_clusters=2, random_state=42, init='k-means++'
"""
import numpy as np, joblib
from pathlib import Path
from typing import Optional
from sklearn.cluster import MiniBatchKMeans
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logger import get_logger, load_config
from src.utils.metrics import compute_metrics
logger = get_logger(__name__)


class CTITransferModel:
    BENIGN, MALICIOUS = 0, 1

    def __init__(self, config=None):
        cfg = (config or load_config())["cti_transfer_model"]["kmeanspp"]
        self.model = MiniBatchKMeans(
            n_clusters=cfg["n_clusters"], init=cfg["init"],
            random_state=cfg["random_state"], max_iter=cfg.get("max_iter",300), n_init=5,
        )
        self._fitted = False
        self._mal_cluster: Optional[int] = None

    def fit(self, X, y):
        logger.info(f"[CTITransfer] fit() on {len(X)} CTI samples.")
        self.model.fit(X)
        self._mal_cluster = self._find_mal(X, y)
        self._fitted = True
        return self

    def partial_fit(self, X, y=None):
        self.model.partial_fit(X)
        if y is not None and len(y) == len(X):
            self._mal_cluster = self._find_mal(X, y)
        elif self._mal_cluster is None:
            self._mal_cluster = 1
        self._fitted = True
        return self

    def predict(self, X):
        if not self._fitted:
            self.model.fit(X); self._mal_cluster = 1; self._fitted = True
        return (self.model.predict(X) == self._mal_cluster).astype(int)

    def predict_proba(self, X):
        if not self._fitted:
            self.model.fit(X); self._mal_cluster = 1; self._fitted = True
        dist = self.model.transform(X)
        sim  = 1.0 / (dist + 1e-9)
        prob = sim / sim.sum(axis=1, keepdims=True)
        mc   = self._mal_cluster or 1
        p_m  = prob[:, mc].reshape(-1, 1)
        return np.hstack([1-p_m, p_m])

    def evaluate(self, X, y, label="CTI"):
        return compute_metrics(y, self.predict(X), average="binary", label=label)

    def _find_mal(self, X, y):
        raw = self.model.predict(X)
        best, best_r = 0, -1.0
        for c in range(self.model.n_clusters):
            mask = raw == c
            if mask.sum() == 0: continue
            r = y[mask].mean()
            if r > best_r: best_r, best = r, c
        return best

    def save(self, path=None):
        cfg = load_config()
        p   = path or cfg["cti_transfer_model"]["model_save_path"]
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, p)

    @classmethod
    def load(cls, path):
        return joblib.load(path)


def evaluate_feature_count_impact(X_train, y_train, X_test, y_test,
                                   config=None, feature_counts=None):
    """Reproduce Figure 13: F1 vs number of CTI features."""
    n_total = X_train.shape[1]
    feature_counts = feature_counts or list(range(5, min(n_total+1, 111), 10))
    results = {}
    for n in feature_counts:
        n   = min(n, n_total)
        idx = np.argsort(np.var(X_train, axis=0))[::-1][:n]
        m   = CTITransferModel(config=config)
        m.fit(X_train[:, idx], y_train)
        met = m.evaluate(X_test[:, idx], y_test, label=f"n={n}")
        results[n] = met["f1"]
    return results
