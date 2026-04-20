"""
data_preprocessing.py  –  Full preprocessing for Sighting & CTI datasets.
Paper Section V-D: drop metadata, impute, one-hot encode, standardise, undersample.
"""
import os, numpy as np, pandas as pd
from pathlib import Path
from typing import Tuple, Optional, List
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

try:
    from imblearn.under_sampling import RandomUnderSampler
    _IMBLEARN = True
except ImportError:
    _IMBLEARN = False

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logger import get_logger, load_config
logger = get_logger(__name__)


class SightingPreprocessor:
    """Preprocess network-traffic sighting dataset.
    Labels: 0=benign, 1=malicious, 2=outlier  (y^S in paper)
    """
    def __init__(self, config=None):
        cfg = config or load_config()
        pp  = cfg["preprocessing"]
        self.drop_features = pp["drop_features"]
        self.cat_features   = pp["categorical_features"]
        self.label_col      = pp["sighting_label_col"]
        self.test_size      = pp["test_size"]
        self.random_state   = pp["random_state"]
        self.missing_thr    = pp["missing_threshold"]
        self.sampling_strat = pp["sampling_strategy"]
        self.scaler  = StandardScaler()
        self.imputer = SimpleImputer(strategy="mean")
        self.feature_names_: Optional[List[str]] = None

    def fit_transform(self, df):
        df = self._clean(df);  X, y = self._encode(df)
        X  = self._impute_scale(X, fit=True)
        X, y = self._balance(X, y)
        return train_test_split(X, y, test_size=self.test_size, random_state=self.random_state, stratify=y)

    def transform(self, df):
        df = self._clean(df);  X, y = self._encode(df)
        return self._impute_scale(X, fit=False), y

    def _clean(self, df):
        df = df.drop(columns=[c for c in self.drop_features if c in df.columns], errors="ignore")
        thresh = int(self.missing_thr * df.shape[1])
        return df.dropna(thresh=thresh)

    def _encode(self, df):
        y  = df[self.label_col].values.astype(int) if self.label_col in df.columns else np.zeros(len(df), dtype=int)
        df = df.drop(columns=[self.label_col], errors="ignore")
        cats = [c for c in self.cat_features if c in df.columns]
        if cats:
            df = pd.get_dummies(df, columns=cats)
        self.feature_names_ = list(df.columns)
        return df, y

    def _impute_scale(self, X, fit=True):
        if isinstance(X, pd.DataFrame): X = X.values.astype(float)
        if fit:
            X = self.imputer.fit_transform(X)
            X = self.scaler.fit_transform(X)
        else:
            X = self.imputer.transform(X)
            X = self.scaler.transform(X)
        return X

    def _balance(self, X, y):
        if len(np.unique(y)) < 2 or not _IMBLEARN:
            if not _IMBLEARN:
                logger.warning("[Sighting] imblearn not found – skipping undersampling.")
            return X, y
        rus = RandomUnderSampler(sampling_strategy=self.sampling_strat, random_state=self.random_state)
        X_r, y_r = rus.fit_resample(X, y)
        logger.info(f"[Sighting] After undersampling: {X_r.shape}")
        return X_r, y_r


class CTIPreprocessor:
    """Preprocess VirusTotal CTI reports.
    Labels: 0=benign, 1=malicious  (y^C in paper)
    Paper uses 105 features from each report.
    """
    def __init__(self, config=None):
        cfg = config or load_config()
        pp  = cfg["preprocessing"]
        self.label_col   = pp["cti_label_col"]
        self.test_size   = pp["test_size"]
        self.random_state= pp["random_state"]
        self.missing_thr = pp["missing_threshold"]
        self.sampling_strat = pp["sampling_strategy"]
        self.n_features  = cfg["cti_transfer_model"]["n_features"]
        self.scaler  = StandardScaler()
        self.imputer = SimpleImputer(strategy="mean")
        self.feature_names_: Optional[List[str]] = None

    def fit_transform(self, df):
        df = self._clean(df);  X, y = self._encode(df)
        X  = self._impute_scale(X, fit=True)
        X, y = self._balance(X, y)
        return train_test_split(X, y, test_size=self.test_size, random_state=self.random_state)

    def transform(self, df):
        df = self._clean(df);  X, y = self._encode(df)
        return self._impute_scale(X, fit=False), y

    def _clean(self, df):
        thresh = int(self.missing_thr * df.shape[1])
        return df.dropna(thresh=thresh)

    def _encode(self, df):
        y  = df[self.label_col].values.astype(int) if self.label_col in df.columns else np.zeros(len(df), dtype=int)
        df = df.drop(columns=[c for c in [self.label_col,"ip","src_ip","dest_ip"] if c in df.columns], errors="ignore")
        obj_cols = df.select_dtypes(include="object").columns.tolist()
        if obj_cols:
            df = pd.get_dummies(df, columns=obj_cols)
        if df.shape[1] > self.n_features:
            top = df.var(numeric_only=True).nlargest(self.n_features).index.tolist()
            df  = df[top]
        self.feature_names_ = list(df.columns)
        return df, y

    def _impute_scale(self, X, fit=True):
        if isinstance(X, pd.DataFrame): X = X.values.astype(float)
        if fit:
            X = self.imputer.fit_transform(X)
            X = self.scaler.fit_transform(X)
        else:
            X = self.imputer.transform(X)
            X = self.scaler.transform(X)
        return X

    def _balance(self, X, y):
        if len(np.unique(y)) < 2 or not _IMBLEARN:
            return X, y
        rus = RandomUnderSampler(sampling_strategy=self.sampling_strat, random_state=self.random_state)
        X_r, y_r = rus.fit_resample(X, y)
        return X_r, y_r


def load_csv_safe(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found: {path}")
    df = pd.read_csv(path)
    logger.info(f"Loaded {path}: {df.shape}")
    return df


def filter_sighting_by_type(X, y, sighting_type="outlier"):
    """
    Filter by type for CTI Transfer Model training.
    Paper finding (Fig 8): 'outlier' achieves best F1 = 89.52%
    """
    type_map = {
        "benign":            [0],
        "malicious":         [1],
        "outlier":           [2],
        "benign_malicious":  [0, 1],
        "benign_outlier":    [0, 2],
        "malicious_outlier": [1, 2],
        "all":               [0, 1, 2],
    }
    mask = np.isin(y, type_map.get(sighting_type, [2]))
    logger.info(f"[Filter] type='{sighting_type}' → {mask.sum()}/{len(y)} samples")
    return X[mask], y[mask]
