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
        df = self._clean(df);  X, y = self._encode(df, is_training=True)
        X  = self._impute_scale(X, fit=True)
        X, y = self._balance(X, y)
        return train_test_split(X, y, test_size=self.test_size, random_state=self.random_state, stratify=y)
    
    def fit_transform_with_ips(self, df, isTraining) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        # 1. Capture the IPs before they get dropped or encoded
        ips = df["src_ip"].values if "src_ip" in df.columns else np.array([None]*len(df))
        
        # Updates the df directly
        df.drop(columns=['src_ip', 'dest_ip'], inplace=True)
        
        # 2. Run the normal pipeline
        df = self._clean(df)
        X_df, y = self._encode(df, is_training=isTraining)
        
        # 3. We must keep 'ips' aligned with 'X_df' after cleaning/encoding
        # If _clean dropped rows, we need to match indices
        ips = ips[df.index] 
        
        X = self._impute_scale(X_df, fit=True)
        
        # 4. Handle Balancing (Undersampling changes the number of rows)
        if hasattr(self, '_balance'):
            X, y, final_indices = self._balance_with_indices(X, y)
            ips = ips[final_indices]

        # 5. Attach IPs back to X (X becomes an object array or a DataFrame)
        # Note: Machine Learning models usually want pure floats, so we often
        # return (X, y, ips) as a triplet instead of merging them.
        X_train, X_test, y_train, y_test, ips_train, ips_test = train_test_split(
            X, y, ips, test_size=self.test_size, random_state=self.random_state, stratify=y
        )
        
        return X_train, X_test, y_train, y_test, ips_train, ips_test

    def _balance_with_indices(self, X, y):
        """Modified balance to return the indices of the rows kept."""
        indices = np.arange(len(y))
        if len(np.unique(y)) < 2 or not _IMBLEARN:
            return X, y, indices
        
        rus = RandomUnderSampler(sampling_strategy=self.sampling_strat, random_state=self.random_state)
        # Resample indices along with data to know which IPs to keep
        X_r, y_r = rus.fit_resample(X, y)
        final_indices = rus.sample_indices_ # imblearn stores the kept indices here
        
        return X_r, y_r, final_indices

    def transform(self, df):
        df = self._clean(df);  X, y = self._encode(df,is_training=False)
        return self._impute_scale(X, fit=False), y

    def _clean(self, df):
        df = df.drop(columns=[c for c in self.drop_features if c in df.columns], errors="ignore")
        thresh = int(self.missing_thr * df.shape[1])
        return df.dropna(thresh=thresh)

    def _encode(self, df, is_training=True):
        y  = df[self.label_col].values.astype(int) if self.label_col in df.columns else np.zeros(len(df), dtype=int)
        df = df.drop(columns=[self.label_col], errors="ignore")

        cats = [c for c in self.cat_features if c in df.columns]

        if cats:
            df = pd.get_dummies(df, columns=cats)

        if is_training:
            self.feature_names_ = list(df.columns)   # lock schema
        else:
             # 🔥 FAST + CORRECT
            df = df.reindex(columns=self.feature_names_, fill_value=0)

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
        self.feature_names_: Optional[List[str]] = None 
        self.encoder_categories_ = None # Store OHE categories here

    def fit_transform(self, df):
        df = self._clean(df);  X, y = self._encode(df,is_training=True)
        X  = self._impute_scale(X, fit=True)
        X, y = self._balance(X, y)
        return train_test_split(X, y, test_size=self.test_size, random_state=self.random_state)

    def transform(self, df):
        df = self._clean(df);  X, y = self._encode(df,is_training=False)
        return self._impute_scale(X, fit=False), y

    def _clean(self, df):
        thresh = int(self.missing_thr * df.shape[1])
        return df.dropna(thresh=thresh)

    def _encode(self, df, is_training=False):
        y = df[self.label_col].values.astype(int) if self.label_col in df.columns else np.zeros(len(df), dtype=int)

        # 1. Drop labels
        df = df.drop(columns=[c for c in [self.label_col,"ip","src_ip","dest_ip"] if c in df.columns], errors="ignore")


        logger.info(f"Shape is {df.shape}")
        
        # 2. Get dummies (or better: OneHotEncoder)
        # If not training, we must ensure we have the exact columns from training
        if is_training:
            df = pd.get_dummies(df, columns=df.select_dtypes(include="object").columns.tolist())
            self.feature_names_ = list(df.columns) # LOCK IN THE COLUMNS
        else:
            # Inference mode: Encode, but then force the schema
            df = pd.get_dummies(df, columns=df.select_dtypes(include="object").columns.tolist())
            
            # ADD MISSING COLUMNS AS ZEROS
            # This adds columns that existed in training but are missing here
            for col in self.feature_names_:
                if col not in df.columns:
                    df[col] = 0
            
            # REMOVE EXTRA COLUMNS
            # This removes columns that didn't exist in training
            df = df[self.feature_names_] 
            
        logger.info(f"Encoded shape of Y {y.shape}")
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
