"""
online_learning.py  –  Online learning loop (Figure 2, 3, Section IV-B).

Thresholds:
  p = cti_update_threshold   → trigger CTI model partial_fit
  q = ids_update_threshold   → trigger IDS model partial_fit  (optimal = 224, Fig 14)
"""
import numpy as np
from typing import Optional, List, Callable
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.api.virustotal_api import VirusTotalAPI
from src.utils.logger import get_logger, load_config
from src.utils.metrics import MetricsTracker
logger = get_logger(__name__)

import time

cfg    = load_config()
vt_api = VirusTotalAPI(cfg)


class OnlineLearningController:
    """Controls the DICI online-learning feedback loop."""
    def __init__(self, ids_model, cti_model, config=None):
        self.cfg = config or load_config()
        ol = self.cfg["online_learning"]
        self.ids_model = ids_model
        self.cti_model = cti_model
        self.p = ol["cti_update_threshold"]
        self.q = ol["ids_update_threshold"]
        self.n_epochs = ol["n_epochs"]
        self._cti_X: List[np.ndarray] = []
        self._cti_y: List[int] = []
        self._ids_X: List[np.ndarray] = []
        self._ids_y: List[int] = []
        self.tracker   = MetricsTracker()
        self.iteration = 0

    def add_cti_report(self, X, y):
        self._cti_X.append(X); self._cti_y.append(y)
        if len(self._cti_X) >= self.p:
            self._update_cti()

    def add_sighting(self, X, y):
        self._ids_X.append(X); self._ids_y.append(y)
        if len(self._ids_X) >= self.q:
            self._update_ids()

    def _update_cti(self):
        X = np.vstack(self._cti_X); y = np.array(self._cti_y)
        self.cti_model.partial_fit(X, y)
        self._cti_X.clear(); self._cti_y.clear()

    def _update_ids(self):
        X = np.vstack(self._ids_X); y = np.array(self._ids_y)
        for _ in range(self.n_epochs):
            self.ids_model.partial_fit(X, y)
        self._ids_X.clear(); self._ids_y.clear()
        self.iteration += 1

    def run_simulation(self, X_stream, y_stream, X_cti, y_cti, X_test, y_test, n_iterations=21):
        logger.info(f"[OnlineLearning] Starting {n_iterations} iterations.")
        # Iteration 0 baseline
        m0 = self.ids_model.evaluate(X_test, y_test, label="IDS (no CTI)")
        self.tracker.update(0, m0)

        idx = np.random.permutation(len(X_stream))
        X_stream, y_stream = X_stream[idx], y_stream[idx]
        chunk = max(1, len(X_stream) // n_iterations)

        for it in range(1, n_iterations + 1):
            s, e = (it-1)*chunk, min(it*chunk, len(X_stream))
            Xb, yb = X_stream[s:e], y_stream[s:e]
            if len(Xb) == 0: break

            preds     = self.ids_model.predict(Xb)
            out_mask  = preds == 2
            out_X     = Xb[out_mask]

            if len(out_X) > 0:
                ci = np.random.choice(len(X_cti), size=min(len(out_X), len(X_cti)), replace=False)
                Xcs, ycs = X_cti[ci], y_cti[ci]
                cti_preds = self.cti_model.predict(Xcs)
                for i, (xc, yc) in enumerate(zip(Xcs, cti_preds)):
                    self.add_cti_report(xc.reshape(1,-1), int(yc))
                for i, (xo, yo) in enumerate(zip(out_X, yb[out_mask])):
                    vl = int(cti_preds[i % len(cti_preds)]) if len(cti_preds) > 0 else int(yo)
                    self.add_sighting(xo.reshape(1,-1), vl)

            if self._ids_X: self._update_ids()
            if self._cti_X: self._update_cti()

            m = self.ids_model.evaluate(X_test, y_test, label=f"IDS+CTI iter={it}")
            self.tracker.update(it, m)
            logger.info(f"[Iter {it:02d}] F1={m['f1']:.2f}%")

        logger.info(f"[OnlineLearning] Done. Best F1={self.tracker.best_f1():.2f}%")
        return self.tracker


    def run_simulation_virustotal_api(self, X_stream, y_stream, X_cti, y_cti, X_test, y_test, ip_stream, src_ips_tr, src_ips_te, n_iterations=21):
        logger.info(f"[OnlineLearning] Starting {n_iterations} iterations with VirusTotal.")
        
        # Iteration 0 baseline
        m0 = self.ids_model.evaluate(X_test, y_test, label="IDS (no CTI)")
        self.tracker.update(0, m0)

        idx = np.random.permutation(len(X_stream))
        X_stream, y_stream, ip_stream = X_stream[idx], y_stream[idx], ip_stream[idx]
        chunk = max(1, len(X_stream) // n_iterations)
        seen_ips = {}


        for it in range(1, n_iterations + 1):
            s, e = (it-1)*chunk, min(it*chunk, len(X_stream))
            Xb, yb, ipx = X_stream[s:e], y_stream[s:e], ip_stream[s:e]
            if len(Xb) == 0: break

            preds     = self.ids_model.predict(Xb)
            out_mask  = preds == 2 # Outlier detected
            out_X     = Xb[out_mask]
            out_ips   = ipx[out_mask]

            if len(out_X) > 0:
                # We will gather VirusTotal predictions for the outliers
                cti_preds = []
                
                # --- VIRUSTOTAL INTEGRATION BLOCK ---
                for i, io in enumerate(out_ips):
                    # IMPORTANT: 'xo' must contain the src_ip or you must have a way 
                    # to map this feature row back to its original IP address.
                    # Assuming your preprocessing keeps src_ip as the last column or similar:
                    # ip_to_check = get_ip_from_features(xo) 
                    
                    # For this example, we call your existing lookup function
                    if io in seen_ips.keys():
                        logger.info(f"Querying VirusTotal {io}")
                        cti_preds.append(seen_ips[io])
                    else:
                        try:
                            # vt_data is the JSON response from your cti_lookup(ip) function
                            logger.info(f"Querying VirusTotal {io}")
                            vt_data = vt_api.lookup_ip(io) # Replace with actual IP extraction logic
                            
                            # Logic: If malicious_count > 0, label as 1 (Malicious), else 0 (Benign)
                            verdict = 1 if vt_data.get("malicious_count", 0) > 0 else 0
                            cti_preds.append(verdict)
                            
                            # RATE LIMIT HANDLING: VT Free Tier allows 4 requests/min (1 every 15s)
                            # If you have many outliers, this sleep is necessary.
                            time.sleep(15) 
                            seen_ips[io] = verdict
                        except Exception as e:
                            logger.error(f"VT Lookup failed for {io}: {e}")
                            cti_preds.append(int(yb[out_mask][i])) # Fallback to original label
                # -------------------------------------

                # Add to buffers for partial_fit
                for i, (xo, label) in enumerate(zip(out_X, cti_preds)):
                    # We add the sighting to the IDS buffer using the VT verdict
                    self.add_sighting(xo.reshape(1,-1), int(label))

            # Perform the actual reinforcement training
            if self._ids_X: self._update_ids()
            
            # Evaluate how much the IDS improved after learning from VirusTotal
            m = self.ids_model.evaluate(X_test, y_test, label=f"IDS+VT iter={it}")
            self.tracker.update(it, m)
            logger.info(f"[Iter {it:02d}] F1={m['f1']:.2f}%")

        logger.info(f"[OnlineLearning] Done. Best F1={self.tracker.best_f1():.2f}%")
        return self.tracker

def simulate_batch_experiment(ids_model, X_train, y_train, X_test, y_test,
                               batch_sizes=None, epoch_list=None):
    """
    Reproduce Figures 14 & 15: F1 and loss vs batch_size × epochs.
    Paper finding: optimal batch_size = 224.
    """
    import copy
    # batch_sizes = batch_sizes or [32,64,96,128,160,192,224,256,288]
    # epoch_list  = epoch_list  or [2,4,6,8,10]

    batch_sizes = batch_sizes or [100000]
    epoch_list  = epoch_list  or [2,4,6,8]

    results = {}
    for bs in batch_sizes:
        for ep in epoch_list:
            m = copy.deepcopy(ids_model)
            n_batches = max(1, len(X_train) // bs)
            for e in range(ep):
                idx = np.random.permutation(len(X_train))
                for b in range(n_batches):
                    sl = idx[b*bs:(b+1)*bs]
                    if len(sl) > 0:
                        m.partial_fit(X_train[sl], y_train[sl])
            met = m.evaluate(X_test, y_test, label=f"bs={bs}_ep={ep}")
            results[(bs,ep)] = {"f1": met["f1"], "loss": 100.0 - met["f1"]}
    return results
