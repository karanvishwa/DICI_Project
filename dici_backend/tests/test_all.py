"""
tests/test_all.py
=================
Full test suite for DICI.  Run with:
    python -m pytest tests/test_all.py -v        # if pytest installed
    python tests/test_all.py                     # plain Python
"""
import sys, os, json, copy, unittest, numpy as np, pandas as pd
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.utils.logger import load_config
from src.utils.data_preprocessing import (
    SightingPreprocessor, CTIPreprocessor, filter_sighting_by_type
)
from src.utils.metrics import compute_metrics, compute_false_rates, MetricsTracker
from src.utils.feature_extraction import CTIFeatureExtractor
from src.ids_model.ids_model import OnlineSVM, IDSKMeans, HybridIDSModel
from src.ids_model.online_learning import OnlineLearningController
from src.cti_transfer.cti_transfer_model import CTITransferModel
from src.cti_transfer.rule_based import RuleBasedCTIClassifier, compare_ml_vs_rulebased
from src.api.virustotal_api import VirusTotalAPI

CFG = load_config()
RNG = np.random.default_rng(42)

# ── Shared fixtures ────────────────────────────────────────────────────
def _sighting_df(n=300):
    r = np.random.default_rng(42)
    return pd.DataFrame({
        "duration":              r.uniform(0,100,n),
        "dest_port":             r.integers(1,65535,n),
        "protocol":              r.choice(["TCP","UDP","ICMP"],n),
        "flags":                 r.choice(["......","...A.."],n),
        "forwarding_status":     r.integers(0,3,n),
        "source_type_of_service":r.integers(0,64,n),
        "ingress_packet_count":  r.integers(1,500,n),
        "ingress_byte_count":    r.integers(64,100000,n),
        "time_start":["2023-01-01"]*n,"time_end":["2023-01-01"]*n,
        "src_ip":["1.2.3.4"]*n,"dest_ip":["5.6.7.8"]*n,
        "src_port":r.integers(1024,65535,n),
        "label": r.choice([0,1,2],n),
    })

def _cti_df(n=200):
    r = np.random.default_rng(1)
    df = pd.DataFrame({
        "stat_malicious":   r.integers(0,25,n), "stat_harmless":  r.integers(10,60,n),
        "stat_suspicious":  r.integers(0,10,n), "stat_undetected":r.integers(0,20,n),
        "stat_timeout":     r.integers(0,5,n),  "stat_total":     [80]*n,
        "ratio_malicious":  r.uniform(0,.4,n),  "ratio_harmless": r.uniform(.4,1.,n),
        "ratio_suspicious": r.uniform(0,.15,n), "reputation":     r.integers(-30,10,n),
        "votes_malicious":  r.integers(0,20,n), "votes_harmless": r.integers(0,15,n),
        "whois_length":     r.integers(100,2000,n),"has_whois":    r.integers(0,2,n),
        "n_tags":           r.integers(0,4,n),
        "tag_CDN":r.integers(0,2,n),"tag_proxy":r.integers(0,2,n),
        "tag_tor":r.integers(0,2,n),"tag_vpn":r.integers(0,2,n),
        "tag_scanner":r.integers(0,2,n),
        "asn":r.integers(1000,65535,n),
        "last_analysis_date":r.integers(1690000000,1700000000,n),
        "label":r.choice([0,1],n),
    })
    return df

def _Xy(n=300, n_feat=20, seed=0):
    r = np.random.default_rng(seed)
    X = r.standard_normal((n, n_feat))
    y = r.choice([0,1,2], n, p=[.6,.3,.1])
    return X, y

def _Xyc(n=100, n_feat=15):
    r = np.random.default_rng(1)
    return r.standard_normal((n,n_feat)), r.choice([0,1],n)


# ══════════════════════════════════════════════════════════════════════
class TestSightingPreprocessor(unittest.TestCase):

    def test_shapes_and_no_nan(self):
        df = _sighting_df()
        pp = SightingPreprocessor(config=CFG)
        Xt, Xe, yt, ye = pp.fit_transform(df)
        self.assertEqual(Xt.ndim, 2)
        self.assertFalse(np.any(np.isnan(Xt)))
        self.assertFalse(np.any(np.isnan(Xe)))

    def test_labels_valid(self):
        df = _sighting_df()
        pp = SightingPreprocessor(config=CFG)
        Xt, Xe, yt, ye = pp.fit_transform(df)
        self.assertTrue(set(np.unique(yt)).issubset({0,1,2}))

    def test_filter_outlier(self):
        X = np.ones((30,5)); y = np.array([0]*10+[1]*10+[2]*10)
        Xf, yf = filter_sighting_by_type(X, y, "outlier")
        self.assertEqual(set(np.unique(yf)), {2})

    def test_filter_benign_malicious(self):
        X = np.ones((30,5)); y = np.array([0]*10+[1]*10+[2]*10)
        Xf, yf = filter_sighting_by_type(X, y, "benign_malicious")
        self.assertTrue(set(np.unique(yf)).issubset({0,1}))

    def test_filter_all(self):
        X = np.ones((30,5)); y = np.array([0]*10+[1]*10+[2]*10)
        Xf, yf = filter_sighting_by_type(X, y, "all")
        self.assertEqual(len(Xf), 30)


class TestCTIPreprocessor(unittest.TestCase):

    def test_shapes(self):
        df = _cti_df()
        pp = CTIPreprocessor(config=CFG)
        Xt, Xe, yt, ye = pp.fit_transform(df)
        self.assertEqual(Xt.ndim, 2)
        self.assertEqual(len(yt), len(Xt))

    def test_binary_labels(self):
        df = _cti_df()
        pp = CTIPreprocessor(config=CFG)
        Xt, Xe, yt, ye = pp.fit_transform(df)
        self.assertTrue(set(np.unique(yt)).issubset({0,1}))

    def test_no_nan(self):
        df = _cti_df()
        pp = CTIPreprocessor(config=CFG)
        Xt, Xe, yt, ye = pp.fit_transform(df)
        self.assertFalse(np.any(np.isnan(Xt)))


# ══════════════════════════════════════════════════════════════════════
class TestMetrics(unittest.TestCase):

    def test_perfect_f1(self):
        y = np.array([0,1,0,1,1])
        m = compute_metrics(y, y, average="binary")
        self.assertAlmostEqual(m["f1"], 100.0, places=5)

    def test_false_rates_keys(self):
        y_t = np.array([0,0,1,1,1])
        y_p = np.array([0,1,1,1,0])
        r   = compute_false_rates(y_t, y_p)
        self.assertIn("fpr", r); self.assertIn("fnr", r)
        self.assertTrue(0 <= r["fpr"] <= 100)
        self.assertTrue(0 <= r["fnr"] <= 100)

    def test_metrics_tracker(self):
        t = MetricsTracker()
        t.update(1, {"f1":80.,"precision":85.,"recall":75.,"accuracy":82.})
        t.update(2, {"f1":85.,"precision":88.,"recall":82.,"accuracy":86.})
        df = t.get_dataframe()
        self.assertEqual(len(df), 2)
        self.assertAlmostEqual(t.best_f1(), 85.0)

    def test_zero_division_safe(self):
        y_t = np.zeros(10, dtype=int)
        y_p = np.zeros(10, dtype=int)
        m   = compute_metrics(y_t, y_p, average="binary")
        self.assertGreaterEqual(m["f1"], 0)


# ══════════════════════════════════════════════════════════════════════
class TestFeatureExtractor(unittest.TestCase):

    def test_extract_keys(self):
        report = VirusTotalAPI._mock_report("8.8.8.8")
        feat   = CTIFeatureExtractor().extract(report, ip="8.8.8.8")
        for k in ["stat_malicious","stat_harmless","ratio_malicious","reputation","votes_malicious","ip"]:
            self.assertIn(k, feat)
        self.assertEqual(feat["ip"], "8.8.8.8")

    def test_ratios_in_range(self):
        ext = CTIFeatureExtractor()
        for ip in ["1.1.1.1","8.8.8.8","192.168.0.1"]:
            feat = ext.extract(VirusTotalAPI._mock_report(ip), ip=ip)
            self.assertGreaterEqual(feat["ratio_malicious"], 0)
            self.assertLessEqual(feat["ratio_malicious"], 1)

    def test_mock_reproducible(self):
        r1 = VirusTotalAPI._mock_report("8.8.8.8")
        r2 = VirusTotalAPI._mock_report("8.8.8.8")
        a1 = r1["data"]["attributes"]["reputation"]
        a2 = r2["data"]["attributes"]["reputation"]
        self.assertEqual(a1, a2)


# ══════════════════════════════════════════════════════════════════════
class TestOnlineSVM(unittest.TestCase):

    def test_fit_predict_shape(self):
        X, y = _Xy()
        m = OnlineSVM(); m.fit(X, y)
        p = m.predict(X)
        self.assertEqual(p.shape, (len(X),))
        self.assertTrue(set(np.unique(p)).issubset({0,1}))

    def test_partial_fit(self):
        X, y = _Xy()
        m = OnlineSVM(); m.fit(X[:200], y[:200])
        m.partial_fit(X[200:], y[200:])
        self.assertEqual(len(m.predict(X)), len(X))

    def test_unfitted_raises(self):
        m = OnlineSVM()
        with self.assertRaises(RuntimeError):
            m.predict(np.zeros((5,5)))

    def test_single_class_batch(self):
        """partial_fit with single-class batch must not crash."""
        X, y = _Xy()
        m = OnlineSVM(); m.fit(X[:200], y[:200])
        X_one = X[200:210]
        y_one = np.ones(10, dtype=int)
        m.partial_fit(X_one, y_one)   # should not raise


class TestIDSKMeans(unittest.TestCase):

    def test_fit_predict(self):
        X, y = _Xy()
        m = IDSKMeans(); m.fit(X, y)
        p = m.predict(X)
        self.assertTrue(set(np.unique(p)).issubset({0,1}))

    def test_partial_fit(self):
        X, y = _Xy()
        m = IDSKMeans(); m.fit(X[:200], y[:200])
        m.partial_fit(X[200:], y[200:])
        self.assertEqual(len(m.predict(X)), len(X))


class TestHybridIDSModel(unittest.TestCase):

    def test_fit_predict_labels(self):
        X, y = _Xy()
        m = HybridIDSModel(config=CFG); m.fit(X, y)
        p = m.predict(X)
        self.assertTrue(set(np.unique(p)).issubset({0,1,2}))

    def test_evaluate_dict(self):
        X, y = _Xy()
        m = HybridIDSModel(config=CFG); m.fit(X, y)
        met = m.evaluate(X, y)
        for k in ["f1","precision","recall","accuracy"]:
            self.assertIn(k, met)
            self.assertGreaterEqual(met[k], 0)
            self.assertLessEqual(met[k], 100)

    def test_outlier_indices(self):
        X, y = _Xy()
        m = HybridIDSModel(config=CFG); m.fit(X, y)
        idx = m.get_outlier_indices(X)
        self.assertEqual(idx.ndim, 1)
        self.assertTrue(all(0 <= i < len(X) for i in idx))

    def test_partial_fit(self):
        X, y = _Xy()
        m = HybridIDSModel(config=CFG); m.fit(X[:200], y[:200])
        m.partial_fit(X[200:], y[200:])
        p = m.predict(X)
        self.assertEqual(len(p), len(X))

    def test_save_load(self):
        X, y = _Xy()
        m = HybridIDSModel(config=CFG); m.fit(X, y)
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            path = f.name
        try:
            m.save(path)
            m2 = HybridIDSModel.load(path)
            np.testing.assert_array_equal(m.predict(X), m2.predict(X))
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════
class TestCTITransferModel(unittest.TestCase):

    def test_fit_predict_binary(self):
        Xc, yc = _Xyc()
        m = CTITransferModel(config=CFG); m.fit(Xc, yc)
        p = m.predict(Xc)
        self.assertTrue(set(np.unique(p)).issubset({0,1}))

    def test_partial_fit(self):
        Xc, yc = _Xyc()
        m = CTITransferModel(config=CFG)
        m.fit(Xc[:50], yc[:50])
        m.partial_fit(Xc[50:], yc[50:])
        self.assertEqual(len(m.predict(Xc)), len(Xc))

    def test_predict_proba_sums_to_1(self):
        Xc, yc = _Xyc()
        m = CTITransferModel(config=CFG); m.fit(Xc, yc)
        prob = m.predict_proba(Xc)
        self.assertEqual(prob.shape, (len(Xc), 2))
        np.testing.assert_allclose(prob.sum(axis=1), 1.0, atol=1e-5)

    def test_evaluate_in_range(self):
        Xc, yc = _Xyc()
        m = CTITransferModel(config=CFG); m.fit(Xc, yc)
        met = m.evaluate(Xc, yc)
        self.assertGreaterEqual(met["f1"], 0)
        self.assertLessEqual(met["f1"], 100)

    def test_lazy_predict_without_fit(self):
        Xc, _ = _Xyc()
        m = CTITransferModel(config=CFG)
        p = m.predict(Xc)         # should not raise
        self.assertEqual(len(p), len(Xc))

    def test_save_load(self):
        Xc, yc = _Xyc()
        m = CTITransferModel(config=CFG); m.fit(Xc, yc)
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            path = f.name
        try:
            m.save(path)
            m2 = CTITransferModel.load(path)
            np.testing.assert_array_equal(m.predict(Xc), m2.predict(Xc))
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════
class TestRuleBasedClassifier(unittest.TestCase):

    def test_predict_binary(self):
        Xc, yc = _Xyc()
        rb = RuleBasedCTIClassifier()
        p  = rb.predict(Xc)
        self.assertTrue(set(np.unique(p)).issubset({0,1}))

    def test_known_malicious_row(self):
        feat_names = ["stat_malicious","ratio_malicious","reputation","votes_malicious"]
        X = np.array([
            [10, 0.5, -10, 5],   # clearly malicious
            [0,  0.0,   3, 0],   # clearly benign
        ])
        rb = RuleBasedCTIClassifier(feature_names=feat_names)
        p  = rb.predict(X)
        self.assertEqual(p[0], 1)
        self.assertEqual(p[1], 0)

    def test_evaluate_returns_dict(self):
        Xc, yc = _Xyc()
        rb = RuleBasedCTIClassifier()
        m  = rb.evaluate(Xc, yc)
        self.assertIn("f1", m)


# ══════════════════════════════════════════════════════════════════════
class TestVirusTotalAPI(unittest.TestCase):

    def test_mock_structure(self):
        r = VirusTotalAPI._mock_report("1.2.3.4")
        self.assertIn("data", r)
        attrs = r["data"]["attributes"]
        self.assertIn("last_analysis_stats", attrs)
        self.assertIn("reputation", attrs)
        self.assertIn("total_votes", attrs)

    def test_mock_reproducible(self):
        r1 = VirusTotalAPI._mock_report("8.8.8.8")
        r2 = VirusTotalAPI._mock_report("8.8.8.8")
        self.assertEqual(
            r1["data"]["attributes"]["reputation"],
            r2["data"]["attributes"]["reputation"]
        )

    def test_no_key_returns_mock(self):
        cfg2 = copy.deepcopy(CFG)
        cfg2["api"]["virustotal_key"] = ""
        api  = VirusTotalAPI(config=cfg2)
        rep  = api.lookup_ip("9.9.9.9")
        self.assertIsNotNone(rep)
        self.assertIn("data", rep)


# ══════════════════════════════════════════════════════════════════════
class TestOnlineLearning(unittest.TestCase):

    def test_run_simulation(self):
        X, y   = _Xy()
        Xc, yc = _Xyc()
        ids = HybridIDSModel(config=CFG); ids.fit(X[:150], y[:150])
        cti = CTITransferModel(config=CFG); cti.fit(Xc[:50], yc[:50])
        ctrl = OnlineLearningController(ids, cti, config=CFG)
        tr   = ctrl.run_simulation(
            X[150:], y[150:], Xc[50:], yc[50:], X[:50], y[:50], n_iterations=3
        )
        df = tr.get_dataframe()
        self.assertGreater(len(df), 0)
        self.assertIn("f1", df.columns)
        self.assertGreaterEqual(tr.best_f1(), 0)

    def test_compare_ml_vs_rulebased(self):
        Xc, yc = _Xyc(n=150)
        km_m, rb_m, imp = compare_ml_vs_rulebased(Xc[:100], yc[:100], Xc[100:], yc[100:], config=CFG)
        self.assertIn("f1", km_m); self.assertIn("f1", rb_m)
        self.assertIn("f1_improvement", imp)


# ══════════════════════════════════════════════════════════════════════
class TestIntegration(unittest.TestCase):
    """End-to-end mini pipeline test."""

    def test_full_pipeline(self):
        # Preprocess
        sp = SightingPreprocessor(config=CFG)
        Xs_tr, Xs_te, ys_tr, ys_te = sp.fit_transform(_sighting_df(400))
        cp = CTIPreprocessor(config=CFG)
        Xc_tr, Xc_te, yc_tr, yc_te = cp.fit_transform(_cti_df(300))

        # Train
        ids = HybridIDSModel(config=CFG); ids.fit(Xs_tr, ys_tr)
        cti = CTITransferModel(config=CFG); cti.fit(Xc_tr, yc_tr)

        # Evaluate
        m_ids = ids.evaluate(Xs_te, ys_te)
        m_cti = cti.evaluate(Xc_te, yc_te)
        self.assertGreaterEqual(m_ids["f1"], 0)
        self.assertGreaterEqual(m_cti["f1"], 0)

        # Online loop
        ctrl = OnlineLearningController(ids, cti, config=CFG)
        tr   = ctrl.run_simulation(
            Xs_tr, ys_tr, Xc_tr, yc_tr, Xs_te, ys_te, n_iterations=3
        )
        self.assertGreater(len(tr.history["f1"]), 0)

        # Comparison
        km_m, rb_m, imp = compare_ml_vs_rulebased(Xc_tr, yc_tr, Xc_te, yc_te, config=CFG)
        self.assertIn("f1_improvement", imp)


# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
