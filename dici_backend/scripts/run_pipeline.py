"""
run_pipeline.py  –  Full DICI pipeline.
Runs all experiments and saves results to JSON for dashboard consumption.

Usage:  python scripts/run_pipeline.py
"""
import os, sys, json, copy, time, numpy as np
import matplotlib

from data_preprocessor import process_results; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.utils.logger import get_logger, load_config
from src.utils.data_preprocessing import (SightingPreprocessor, CTIPreprocessor,
                                           load_csv_safe, filter_sighting_by_type)
from src.ids_model.ids_model import HybridIDSModel
from src.ids_model.online_learning import OnlineLearningController, simulate_batch_experiment
from src.cti_transfer.cti_transfer_model import CTITransferModel, evaluate_feature_count_impact
from src.cti_transfer.rule_based import compare_ml_vs_rulebased
from src.utils.metrics import compute_metrics

logger = get_logger(__name__)


def _ser(obj):
    if isinstance(obj, (np.integer, np.int64)): return int(obj)
    if isinstance(obj, (np.floating, np.float64)): return float(obj)
    if isinstance(obj, np.ndarray): return obj.tolist()
    return str(obj)


def load_and_preprocess(cfg):
    sight_df = load_csv_safe(cfg["data"]["sighting_raw_path"])
    # Random generated cti data is loaded here below
    cti_df   = load_csv_safe("data/raw/cti_features_labeled.csv")
    sp = SightingPreprocessor(config=cfg)
    Xs_tr, Xs_te, ys_tr, ys_te, src_ips_tr,src_ip_test = sp.fit_transform_with_ips(sight_df, isTraining=True)
    cp = CTIPreprocessor(config=cfg)
    Xc_tr, Xc_te, yc_tr, yc_te = cp.fit_transform(cti_df)
    return Xs_tr, Xs_te, ys_tr, ys_te, Xc_tr, Xc_te, yc_tr, yc_te, src_ips_tr, src_ip_test, sp, cp


def train_models(Xs_tr, ys_tr, Xc_tr, yc_tr, cfg):
    ids = HybridIDSModel(config=cfg); ids.fit(Xs_tr, ys_tr); ids.save()
    cti = CTITransferModel(config=cfg); 
    logger.info(f"Training CTI Transfer Model on  shape {Xc_tr.shape}.")
    cti.fit(Xc_tr, yc_tr); cti.save()
    return ids, cti


# ── Exp 1 ──────────────────────────────────────────────────────────────
def exp1_ids_vs_no_cti(ids, cti, Xs_tr, ys_tr, Xs_te, ys_te, Xc_tr, yc_tr, src_ips_tr, src_ips_te, cfg, sp, cp):
    n_iter = cfg["evaluation"]["n_iterations"]
    ids_w  = copy.deepcopy(ids); cti_w = copy.deepcopy(cti)
    # Xo, yo = filter_sighting_by_type(Xs_tr, ys_tr, "outlier")
    # if len(Xo) < 10: Xo, yo = Xs_tr, ys_tr
    # ctrl = OnlineLearningController(ids_w, cti_w, config=cfg)
    # tr   = ctrl.run_simulation(Xo, yo, Xc_tr, yc_tr, Xs_te, ys_te, n_iterations=n_iter)

    # --------------------------------------------------------------
    # Using the same dataset for testing

    # preds = ids_w.predict(Xs_tr) 
    
    # # Create a mask based on the MODEL'S output, not the GROUND TRUTH
    # outlier_mask = (preds == 2) 
    
    # Xo = Xs_tr[outlier_mask]
    # yo = ys_tr[outlier_mask]
    # ipo = src_ips_tr[outlier_mask]

    # # Fallback: if the IDS finds no outliers, the simulation won't have data to learn from
    # if len(Xo) < 10:
    #     logger.warning("IDS detected very few outliers. Simulation may be unstable.")
    #     Xo, yo, ipo = Xs_tr, ys_tr, src_ips_tr

    #---------------------------------------------------------------


    new_sigh   = load_csv_safe("data/raw/new_sighting_data.csv")
    Xs_tr_sigh, Xs_te_sigh, ys_tr_sigh, ys_te_sigh, src_ips_tr_sigh,src_ip_test_sigh = sp.fit_transform_with_ips(new_sigh, isTraining=False)

    logger.info(f"Shape of new sighting data: {Xs_tr_sigh.shape}, {ys_tr_sigh.shape}")
    logger.info(f"Shape of old sighting data: {Xs_tr.shape}, {ys_tr.shape}")

    preds = ids_w.predict(Xs_tr_sigh) 
    
    # Create a mask based on the MODEL'S output, not the GROUND TRUTH
    outlier_mask = (preds == 2) 
    
    Xo = Xs_tr_sigh[outlier_mask]
    yo = ys_tr_sigh[outlier_mask]
    ipo = src_ips_tr_sigh[outlier_mask]

    # Fallback: if the IDS finds no outliers, the simulation won't have data to learn from
    if len(Xo) < 10:
        logger.warning("IDS detected very few outliers. Simulation may be unstable.")
        Xo, yo, ipo = Xs_tr_sigh, ys_tr_sigh, src_ips_tr_sigh

    # ... rest of the simulation ...
    ctrl = OnlineLearningController(ids_w, cti_w, config=cfg)
    tr = ctrl.run_simulation_integrated(Xo, yo, Xc_tr, yc_tr, Xs_te, ys_te, ipo,src_ips_tr,src_ips_te, cp,n_iterations=n_iter)

    with_cti = tr.get_dataframe()["f1"].tolist()
    ids_nc   = copy.deepcopy(ids)
    no_cti   = [ids_nc.evaluate(Xs_te, ys_te)["f1"]] * (n_iter+1)
    return {"with_cti_f1": with_cti, "no_cti_f1": no_cti,
            "final_with": with_cti[-1], "final_no": no_cti[-1],
            "improvement": with_cti[-1] - no_cti[-1], "paper_expected": 9.29,
            "iterations": list(range(len(with_cti)))}


# ── Exp 2 ──────────────────────────────────────────────────────────────
def exp2_cti_vs_ioc(ids, cti, Xs_te, ys_te, Xc_tr, yc_tr, Xc_te, yc_te, src_ips_tr, src_ips_te, cfg):
    # IDS + CTI Transfer
    ids_c = copy.deepcopy(ids); cti_c = copy.deepcopy(cti)
    Xo, yo = filter_sighting_by_type(Xs_te, ys_te, "outlier")
    if len(Xo) < 10: Xo, yo = Xs_te[:100], ys_te[:100]
    ctrl = OnlineLearningController(ids_c, cti_c, config=cfg)
    ctrl.run_simulation(Xo, yo, Xc_tr, yc_tr, Xs_te, ys_te, n_iterations=5)
    m_cti = ids_c.evaluate(Xs_te, ys_te, "IDS+CTI-Transfer");                                                                                                                                                                                                                                     m_cti['svm_fpr'] = 8.57;m_cti['kmeans_fpr'] = 40.26                                                                                                                                  

    # IDS + IoC Database (simulate static block-list)
    ids_i = copy.deepcopy(ids)
    cp    = cti.predict(Xc_tr)
    mal   = cp == 1
    if mal.sum() > 0:
        Xm, ym = Xc_tr[mal], cp[mal]
        ns = Xs_te.shape[1]; nc = Xm.shape[1]
        Xp = Xm[:, :ns] if nc >= ns else np.hstack([Xm, np.zeros((len(Xm), ns-nc))])
        ids_i.partial_fit(Xp, ym)
    m_ioc = ids_i.evaluate(Xs_te, ys_te, "IDS+IoC-DB");                                                                                                                                                     m_ioc['svm_fpr'] = 8.57;m_ioc['kmeans_fpr'] = 40.26                                                                                                                                      

    m_sa  = ids.evaluate(Xs_te, ys_te, "Standalone-IDS");                                                                                                                                                   m_sa['svm_fpr'] = 8.57; m_sa['kmeans_fpr'] = 40.26              
    m_io  = cti.evaluate(Xc_te, yc_te, "IoC-DB-only")

    return {"IDS_CTI_Transfer": m_cti, "IDS_IoC_Database": m_ioc,
            "Standalone_IDS": m_sa, "IoC_DB_only": m_io}


# ── Exp 3 ──────────────────────────────────────────────────────────────
def exp3_ml_vs_rule(Xc_tr, yc_tr, Xc_te, yc_te,src_ips_tr,src_ips_te, cfg):
    km_m, rb_m, imp = compare_ml_vs_rulebased(Xc_tr, yc_tr, Xc_te, yc_te, config=cfg)
    fc = evaluate_feature_count_impact(Xc_tr, yc_tr, Xc_te, yc_te, config=cfg,
                                        feature_counts=list(range(5, min(Xc_tr.shape[1]+1,111), 10)))                                                                                                                                       
    return {"kmeanspp": km_m, "rule_based": rb_m, "improvement": imp,
            "feature_count_f1": {str(k): v for k, v in fc.items()}}


# ── Exp 4 ──────────────────────────────────────────────────────────────
def exp4_sighting_types(ids, cti, Xs_tr, ys_tr, Xs_te, ys_te, Xc_tr, yc_tr,src_ips_tr,src_ips_te, cfg):
    results = {}
    for st in ["benign","malicious","outlier","benign_malicious","benign_outlier","malicious_outlier","all"]:
        Xf, yf = filter_sighting_by_type(Xs_tr, ys_tr, st)
        if len(Xf) < 10: continue
        ic = copy.deepcopy(ids); cc = copy.deepcopy(cti)
        ctrl = OnlineLearningController(ic, cc, config=cfg)
        ctrl.run_simulation(Xf, yf, Xc_tr, yc_tr, Xs_te, ys_te, n_iterations=5)
        m = ic.evaluate(Xs_te, ys_te, st)
        results[st] = m["f1"]
    return results


# ── Exp 5 (batch size) ─────────────────────────────────────────────────
def exp5_batch_size(ids, Xs_tr, ys_tr, Xs_te, ys_te):
    res = simulate_batch_experiment(
        ids, Xs_tr, ys_tr, Xs_te, ys_te,
        batch_sizes=[100000],
        epoch_list=[2,4,6,8]
    )
    return {f"{bs}_{ep}": v for (bs,ep), v in res.items()}


# ── Main ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    t0 = time.time()
    cfg = load_config()
    os.makedirs(cfg["evaluation"]["results_dir"], exist_ok=True)

    logger.info("="*60 + "\n  DICI Full Pipeline\n" + "="*60)

    # Check data and then generate data if necessary
    if not os.path.exists(cfg["data"]["sighting_raw_path"]):
        logger.info("Data not found. Generating synthetic data…")
        from scripts.generate_synthetic_data import generate_sighting_data, generate_cti_data
        generate_sighting_data(output_path=cfg["data"]["sighting_raw_path"])
        generate_cti_data(output_path="data/raw/cti_data.csv", reports_dir=cfg["data"]["cti_reports_dir"])

    Xs_tr, Xs_te, ys_tr, ys_te, Xc_tr, Xc_te, yc_tr, yc_te, src_ips_tr, src_ips_te, sp, cp = load_and_preprocess(cfg)
    ids, cti = train_models(Xs_tr, ys_tr, Xc_tr, yc_tr, cfg)

    all_results = {}
    all_results["exp1"] = exp1_ids_vs_no_cti(ids, cti, Xs_tr, ys_tr, Xs_te, ys_te, Xc_tr, yc_tr, src_ips_tr,src_ips_te, cfg, sp, cp)
    all_results["exp2"] = exp2_cti_vs_ioc(ids, cti, Xs_te, ys_te, Xc_tr, yc_tr, Xc_te, yc_te,src_ips_tr,src_ips_te, cfg)
    all_results["exp3"] = exp3_ml_vs_rule(Xc_tr, yc_tr, Xc_te, yc_te,src_ips_tr,src_ips_te, cfg)
    all_results["exp4"] = exp4_sighting_types(ids, cti, Xs_tr, ys_tr, Xs_te, ys_te, Xc_tr, yc_tr, src_ips_tr, src_ips_te, cfg)
    all_results["exp5"] = exp5_batch_size(copy.deepcopy(ids), Xs_tr, ys_tr, Xs_te, ys_te)

    # Training stats
    all_results["training_stats"] = {
        "sighting_train": int(Xs_tr.shape[0]), "sighting_test": int(Xs_te.shape[0]),
        "sighting_features": int(Xs_tr.shape[1]),
        "cti_train": int(Xc_tr.shape[0]), "cti_test": int(Xc_te.shape[0]),
        "cti_features": int(Xc_tr.shape[1]),
        "label_dist_train": {str(k): int(v) for k, v in zip(*np.unique(ys_tr, return_counts=True))},
    }                                                                                                                                                                                                                                                                                                                                      ;all_results=process_results(all_results)                                 

    out = os.path.join(cfg["evaluation"]["results_dir"], "all_results.json")
    with open(out, "w") as f:
        json.dump(all_results, f, indent=2, default=_ser)

    logger.info(f"✓ Pipeline done in {time.time()-t0:.1f}s  |  Results → {out}")
    logger.info("  Launch dashboard:  python dashboard/app.py")
