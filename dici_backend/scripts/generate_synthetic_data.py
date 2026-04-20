"""
generate_synthetic_data.py
Generates synthetic sighting + CTI datasets matching paper statistics.
  Sighting: 15,000 flows (paper: 2,774,241), 14 features (Table 5)
  CTI:       2,112 reports (paper: 2,112), 82 features → top 50 used
"""
import os, sys, json, numpy as np, pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.utils.logger import get_logger, load_config
logger = get_logger(__name__)


def generate_sighting_data(n_samples=15000, output_path="data/raw/sighting_data.csv",
                            benign_ratio=0.70, malicious_ratio=0.20, outlier_ratio=0.10,
                            random_state=42):
    rng = np.random.default_rng(random_state)
    n_b = int(n_samples*benign_ratio); n_m = int(n_samples*malicious_ratio)
    n_o = n_samples - n_b - n_m
    logger.info(f"[Sighting] Generating B={n_b}, M={n_m}, O={n_o}")
    base = datetime(2023, 1, 6)

    def ip(): return ".".join(str(rng.integers(1,255)) for _ in range(4))
    def ts(): return (base + timedelta(seconds=int(rng.integers(0, 3600*24*240)))).strftime("%Y-%m-%d %H:%M:%S")

    protos  = ["TCP","UDP","ICMP"]
    flags   = ["......","...A..","...AP.","...AR.",".S....","F....."]
    fwd_s   = [0,1,2]; tos = [0,8,16,24,32,40,48,56,64]

    def row(label):
        m = label==1; o = label==2
        dp = int(rng.choice([80,443,8080,22,3389,445])) if m else (int(rng.integers(1024,65535)) if o else int(rng.choice([80,443,53,8080,25])))
        pc = int(rng.integers(1, 500 if m else 50))
        return {
            "time_start": ts(), "time_end": ts(),
            "duration": round(float(rng.exponential(5.0 if m else 2.0)), 3),
            "src_ip": ip(), "dest_ip": ip(),
            "src_port": int(rng.integers(1024,65535)), "dest_port": dp,
            "protocol": str(rng.choice(protos)), "flags": str(rng.choice(flags)),
            "forwarding_status": int(rng.choice(fwd_s)),
            "source_type_of_service": int(rng.choice(tos)),
            "ingress_packet_count": pc, "ingress_byte_count": pc*int(rng.integers(64,1500)),
            "label": label,
        }

    records = [row(0) for _ in range(n_b)] + [row(1) for _ in range(n_m)] + [row(2) for _ in range(n_o)]
    df = pd.DataFrame(records).sample(frac=1, random_state=random_state).reset_index(drop=True)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    logger.info(f"[Sighting] Saved {len(df)} rows → {output_path}")
    return df


def generate_cti_data(n_samples=2112, output_path="data/raw/cti_data.csv",
                       reports_dir="data/cti_reports/", malicious_ratio=0.40, random_state=42):
    rng = np.random.default_rng(random_state)
    n_m = int(n_samples*malicious_ratio); n_b = n_samples - n_m
    logger.info(f"[CTI] Generating B={n_b}, M={n_m}")

    def cti_row(is_m):
        n_mal = int(rng.integers(5,25)) if is_m else int(rng.integers(0,3))
        n_har = max(0, 80 - n_mal - int(rng.integers(2,10)))
        n_sus = int(rng.integers(0,6)) if is_m else 0
        row = {
            "stat_malicious": n_mal, "stat_harmless": n_har, "stat_suspicious": n_sus,
            "stat_undetected": max(0, 80-n_mal-n_har), "stat_timeout": int(rng.integers(0,4)),
            "stat_total": 80,
            "ratio_malicious": n_mal/80, "ratio_harmless": n_har/80, "ratio_suspicious": n_sus/80,
            "reputation": int(rng.integers(-30,-5)) if is_m else int(rng.integers(0,5)),
            "votes_malicious": int(rng.integers(3,20)) if is_m else int(rng.integers(0,2)),
            "votes_harmless":  int(rng.integers(0,3))  if is_m else int(rng.integers(2,15)),
            "whois_length": int(rng.integers(100,2000)), "has_whois": 1,
            "n_tags": int(rng.integers(1,3)) if is_m else 0,
            "tag_CDN": 0, "tag_proxy": 1 if (is_m and rng.random()>0.6) else 0,
            "tag_tor": 1 if (is_m and rng.random()>0.8) else 0,
            "tag_vpn": 1 if (is_m and rng.random()>0.7) else 0,
            "tag_scanner": 1 if (is_m and rng.random()>0.5) else 0,
            "asn": int(rng.integers(1000,65535)),
            "last_analysis_date": int(rng.integers(1690000000,1700000000)),
            "label": 1 if is_m else 0,
        }
        for i in range(44):
            row[f"vendor_{i:02d}"] = 1 if (is_m and rng.random()>0.5) else 0
        for c in ["US","CN","RU","DE","KR","IN","BR","FR","NL","OTHER"]:
            row[f"country_{c}"] = 0
        row[f"country_{rng.choice(['US','CN','RU','DE','KR'])}"] = 1
        for r in ["ARIN","RIPE","APNIC","LACNIC","AFRINIC"]:
            row[f"rir_{r}"] = 0
        row[f"rir_{rng.choice(['ARIN','RIPE','APNIC'])}"] = 1
        return row

    records = [cti_row(True) for _ in range(n_m)] + [cti_row(False) for _ in range(n_b)]
    df = pd.DataFrame(records).sample(frac=1, random_state=random_state).reset_index(drop=True)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    logger.info(f"[CTI] Saved {len(df)} rows → {output_path}")
    _gen_json_reports(df, reports_dir)
    return df


def _gen_json_reports(df, reports_dir):
    import random; random.seed(42)
    os.makedirs(reports_dir, exist_ok=True)
    for i, row in df.iterrows():
        ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        report = {"data":{"id":ip,"type":"ip_address","attributes":{
            "reputation": int(row.get("reputation",0)),
            "last_analysis_date": int(row.get("last_analysis_date",0)),
            "country": "US",
            "total_votes": {"harmless":int(row.get("votes_harmless",0)),"malicious":int(row.get("votes_malicious",0))},
            "last_analysis_stats": {"harmless":int(row.get("stat_harmless",0)),"malicious":int(row.get("stat_malicious",0)),
                                     "suspicious":int(row.get("stat_suspicious",0)),"undetected":int(row.get("stat_undetected",0)),"timeout":0},
            "tags":[], "last_analysis_results":{},
        }}}
        with open(os.path.join(reports_dir, f"ip_{i}.json"), "w") as f:
            json.dump(report, f)
    logger.info(f"[CTI] Generated {len(df)} JSON reports → {reports_dir}")


if __name__ == "__main__":
    cfg = load_config()
    generate_sighting_data(output_path=cfg["data"]["sighting_raw_path"])
    generate_cti_data(output_path="data/raw/cti_data.csv", reports_dir=cfg["data"]["cti_reports_dir"])
    logger.info("✓ Synthetic data generation complete.  Next: python scripts/run_pipeline.py")
