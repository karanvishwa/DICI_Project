import pandas as pd
import random

from src.api.virustotal_api import VirusTotalAPI
from src.utils.logger import get_logger, load_config

cfg    = load_config()
vt_api = VirusTotalAPI(cfg)
logger = get_logger(__name__)

BASE = "G:/DICI_react/dici_backend/scripts/raw"  # Adjust this path as needed

def generate_public_ips(n=200):
    ips = set()

    while len(ips) < n:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))

        # skip private ranges
        if ip.startswith(("10.", "192.168.", "172.16.")):
            continue

        ips.add(ip)

    return list(ips)

# Load your new raw dataset
df = pd.read_csv(f"{BASE}/dataset.csv")

# 2. Filter for only the columns we need
df_filtered_src = df["IPV4_SRC_ADDR"].unique()  # Start with src_ip
df_filtered_dst = df["IPV4_DST_ADDR"].unique()  # Start with dst_ip


logger.info(f"Unique IPs or IP pairs to lookup: {len(df_filtered_src)} src IPs, {len(df_filtered_dst)} dst IPs                  ")

reports = []

for ip in df_filtered_src:
    logger.info(f"Looking up CTI data for IP: {ip}")
    report = vt_api.lookup_ip(ip)
    if not report:
        logger.warning(f"No data found for IP: {ip}")
        continue
    reports.append(report)
    logger.info(f"Completed lookup for IP: {ip}")

for ip in df_filtered_dst:
    logger.info(f"Looking up CTI data for IP: {ip}")
    report = vt_api.lookup_ip(ip)
    if not report:
        logger.warning(f"No data found for IP: {ip}")
        continue
    reports.append(report)
    logger.info(f"Completed lookup for IP: {ip}")

generated_ips = generate_public_ips(n=300)

for ip in generated_ips:
    logger.info(f"Looking up CTI data for IP: {ip}")
    report = vt_api.lookup_ip(ip)
    if not report:
        logger.warning(f"No data found for IP: {ip}")
        continue
    reports.append(report)
    logger.info(f"Completed lookup for IP: {ip}")

features_list = []

for report in reports:
    attr = report.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    votes = attr.get("total_votes", {})

    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    total = malicious + harmless + suspicious + undetected

    label = malicious >= 2 or suspicious >= 2 or votes.get("malicious", 0) > 0

    features = {
        "reputation": attr.get("reputation", 0),
        "malicious_count": malicious,
        "harmless_count": harmless,
        "suspicious_count": suspicious,
        "undetected_count": undetected,
        "malicious_ratio": malicious / (total + 1e-9),
        "votes_malicious": votes.get("malicious", 0),
        "votes_harmless": votes.get("harmless", 0),
        "num_tags": len(attr.get("tags", [])),
        "label": int(label)
    }

    features_list.append(features)


df_features = pd.DataFrame(features_list)


# 4. Save for use in run_pipeline.py
df_features.to_csv(f"{BASE}/cti_features_labeled.csv", index=False)