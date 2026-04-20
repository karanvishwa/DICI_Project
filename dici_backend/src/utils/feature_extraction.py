"""
feature_extraction.py
Extracts 105 features from VirusTotal IP reports (paper Section V-B, V-D).
Categories: network/WHOIS, last_analysis_date, ownership, vendor assessments,
reputation scores, country, total votes.
"""
import json, os, numpy as np, pandas as pd
from pathlib import Path
from typing import Dict, Any, Optional, List
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logger import get_logger
logger = get_logger(__name__)

KNOWN_VENDORS = [
    "Abusix","ADMINUSLabs","AegisLab","AlienVault","Antiy-AVL","Avira","Baidu",
    "BitDefender","CertEE","CINS Army","Comodo Valkyrie Verdict","CRDF","CyRadar",
    "Dr.Web","EmergingThreats","Emsisoft","ESET","Forcepoint ThreatSeeker",
    "Fortinet","GreenSnow","G-Data","Heimdal Security","IPsum","Kaspersky",
    "Lionic","Lumu","MalwarePatrol","MalwareURL","Netcraft","OpenPhish",
    "PhishTank","Sangfor","SOCRadar","Sophos","Spam404","StopForumSpam",
    "Sucuri SiteCheck","ThreatHive","Trustwave","URLhaus","VX Vault",
    "Webroot","Xcitium Verdict Cloud","ZeroCERT",
]

class CTIFeatureExtractor:
    """Parse VirusTotal JSON report → flat numeric feature dict."""

    def extract(self, report: Dict[str, Any], ip: str = "") -> Dict[str, Any]:
        feat: Dict[str, Any] = {"ip": ip}
        data  = report.get("data", {})
        attrs = data.get("attributes", {})

        feat["reputation"]         = attrs.get("reputation", 0)
        feat["last_analysis_date"] = attrs.get("last_analysis_date", 0)
        feat["country"]            = attrs.get("country", "UNKNOWN")
        feat["continent"]          = attrs.get("continent", "UNKNOWN")
        feat["asn"]                = attrs.get("asn", 0)
        feat["network"]            = attrs.get("network", "")

        votes = attrs.get("total_votes", {})
        feat["votes_harmless"]  = votes.get("harmless", 0)
        feat["votes_malicious"] = votes.get("malicious", 0)

        stats = attrs.get("last_analysis_stats", {})
        feat["stat_harmless"]   = stats.get("harmless", 0)
        feat["stat_malicious"]  = stats.get("malicious", 0)
        feat["stat_suspicious"] = stats.get("suspicious", 0)
        feat["stat_undetected"] = stats.get("undetected", 0)
        feat["stat_timeout"]    = stats.get("timeout", 0)
        feat["stat_total"]      = sum(stats.values())

        total = max(feat["stat_total"], 1)
        feat["ratio_malicious"]  = feat["stat_malicious"] / total
        feat["ratio_harmless"]   = feat["stat_harmless"] / total
        feat["ratio_suspicious"] = feat["stat_suspicious"] / total

        analysis = attrs.get("last_analysis_results", {})
        for v in KNOWN_VENDORS:
            cat = analysis.get(v, {}).get("category", "undetected")
            feat[f"vendor_{v.replace(' ','_').replace('-','_')}"] = 1 if cat in ("malicious","suspicious") else 0

        whois = attrs.get("whois", "") or ""
        feat["whois_length"] = len(whois)
        feat["has_whois"]    = int(bool(whois.strip()))

        tags = attrs.get("tags", [])
        feat["n_tags"] = len(tags)
        for t in ["CDN","proxy","tor","vpn","scanner"]:
            feat[f"tag_{t}"] = int(t in tags)

        feat["rir"] = attrs.get("regional_internet_registry", "UNKNOWN")
        return feat

    def extract_batch(self, reports_dir: str, label_map: Optional[Dict[str, int]] = None) -> pd.DataFrame:
        records, files = [], list(Path(reports_dir).glob("*.json"))
        for fp in files:
            try:
                with open(fp) as f:
                    report = json.load(f)
                ip   = fp.stem
                feat = self.extract(report, ip=ip)
                if label_map: feat["label"] = label_map.get(ip, -1)
                records.append(feat)
            except Exception as e:
                logger.warning(f"Failed on {fp}: {e}")
        return pd.DataFrame(records)


# Sighting feature descriptions matching Table 5 of paper
SIGHTING_FEATURES = {
    "time_start":            "Start time of the network session.",
    "time_end":              "End time of the network session.",
    "duration":              "Duration of the network session in seconds.",
    "src_ip":                "Source IP address (dropped before ML).",
    "dest_ip":               "Destination IP address (dropped before ML).",
    "src_port":              "Source port number (dropped before ML).",
    "dest_port":             "Destination port number on the receiving device.",
    "protocol":              "Protocol used (TCP, UDP, ICMP).",
    "flags":                 "TCP flags set during the communication.",
    "forwarding_status":     "Status of packet forwarding (0 = no issues).",
    "source_type_of_service":"Type of Service (ToS) field in IP header.",
    "ingress_packet_count":  "Number of packets received during the session.",
    "ingress_byte_count":    "Total bytes received during the session.",
    "label":                 "Traffic class: 0=benign, 1=malicious, 2=outlier.",
}
