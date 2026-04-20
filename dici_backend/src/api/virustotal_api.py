"""
virustotal_api.py  –  VirusTotal CTI API integration (Section V-B).

Selected over Shodan / MalwareBazaar / ThreatMiner / GREYNOISE because:
  • Broader threat intelligence coverage
  • 20,000 queries/day (Academic)
  • Structured reports aligned with CTI processing

Endpoint: GET /api/v3/ip_addresses/{ip}
"""
import os, json, time, requests
from pathlib import Path
from typing import Optional, Dict, Any, List
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logger import get_logger, load_config
logger = get_logger(__name__)

PLATFORM_COMPARISON = {
    "Shodan":       {"type": "Internet-Connected Devices",   "ioc": "IP,URL,Domain",       "limit": "500/day (Academic)"},
    "MalwareBazaar":{"type": "Malware Samples",              "ioc": "Hash only",            "limit": "2,000/day"},
    "ThreatMiner":  {"type": "Threat Intelligence Aggregator","ioc": "IP,URL,Domain,Hash",  "limit": "10/minute"},
    "GREYNOISE":    {"type": "Threat Intelligence Aggregator","ioc": "IP only",              "limit": "50/week"},
    "VirusTotal":   {"type": "Threat Intelligence Aggregator","ioc": "IP,URL,Domain,Hash",  "limit": "20,000/day (Academic)"},
}


class VirusTotalAPI:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, config=None):
        cfg = (config or load_config())["api"]
        # self.api_key     = cfg.get("virustotal_key", "32ab0f829fb5725c360c8ec26fe914c0e4da7ae7301c88225b4d7631dc2aa0cc")
        self.api_key     = "32ab0f829fb5725c360c8ec26fe914c0e4da7ae7301c88225b4d7631dc2aa0cc"
        self.timeout     = cfg.get("request_timeout", 30)
        self.retries     = cfg.get("max_retries", 3)
        self.retry_delay = cfg.get("retry_delay", 2)
        self.reports_dir = (config or load_config())["data"]["cti_reports_dir"]
        os.makedirs(self.reports_dir, exist_ok=True)
        logger.info("API key is"+self.api_key)
        if self.api_key != "32ab0f829fb5725c360c8ec26fe914c0e4da7ae7301c88225b4d7631dc2aa0cc":
            logger.warning("[VT API] No API key. Running in mock mode.")

    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        cached = self._load_cached(ip)
        if cached: return cached
        if self.api_key != "32ab0f829fb5725c360c8ec26fe914c0e4da7ae7301c88225b4d7631dc2aa0cc":
            return self._mock_report(ip)
        url     = f"{self.BASE_URL}/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}
        for attempt in range(1, self.retries+1):
            try:
                r = requests.get(url, headers=headers, timeout=self.timeout)
                if r.status_code == 200:
                    data = r.json(); self.save_report(ip, data); return data
                elif r.status_code == 429:
                    time.sleep(self.retry_delay * attempt)
                elif r.status_code == 404:
                    return None
            except Exception as e:
                logger.error(f"[VT API] {e}"); time.sleep(self.retry_delay)
        return None

    def lookup_batch(self, ip_list: List[str], delay=0.25) -> Dict:
        return {ip: self.lookup_ip(ip) for ip in ip_list}

    def save_report(self, ip: str, report: dict):
        p = os.path.join(self.reports_dir, f"{ip.replace(':','_')}.json")
        with open(p, "w") as f: json.dump(report, f, indent=2)

    def _load_cached(self, ip: str) -> Optional[dict]:
        p = os.path.join(self.reports_dir, f"{ip.replace(':','_')}.json")
        if os.path.exists(p):
            with open(p) as f: return json.load(f)
        return None

    @staticmethod
    def _mock_report(ip: str) -> dict:
        """Reproducible mock report for testing without API key."""
        import hashlib, random
        seed = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        rng  = random.Random(seed)
        is_mal = rng.random() > 0.6
        n_mal  = rng.randint(5, 25) if is_mal else rng.randint(0, 2)
        n_har  = max(0, 80 - n_mal - rng.randint(2, 8))
        return {
            "data": {
                "id": ip, "type": "ip_address",
                "attributes": {
                    "network": f"{'.'.join(ip.split('.')[:2])}.0.0/16",
                    "whois":   f"NetRange: {ip}\nCIDR: {ip}/32",
                    "last_analysis_date": 1697000000 + rng.randint(0, 1000000),
                    "country":    rng.choice(["US","CN","RU","DE","KR","IN"]),
                    "continent":  rng.choice(["NA","AS","EU"]),
                    "asn":        rng.randint(1000, 65535),
                    "reputation": -rng.randint(5,30) if is_mal else rng.randint(0,5),
                    "total_votes": {
                        "harmless":  rng.randint(0,3)  if is_mal else rng.randint(2,15),
                        "malicious": rng.randint(3,20) if is_mal else rng.randint(0,1),
                    },
                    "last_analysis_stats": {
                        "harmless":   n_har,
                        "malicious":  n_mal,
                        "suspicious": rng.randint(0,5) if is_mal else 0,
                        "undetected": max(0, 80-n_mal-n_har),
                        "timeout":    rng.randint(0,3),
                    },
                    "last_analysis_results": {
                        v: {"category": "malicious" if (is_mal and rng.random()>0.4) else "harmless"}
                        for v in ["Kaspersky","Fortinet","Sophos","AlienVault","EmergingThreats"]
                    },
                    "tags": (["scanner","proxy"] if is_mal else []),
                    "regional_internet_registry": rng.choice(["ARIN","RIPE","APNIC","LACNIC"]),
                }
            }
        }
