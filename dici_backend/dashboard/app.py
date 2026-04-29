"""
app.py  –  DICI Live Dashboard
Dynamic, interactive dashboard powered by Plotly.js + Flask SSE.
All charts are fully interactive: zoom, pan, hover, filter, animate.

Run: python dashboard/app.py
Open: http://localhost:5000
"""
import os, sys, json, time, copy, threading, numpy as np
from pathlib import Path
from flask import Flask, jsonify, Response, request
from flask_cors import CORS

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from htmltemplate import HTML
from src.utils.logger import get_logger, load_config

logger = get_logger(__name__)
app    = Flask(__name__)
CORS(app)
cfg    = load_config()

# ── Shared state ──────────────────────────────────────────────────────
state = {
    "results":        {},
    "last_updated":   "Never",
    "pipeline_running": False,
    "traffic_stream": {"benign":0, "malicious":0, "outlier":0, "total":0},
    "live_f1":        [],
    "live_iter":      [],
    "improvements":  []
}

def load_results():
    p = os.path.join(cfg["evaluation"]["results_dir"], "all_results_6.json")
    if os.path.exists(p):
        with open(p) as f:
            state["results"]      = json.load(f)
            state["last_updated"] = time.strftime("%H:%M:%S")

def bg_loader():
    while True:
        try: load_results()
        except Exception: pass
        time.sleep(cfg["dashboard"]["update_interval"] / 1000)

threading.Thread(target=bg_loader, daemon=True).start()

# ═══════════════════════════════════════════════════
# Flask routes
# ═══════════════════════════════════════════════════

@app.route("/")
def index():
    return HTML.replace("{{ INTERVAL }}", str(cfg["dashboard"]["update_interval"]))


@app.route("/api/state")
def api_state():
    return jsonify({
        "results":       state["results"],
        "last_updated":  state["last_updated"],
        "pipeline_running": state["pipeline_running"],
        "traffic_stream": state["traffic_stream"],
        "improvements": state["improvements"]
    })


@app.route("/api/pipeline_status")
def pipeline_status():
    return jsonify({"running": state["pipeline_running"]})


@app.route("/api/run_pipeline", methods=["POST"])
def run_pipeline():
    if state["pipeline_running"]:
        return jsonify({"status": "already_running"})
    state["pipeline_running"] = True

    def worker():
        try:
            import subprocess
            subprocess.run(
                [sys.executable, "scripts/run_pipeline.py"],
                cwd=str(Path(__file__).resolve().parents[1]),
                check=True
            )
            load_results()
        except Exception as e:
            logger.error(f"Pipeline error: {e}")
        finally:
            state["pipeline_running"] = False

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"status": "started"})

# --- Add this import at the top of app.py ---
from src.api.virustotal_api import VirusTotalAPI

# --- Initialize the API client ---
vt_api = VirusTotalAPI(cfg)

# --- Add this new endpoint ---
@app.route("/api/cti_lookup/<ip>")
def cti_lookup(ip):
    """Fetches CTI data for a specific IP from VirusTotal."""
    report = vt_api.lookup_ip(ip)
    if not report:
        return jsonify({"error": "No data found"}), 404
    
    # Extract key attributes for the frontend
    attr = report.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    
    return jsonify({
        "ip": ip,
        "reputation": attr.get("reputation", 0),
        "country": attr.get("country", "??"),
        "votes": attr.get("total_votes", {}),
        "malicious_count": stats.get("malicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "tags": attr.get("tags", []),
        "raw": report # Optional: return full data if needed
    })


@app.route("/api/simulate_traffic", methods=["POST"])
def simulate_traffic():
    data = request.get_json(silent=True) or {}
    n    = int(data.get("n", 100))
    rng  = np.random.default_rng(int(time.time() * 1000) % (2**32))
    b = int(rng.integers(60, 80) * n // 100)
    m = int(rng.integers(15, 25) * n // 100)
    o = n - b - m
    state["traffic_stream"]["benign"]    += b
    state["traffic_stream"]["malicious"] += m
    state["traffic_stream"]["outlier"]   += o
    state["traffic_stream"]["total"]     += n
    return jsonify({"status": "ok", "processed": n})


@app.route("/api/reset", methods=["POST"])
def reset():
    state["traffic_stream"] = {"benign":0,"malicious":0,"outlier":0,"total":0}
    return jsonify({"status": "reset"})


if __name__ == "__main__":
    load_results()
    logger.info(f"  Dashboard → http://localhost:{cfg['dashboard']['port']}")
    app.run(host=cfg["dashboard"]["host"], port=cfg["dashboard"]["port"],
            debug=False, use_reloader=False)
