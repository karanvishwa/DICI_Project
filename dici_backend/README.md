# ⚡ DICI — Dynamic IDS with CTI Integrated

> **Paper:** *Evolving ML-Based Intrusion Detection: Cyber Threat Intelligence for Dynamic Model Updates*
> IEEE Transactions on Machine Learning in Communications and Networking (TMLCN), 2025
> DOI: 10.1109/TMLCN.2025.3564587

---

## What is DICI?

Traditional ML-based IDS systems are **static** — trained once, they fail to detect new attack types until manually retrained. DICI solves this by continuously integrating **Cyber Threat Intelligence (CTI)** to dynamically update the IDS model in real-time.

### Architecture (Figure 1 of paper)

```
Network Traffic  ──►  IDS Model  ──►  Benign / Malicious / Outlier
                           │                        │
                           │         Outlier ──►  CTI Lookup (VirusTotal)
                           │                        │
                           ◄──── CTI Transfer Model ◄──── Structured CTI Report
                           (online partial_fit)
```

### Two AI Models

| Model | Algorithm | Role |
|-------|-----------|------|
| **IDS Model** | Hybrid SVM + KMeans | Classify traffic as Benign / Malicious / Outlier |
| **CTI Transfer Model** | KMeans++ | Analyse CTI reports → generate IDS training data |

---

## Project Structure

```
DICI_Complete/
├── config/
│   └── config.yaml                  ← All hyperparameters & paths
│
├── src/
│   ├── ids_model/
│   │   ├── ids_model.py             ← Hybrid IDS: OnlineSVM + IDSKMeans + HybridIDSModel
│   │   └── online_learning.py       ← OnlineLearningController + batch size experiment
│   │
│   ├── cti_transfer/
│   │   ├── cti_transfer_model.py    ← CTITransferModel (KMeans++)
│   │   └── rule_based.py            ← RuleBasedCTIClassifier (baseline)
│   │
│   ├── api/
│   │   └── virustotal_api.py        ← VirusTotal API integration (mock mode if no key)
│   │
│   └── utils/
│       ├── logger.py                ← Centralised logging + config loader
│       ├── data_preprocessing.py   ← SightingPreprocessor + CTIPreprocessor
│       ├── feature_extraction.py   ← CTIFeatureExtractor (105 features from VT reports)
│       └── metrics.py              ← F1, Precision, Recall, FPR, FNR, MetricsTracker
│
├── dashboard/
│   └── app.py                       ← Flask + Plotly live dashboard (http://localhost:5000)
│
├── scripts/
│   ├── generate_synthetic_data.py  ← Generate test datasets (no real data needed)
│   └── run_pipeline.py             ← Full experiment runner → saves all_results.json
│
├── tests/
│   └── test_all.py                  ← 41 unit + integration tests
│
├── data/
│   ├── raw/                         ← Generated CSV datasets
│   ├── processed/results/           ← Experiment results JSON + saved models
│   └── cti_reports/                 ← VT JSON reports (cached)
│
└── requirements.txt
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate synthetic data
```bash
python scripts/generate_synthetic_data.py
```
This creates synthetic datasets matching paper statistics:
- **Sighting:** 15,000 traffic flows with 14 features (Table 5 of paper)
- **CTI:** 2,112 structured CTI reports with 82 features

### 3. Run the full pipeline
```bash
python scripts/run_pipeline.py
```
Runs all 5 experiments and saves results to `data/processed/results/all_results.json`.

### 4. Launch the live dashboard
```bash
python dashboard/app.py
```
Open **http://localhost:5000** — fully interactive Plotly charts with zoom, pan, hover tooltips, animated transitions.

### 5. Run tests
```bash
python tests/test_all.py
```
All 41 tests should pass.

---

## Experiments Reproduced

| # | Figure | Description | Paper Result |
|---|--------|-------------|-------------|
| Exp 1 | Fig 6  | IDS+CTI vs IDS without CTI | **+9.29% F1** |
| Exp 2 | Fig 12 | CTI Transfer Model vs IoC Database | **+7.16% F1, +12.61% Recall** |
| Exp 3 | Fig 13 | KMeans++ vs Rule-based CTI | **+30.92% F1** |
| Exp 4 | Fig 8  | Sighting type impact on CTI training | **Outlier-only = best (89.52%)** |
| Exp 5 | Fig 14/15 | Batch size optimisation | **Optimal = 224** |
| — | Fig 7  | ML-IDS vs DL-IDS resources | **ML is 18× faster, 4× less memory** |

---

## Dashboard Features

The dashboard at `localhost:5000` includes:

- **Real-time F1 chart** (Fig 6) — shows IDS+CTI vs baseline with zoom/pan
- **CTI vs IoC Database bar chart** (Fig 12) — grouped bars, hover for exact values
- **Sighting type impact** (Fig 8) — horizontal bar chart, best type highlighted
- **Feature count impact** (Fig 13) — line chart with rule-based baseline comparison
- **KMeans++ vs Rule-based** — grouped bar comparison
- **Batch size optimisation** (Fig 14/15) — multi-epoch line chart with optimal marker
- **Live traffic donut** — animated traffic classification distribution
- **Resource comparison** (Fig 7) — ML-IDS vs DL-IDS side by side
- **Results table** — all experiment metrics with paper comparison
- **▶ RUN PIPELINE button** — trigger full experiment run from the browser

---

## Real VirusTotal API

To use real CTI data instead of synthetic mock data:

1. Get a free API key at https://www.virustotal.com/gui/join-us
2. Edit `config/config.yaml`:
   ```yaml
   api:
     virustotal_key: "YOUR_ACTUAL_KEY_HERE"
   ```
3. Run the pipeline — it will automatically query VT for each IP in your sighting dataset.

---

## Key Hyperparameters (Table 6 of paper)

| Model | Parameter | Value |
|-------|-----------|-------|
| SVM (IDS) | loss | hinge |
| SVM (IDS) | alpha | 0.1 |
| SVM (IDS) | random_state | 456 |
| KMeans (IDS) | n_clusters | 2 |
| KMeans (IDS) | max_iter | 100 |
| KMeans++ (CTI) | n_clusters | 2 |
| KMeans++ (CTI) | init | k-means++ |
| Online Learning | batch_size (q) | 224 (optimal) |
| Online Learning | CTI threshold (p) | 10 |

---

## Dataset Description (Table 5 of paper)

| Feature | Description |
|---------|-------------|
| `duration` | Duration of network session (seconds) |
| `dest_port` | Destination port number |
| `protocol` | TCP / UDP / ICMP |
| `flags` | TCP flags |
| `forwarding_status` | Packet forwarding status |
| `source_type_of_service` | ToS field in IP header |
| `ingress_packet_count` | Packets received in session |
| `ingress_byte_count` | Bytes received in session |
| `label` | **0=Benign, 1=Malicious, 2=Outlier** |

*Dropped before ML: time_start, time_end, src_ip, dest_ip, src_port*

---

## Hybrid IDS Decision Logic (Figure 4 of paper)

```
S1 = SVM prediction    (0=benign, 1=malicious)
S2 = KMeans prediction (0=benign, 1=malicious)

S1=0 & S2=0  →  Benign    ✓
S1=1 & S2=1  →  Malicious ✗
S1=1 & S2=0  →  Malicious ✗  (SVM trusted over KMeans)
S1=0 & S2=1  →  Outlier   ?  (→ CTI lookup triggered)
```

---

## Citations

```bibtex
@article{lin2025evolving,
  title={Evolving ML-Based Intrusion Detection: Cyber Threat Intelligence for Dynamic Model Updates},
  author={Lin, Ying-Dar and Lu, Yi-Hsin and Hwang, Ren-Hung and Lai, Yuan-Cheng and Sudyana, Didik and Lee, Wei-Bin},
  journal={IEEE Transactions on Machine Learning in Communications and Networking},
  volume={3},
  year={2025},
  doi={10.1109/TMLCN.2025.3564587}
}
```
