# SENTINEL: Security ML Detection Suite

A real-time security threat detection system built with machine learning, featuring a phishing URL detector and a network intrusion classifier, unified into a live SOC-style web dashboard.

**Full build walkthrough:** [Read on Medium](https://medium.com/@zainabqureshi620/REPLACE_WITH_POST_LINK)

---

## What This Does

- Detects phishing URLs in real time using a trained Random Forest model with live feature extraction (SSL, WHOIS, DNS, HTML parsing)
- Classifies network traffic flows into 7 categories: Normal, DoS, DDoS, Port Scanning, Brute Force, Web Attacks, and Bots
- Unified live dashboard with a per-second detection feed, confidence score rings, and module filtering
- Manual URL scan box — paste any URL and get an instant phishing prediction

---

## Models

| Module | Dataset | Algorithm | Accuracy | Key Metric |
|---|---|---|---|---|
| Phishing | UCI Phishing Websites (11,055 samples) | Random Forest | 97.4% | 96% recall on phishing class |
| Intrusion | CICIDS2017 (625K samples, 7 classes) | Random Forest | 99.9% | class_weight='balanced' |

---

## Project Structure

```
security-ml-suite/
├── phishing/
│   ├── features.py                   ← live URL → 30-feature extraction pipeline
│   ├── predict.py                    ← model inference
│   ├── phishing_model.pkl            ← trained Random Forest
│   └── phishing_feature_columns.pkl  ← feature column order (required for inference)
├── intrusion/
│   ├── predict.py                    ← replay-based inference
│   ├── intrusion_model.pkl           ← trained Random Forest (not included — 31MB exceeds upload limit; retrain using intrusion.ipynb)
│   ├── intrusion_feature_columns.pkl ← feature column order
│   └── intrusion_label_mapping.pkl   ← int → attack type label
├── notebooks/
│   ├── phishing.ipynb                ← full phishing training notebook (Google Colab)
│   └── intrusion.ipynb               ← full intrusion training notebook (Google Colab)
└── dashboard/
    ├── app.py                        ← unified Flask backend (port 5050)
    ├── templates/
    │   └── index.html
    └── static/
        ├── style.css
        └── app.js
```

---

## Setup

### 1. Install dependencies

```bash
pip install flask scikit-learn==1.6.1 joblib pandas numpy \
            requests python-whois dnspython tldextract beautifulsoup4 lxml
```

> **Note:** The models were saved with scikit-learn 1.6.1. Use that exact version to avoid version mismatch warnings on load.

### 2. Generate the intrusion replay sample

The `intrusion_replay_sample.csv` (500 held-out test rows used by the dashboard's live feed) is not included in this repo due to CICIDS2017's redistribution terms. To generate it:

1. Download the dataset from [Kaggle](https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed)
2. Run `notebooks/intrusion.ipynb` in Google Colab
3. The notebook's final cell saves `intrusion_replay_sample.csv` — download it and place it in `intrusion/`

### 3. Run the dashboard

```bash
cd dashboard
python3 app.py
```

### 4. Open in browser

```
http://127.0.0.1:5050
```

---

## Reproducing the Models

Both training notebooks are included in `notebooks/` and designed to run in Google Colab:

- **phishing.ipynb** — downloads the UCI dataset, trains the Random Forest, evaluates with a misclassification analysis, and saves `phishing_model.pkl`
- **intrusion.ipynb** — downloads CICIDS2017 via Kaggle, handles class imbalance, trains the multi-class model, and saves `intrusion_model.pkl`

> **Before running intrusion.ipynb:** The notebook's first cell previously contained a Kaggle API token — this has been removed. Add your own credentials following [Kaggle's API setup guide](https://www.kaggle.com/docs/api).

---

## Known Limitations

- Phishing feature extraction makes live network calls (WHOIS, DNS, SSL, HTML fetch) — scan time is 5–15 seconds per URL depending on the target
- Two phishing features (`Page_Rank`, `web_traffic`) rely on discontinued APIs (Google PageRank, Alexa rankings) and return neutral placeholders — documented in `phishing/features.py`
- The intrusion dashboard replays held-out CICIDS2017 test rows rather than capturing live packets — see the Medium post for the full reasoning
- The intrusion model's strongest feature is Destination Port, meaning attacks run over non-standard ports may evade detection more easily — a known limitation of port-based heuristics in IDS research

