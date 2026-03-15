<div align="center">

```
███╗   ███╗ █████╗ ██╗  ██╗ ██████╗ ██████╗  █████╗  ██████╗  █████╗
████╗ ████║██╔══██╗██║  ██║██╔═══██╗██╔══██╗██╔══██╗██╔════╝ ██╔══██╗
██╔████╔██║███████║███████║██║   ██║██████╔╝███████║██║  ███╗███████║
██║╚██╔╝██║██╔══██║██╔══██║██║   ██║██╔══██╗██╔══██║██║   ██║██╔══██║
██║ ╚═╝ ██║██║  ██║██║  ██║╚██████╔╝██║  ██║██║  ██║╚██████╔╝██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

# ⚔ MAHORAGA SENTINEL

**AI-Powered Threat Intelligence & Phishing Detection Platform**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.x-EE4C2C?style=flat-square&logo=pytorch&logoColor=white)](https://pytorch.org)
[![HuggingFace](https://img.shields.io/badge/🤗_Transformers-4.x-FFD21E?style=flat-square)](https://huggingface.co)
[![Phases](https://img.shields.io/badge/Phases-17%2F17_Complete-brightgreen?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

<br/>

*A full-stack, multi-engine cybersecurity platform that detects phishing, analyzes threats,
scans networks, and explains attacks in plain English — powered by transformer-based deep learning.*

</div>

---

## ⚡ What It Does

MAHORAGA Sentinel runs **17 detection modules** across 6 attack surfaces simultaneously, fusing results from classical ML and state-of-the-art transformers into a single real-time dark-theme dashboard.

```
EMAIL ──► DistilBERT + Auth Headers + URL Extraction
URL   ──► BERT + WHOIS + SSL + DNS + GeoIP + Redirect Chain
FILE  ──► YARA + Entropy + SHA256 + Macro Detection
IMAGE ──► Tesseract OCR + Logo Spoofing Detection
AI    ──► RoBERTa ChatGPT/GPT-4 Content Detection
NET   ──► Nmap Port Scan + Service Fingerprint + OS Detection
                          │
                          ▼
             Risk Score Aggregator (0–100)
                          │
                          ▼
         BART-Large Threat Summary + IOC Extraction
         + Translation (EN › FR ES DE ZH AR)
```

---

## 🏗 Architecture

```
Browser  ──►  Flask :5000  ──►  FastAPI :8001  ──►  HuggingFace Models
                  │                   │
              Jinja2 UI           ML Inference
              RBAC Session        File Analysis
              Chart.js            Background Workers
                         │
                     SQLite DB  (→ PostgreSQL via Alembic)
```

---

## 🧩 Module Map

| # | Module | Route | Engine |
|---|--------|-------|--------|
| 1 | Email Scan | `/email/scan` | DistilBERT · SPF/DKIM/DMARC |
| 2 | URL Intelligence | `/url/intel` | BERT · WHOIS · SSL · DNS · GeoIP |
| 3 | Network Scan | `/network/scan` | Nmap · Service fingerprinting |
| 4 | Detection Rules | `/rules` | 40+ heuristic rules engine |
| 5 | ML Classifier | `/ml/classifier` | Random Forest + BERT ensemble |
| 6 | Attachment Analysis | `/attachments/` | YARA · entropy · hash |
| 7 | Image Analysis | `/image/analysis` | Tesseract OCR · logo detection |
| 8 | AI Content Detection | `/ai/detection` | RoBERTa (ChatGPT detector) |
| 9 | Platform Monitor | `/platform/` | Scheduled re-scan · uptime |
| 10 | Risk Aggregator | `/risk/` | Cross-module score fusion |
| 11 | Live Monitor | `/monitor/` | Real-time feed · SMS spam |
| 12 | Model Management | `/models/` | Version tracking · metrics |
| 13 | Alerts & Audit | `/alerts/` | BART summaries · audit log |
| 14 | Browser Extension | `/extension/` | Chrome scan-on-visit |
| 15 | Architecture | `/architecture/` | Live module health |
| 16 | Threat Explanation | `/threat/explain` | BART + 6-language translation |
| 17 | Dashboard + RBAC | `/` | Unified overview · role gates |

---

## 🤖 ML Models

| Model | Purpose | Size |
|-------|---------|------|
| `cybersectony/phishing-email-detection-distilbert_v2.4.1` | Email classification | ~250 MB |
| `ealvaradob/bert-finetuned-phishing` | URL phishing detection | ~440 MB |
| `elftsdmr/malware-url-detect` | Malware URL detection | ~440 MB |
| `Hello-SimpleAI/chatgpt-detector-roberta` | AI content detection | ~500 MB |
| `mrm8488/bert-tiny-finetuned-sms-spam-detection` | SMS spam | ~17 MB |
| `facebook/bart-large-cnn` | Threat summarization | ~1.6 GB |
| `Helsinki-NLP/opus-mt-en-*` | Threat translation × 6 langs | ~300 MB ea. |
| `scikit-learn RandomForest` | 24-feature URL classifier | trained locally |

> All HuggingFace models auto-download on first FastAPI start (~4–7 GB one-time).

---

## 🚀 Quick Start

**Prerequisites:** Python 3.10+, [Nmap](https://nmap.org/download.html), [Tesseract](https://github.com/UB-Mannheim/tesseract/wiki)

```powershell
# 1 — Clone & enter
git clone https://github.com/your-username/mahoraga-sentinel.git
cd mahoraga-sentinel

# 2 — Virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3 — Install dependencies
pip install -r requirements.txt

# 4 — Create database folder & .env
mkdir database
copy .env.example .env        # then edit FLASK_SECRET_KEY

# 5 — Train the Random Forest model (10 seconds)
python -m backend.ml.train_url_classifier

# 6 — Terminal A: start FastAPI (downloads models on first run)
python -m backend.run_fastapi

# 7 — Terminal B: start Flask
python -m backend.run_flask
```

Then open **<http://127.0.0.1:5000>** — select your role and enter Sentinel.

---

## 🔐 Role-Based Access

| Role | Access |
|------|--------|
| 👑 **Admin** | Full platform — all 17 modules |
| 🔬 **Analyst** | All scan pages · alerts · monitor |
| 👁 **Viewer** | Overview dashboard only |

No login or password required — role is stored in the browser session and can be switched at any time from the sidebar.

---

## 🌐 Interfaces

| Interface | URL |
|-----------|-----|
| Dashboard | <http://127.0.0.1:5000> |
| Swagger API Docs | <http://127.0.0.1:8001/docs> |
| Health Check | <http://127.0.0.1:8001/health> |

---

## 🛠 Stack

```
Backend   Flask 3 · FastAPI · SQLAlchemy · Alembic · SQLite → PostgreSQL
ML        PyTorch · HuggingFace Transformers · scikit-learn
Analysis  python-nmap · YARA · pytesseract · pdfminer · dnspython · python-whois
Frontend  Vanilla JS · Chart.js 4 · Custom dark-theme CSS (no build step)
Extension Chrome MV3 · null-origin CORS
```

---

## ⚖ Ethics & Legal

> This platform is built for **authorized security research and educational use only.**
> Network scanning, email analysis, and file inspection must only be performed on
> systems you own or have **explicit written permission** to test.
> Unauthorized port scanning may be illegal in your jurisdiction.
> The authors assume no liability for misuse.

---

## 📄 License

MIT © 2025 MAHORAGA Sentinel Project

---

<div align="center">
<sub>Built with ⚔ by the MAHORAGA Sentinel team · 17 phases · 7 ML models · 1 platform</sub>
</div>
