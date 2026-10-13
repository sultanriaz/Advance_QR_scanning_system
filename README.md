# Secure QR Reputation Analyzer & Malicious URL Detection Engine

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![OpenCV](https://img.shields.io/badge/OpenCV-5C3EE8?style=for-the-badge&logo=opencv&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-DC2626?style=for-the-badge)

A security utility designed to inspect, decode, and evaluate QR codes in real time. Beyond standard payload decoding, the system executes heuristic URL vulnerability checks (punycode, entropy, IP literal spoofing) and maintains an audited scan history.

---

## 🏛️ Pipeline Architecture

```mermaid
flowchart TD
    ScanInput["QR Code Image / Video Frame"] --> CVEngine["OpenCV QRCodeDetector"]
    CVEngine --> Payload["Decoded Payload (Raw String / URL)"]
    Payload --> Router{"Payload Type"}
    Router -->|Plain Text| SafeDisplay["Text Display & Copy"]
    Router -->|URL Structure| Heuristics["Security Heuristics Engine (heuristics.py)"]
    Heuristics --> Entropy["Shannon Entropy Calculation"]
    Heuristics --> Protocol["Protocol Verification (HTTPS vs HTTP)"]
    Heuristics --> Punycode["Punycode / Homograph Attack Detection"]
    Heuristics --> IPCheck["IP Literal & Port Obfuscation Check"]
    Heuristics --> RepEngine["Reputation Engine (reputation.py)"]
    RepEngine --> Whitelist{"Whitelist Check"}
    Whitelist -->|Match| Trusted["Status: Trusted Safe"]
    Whitelist -->|No Match| Blacklist{"Blacklist Check"}
    Blacklist -->|Match| Malicious["Status: Flagged Malicious"]
    Blacklist -->|No Match| HeuristicScore["Aggregate Risk Scoring"]
    HeuristicScore --> AuditDB[("SQLite Scan Audit History")]
    AuditDB --> WebUI["Flask Web Interface Banner"]
```

---

## 🔬 Core Features

- **Computer Vision QR Decoding:** Uses OpenCV's native `QRCodeDetector` for fast frame analysis.
- **Deep Heuristic Risk Scoring:**
  - Evaluates URL string Shannon entropy to catch obfuscated subdomains.
  - Detects Unicode homograph attacks and punycode strings (`xn--`).
  - Flags raw IP hostnames, non-standard web ports, and excessive subdomain nesting.
- **Reputation Filtering:** Verifies domains against local whitelist and known-malicious blacklist corpora.
- **Persistent Scan History:** Records every scan timestamp, URL payload, risk score, and verdict in SQLite.

---

## 📁 Repository Structure

```
Advance_QR_scanning_system/
├── app.py                     # Flask web server and API endpoints
├── heuristics.py              # URL security analysis and entropy scoring
├── reputation.py              # Whitelist/blacklist domain matching
├── QR_codes_generators.py     # Synthetic test QR generator
├── whitelist.txt              # Known trusted domains
├── blacklist.txt              # Known malicious domains
└── requirements.txt           # Python dependency specification
```

---

## 🚀 Quickstart

```bash
git clone https://github.com/sultanriaz/Advance_QR_scanning_system.git
cd Advance_QR_scanning_system
python -m venv venv
# Linux / macOS:
source venv/bin/activate
# Windows:
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
python app.py
```
Open [http://localhost:5000](http://localhost:5000) to scan and evaluate QR payloads.
