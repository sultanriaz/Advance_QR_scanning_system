Secure QR Reputation Analyzer

Real-time QR code scanner with URL security analysis, heuristic risk scoring, and a reputation-based decision engine.

📌 Project Overview

Secure QR Reputation Analyzer is a computer vision + web application that:

Scans QR codes in real time using your webcam

Detects whether QR payload is a URL or plain text

Performs security analysis on extracted URLs

Classifies links as SAFE / SUSPICIOUS / DANGEROUS

Stores scan history in SQLite database

Displays results via an interactive Flask UI

This project simulates a lightweight URL threat detection & reputation system.

🚀 Key Features
🔍 QR Code Detection

Real-time webcam scanning via OpenCV

Bounding box overlay on detected QR codes

🌐 URL Processing

URL validation

URL normalization

Domain extraction

🛡️ Heuristic Security Checks

HTTPS detection

URL length analysis

Suspicious keyword detection

IP-based URL detection

Shortener detection

📊 Reputation Engine

Whitelist lookup

Blacklist lookup

Layered trust model

🧠 Decision Engine

Aggregated risk scoring

Deterministic classification:

SAFE

SUSPICIOUS

DANGEROUS

Confidence score calculation

💾 Persistence & Logging

SQLite database storage

Timestamped scan history

Logging system

🖥️ Flask Web Interface

Live video stream

Risk badge & confidence indicator

Warning banner for dangerous links

Action buttons:

Open link

Copy URL

Ignore scan

Recent scan history table

🧱 Tech Stack
Layer	Technology
Backend	Python, Flask
Computer Vision	OpenCV
Security Logic	Custom heuristics
URL Handling	validators, urllib.parse
Domain Extraction	tldextract
Database	SQLite
Frontend	HTML, CSS, JavaScript
⚙️ System Architecture
Webcam → OpenCV QR Detection
        → Payload Decode
        → URL Validation
        → Normalization
        → Domain Extraction
        → Reputation Engine
        → Heuristic Analysis
        → Decision Engine
        → SQLite Persistence
        → Flask UI Rendering

📂 Project Structure
SecureQRAnalyzer/
│
├── app.py
├── heuristics.py
├── reputation.py
├── blacklist.txt
├── whitelist.txt
├── scans.db
├── requirements.txt
│
├── templates/
│     └── index.html
│
└── static/
      └── style.css

▶️ How to Run
1️⃣ Create virtual environment (optional)
python -m venv venv
venv\Scripts\activate   # Windows
source venv/bin/activate  # Linux/Mac

2️⃣ Install dependencies
pip install -r requirements.txt

3️⃣ Run the application
python app.py

4️⃣ Open in browser
http://127.0.0.1:5000

🗄️ Data Storage

SQLite Database: Stores scan history locally

Blacklist / Whitelist: Local domain reputation lists

No external data transmission

🎯 Use Cases

QR security analysis simulation

URL threat detection demo

Computer vision + Flask integration example

Educational cybersecurity project

Portfolio / academic showcase

📈 Future Improvements

Cloud database integration

Online reputation API

Multi-user authentication

Machine learning threat classifier

File/image QR scanning

REST API for external systems

👨‍💻 Author

Sultan
BS Computer Science Student

📜 License

This project is for educational and portfolio purposes.