# Hybrid Intrusion Detection System (IDS)

A software-only **Hybrid Intrusion Detection System** that combines **signature-based detection** and **machine learning–based anomaly detection** to analyze network traffic from PCAP files and expose alerts via a REST API.

This project is designed as a **mini SOC-style pipeline**, focusing on real-world structure, clarity, and extensibility rather than a monolithic script.

---

## ✨ Features

- **PCAP-based Network Analysis**
  - Parses offline PCAP files using PyShark
  - Converts packets into normalized events and aggregated flows

- **Flow-Based Detection Engine**
  - Time-windowed flow aggregation
  - Extracts meaningful features (packet count, byte volume, ports, flags, DNS activity)

- **Signature-Based Detection**
  - Port scan detection
  - Traffic spike detection
  - DNS burst detection

- **Anomaly Detection (ML)**
  - Isolation Forest–based anomaly detection
  - Learns baseline behavior from normal traffic
  - Flags statistically abnormal flows

- **Persistent Storage**
  - SQLite database for flows and alerts
  - Indexed for efficient querying

- **REST API**
  - Built using FastAPI
  - Endpoints for alerts, health checks, and statistics

---

## 🧠 Architecture Overview

PCAP File
↓
Packet Parsing (PyShark)
↓
Event Normalization
↓
Flow Aggregation (time windows)
↓
+--------------------------+
| Signature Rules Engine |
| - Port Scan |
| - DNS Burst |
| - Traffic Spike |
+--------------------------+
↓
+--------------------------+
| Anomaly Detection (ML) |
| - Isolation Forest |
+--------------------------+
↓
Alerts Stored in SQLite
↓
FastAPI REST Interface

yaml
Copy code

---

## 🗂️ Project Structure

hybrid-ids/
├── data/
│ ├── baseline/ # ML model + scaler
│ ├── db/ # SQLite database
│ ├── logs/ # Runtime logs
│ └── pcap/ # PCAP files
│
├── src/
│ ├── api/ # FastAPI application
│ ├── detectors/ # Rules + anomaly detection
│ ├── storage/ # Database schema and access
│ ├── utils/ # Logging utilities
│ ├── capture_pcap.py
│ ├── parser.py
│ ├── flow_builder.py
│ └── main.py
│
├── requirements.txt
└── README.md

yaml
Copy code

---

## 🚀 How to Run

### 1️⃣ Install Dependencies
```bash
pip install -r requirements.txt
2️⃣ Run IDS on a PCAP File
bash
Copy code
python -m src.main --pcap data/pcap/sample.pcap --window 10
First run trains the anomaly detection baseline
Subsequent runs generate anomaly alerts

3️⃣ Start the API Server
bash
Copy code
uvicorn src.api.api:app --reload
🔌 API Endpoints
Endpoint	Description
/health	Service health check
/alerts	Fetch latest IDS alerts
/stats	Alert counts by severity

Example:

json
Copy code
GET /alerts

📊 Detection Capabilities

Signature-Based
Port scanning behavior
Excessive DNS querying
Abnormal traffic volume spikes
Anomaly-Based
Learns baseline traffic patterns
Detects statistically abnormal flows using Isolation Forest

🛠️ Tech Stack

Python 3
PyShark
FastAPI
SQLite
Scikit-learn
Isolation Forest

🔮 Future Improvements

Live packet capture support
Threat intelligence integration
Visualization dashboard
Host-based log correlation
Alert correlation and severity scoring

📜 License
This project is intended for educational and research purposes.