from __future__ import annotations
import json
from fastapi import FastAPI
from typing import List
from src.storage.db import get_conn, fetch_latest_alerts
from src.api.schemas import AlertOut, HealthOut

app = FastAPI(
    title="Hybrid IDS API",
    description="Hybrid Intrusion Detection System (PCAP + Logs)",
    version="1.0",
)

@app.get("/health", response_model=HealthOut)
def health():
    return {"status": "ok"}

@app.get("/alerts", response_model=List[AlertOut])
def get_alerts(limit: int = 50):
    conn = get_conn()
    rows = fetch_latest_alerts(conn, limit=limit)
    alerts = []
    for r in rows:
        alerts.append(
            AlertOut(
                id=r["id"],
                time=r["time"],
                alert_type=r["alert_type"],
                severity=r["severity"],
                confidence=r["confidence"],
                src_ip=r["src_ip"],
                dst_ip=r["dst_ip"],
                evidence_json=json.loads(r["evidence_json"]),
            )
        )
    return alerts

@app.get("/stats")
def stats():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
    rows = cur.fetchall()
    return {r["severity"]: r["cnt"] for r in rows}