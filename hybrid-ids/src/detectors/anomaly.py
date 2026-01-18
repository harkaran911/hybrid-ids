from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from typing import Iterable, List
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from storage.db import insert_alert
from flow_builder import Flow

MODEL_PATH = "data/baseline/iforest.joblib"
SCALER_PATH = "data/baseline/scaler.joblib"

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _flow_to_vector(f: Flow) -> List[float]:
    return [
        f.pkt_count,
        f.byte_count,
        f.unique_dst_ports,
        f.syn_count,
        f.rst_count,
        f.dns_query_count,
        f.failed_login_count,
    ]

def train_baseline(flows: Iterable[Flow]):
    X = np.array([_flow_to_vector(f) for f in flows])
    if len(X) < 10:
        return  

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    model.fit(Xs)

    os.makedirs("data/baseline", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

def load_model():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        return None, None

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler

def detect_anomalies(flows: Iterable[Flow], conn):
    model, scaler = load_model()

    if model is None:
        train_baseline(flows)
        return

    for f in flows:
        x = np.array(_flow_to_vector(f)).reshape(1, -1)
        xs = scaler.transform(x)

        score = model.decision_function(xs)[0]
        pred = model.predict(xs)[0] 

        if pred == -1:
            evidence = {
                "score": float(score),
                "features": {
                    "pkt_count": f.pkt_count,
                    "byte_count": f.byte_count,
                    "unique_dst_ports": f.unique_dst_ports,
                    "syn_count": f.syn_count,
                    "dns_query_count": f.dns_query_count,
                },
                "window": [f.window_start, f.window_end],
            }

            insert_alert(
                conn=conn,
                time=iso_now(),
                alert_type="ANOMALOUS_FLOW",
                severity="HIGH",
                confidence=min(1.0, abs(score)),
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                evidence_json=json.dumps(evidence),
            )