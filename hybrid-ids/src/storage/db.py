import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional
from .models import CREATE_ALERTS_TABLE, CREATE_FLOWS_TABLE, CREATE_INDEXES

def get_conn(db_path: str = "data/db/ids.db") -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute(CREATE_FLOWS_TABLE)
    cur.execute(CREATE_ALERTS_TABLE)
    for stmt in CREATE_INDEXES.strip().split(";"):
        if stmt.strip():
            cur.execute(stmt)
    conn.commit()

def insert_alert(
    conn: sqlite3.Connection,
    time: str,
    alert_type: str,
    severity: str,
    confidence: float,
    src_ip: Optional[str],
    dst_ip: Optional[str],
    evidence_json: str,
) -> int:
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO alerts(time, alert_type, severity, confidence, src_ip, dst_ip, evidence_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (time, alert_type, severity, confidence, src_ip, dst_ip, evidence_json),
    )
    conn.commit()
    return int(cur.lastrowid)

def insert_flow(
    conn: sqlite3.Connection,
    window_start: str,
    window_end: str,
    src_ip: Optional[str],
    dst_ip: Optional[str],
    protocol: Optional[str],
    pkt_count: int,
    byte_count: int,
    unique_dst_ports: int,
    syn_count: int,
    rst_count: int,
    dns_query_count: int,
    failed_login_count: int,
    features_json: str,
) -> int:
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO flows(
            window_start, window_end, src_ip, dst_ip, protocol,
            pkt_count, byte_count, unique_dst_ports, syn_count, rst_count,
            dns_query_count, failed_login_count, features_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            window_start, window_end, src_ip, dst_ip, protocol,
            pkt_count, byte_count, unique_dst_ports, syn_count, rst_count,
            dns_query_count, failed_login_count, features_json
        ),
    )
    conn.commit()
    return int(cur.lastrowid)

def fetch_latest_alerts(conn: sqlite3.Connection, limit: int = 50) -> list[Dict[str, Any]]:
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM alerts ORDER BY time DESC, id DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    return [dict(r) for r in rows]