CREATE_FLOWS_TABLE = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start TEXT NOT NULL,
    window_end   TEXT NOT NULL,

    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,

    pkt_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    unique_dst_ports INTEGER DEFAULT 0,
    syn_count INTEGER DEFAULT 0,
    rst_count INTEGER DEFAULT 0,

    dns_query_count INTEGER DEFAULT 0,
    failed_login_count INTEGER DEFAULT 0,

    features_json TEXT
);
"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,

    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,

    src_ip TEXT,
    dst_ip TEXT,

    evidence_json TEXT
);
"""

CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(time);
CREATE INDEX IF NOT EXISTS idx_flows_window ON flows(window_start, window_end);
"""