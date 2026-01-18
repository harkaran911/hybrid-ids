import argparse
import json
from datetime import datetime, timezone
from utils.logger import setup_logger
from storage.db import get_conn, init_db, insert_alert, insert_flow
from capture_pcap import read_pcap_events
from flow_builder import build_flows
from detectors.rules import run_rules
from detectors.anomaly import detect_anomalies

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def main():
    parser = argparse.ArgumentParser(description="Hybrid IDS (PCAP + exported logs) - MVP")
    parser.add_argument("--pcap", type=str, required=False, help="Path to PCAP file")
    parser.add_argument("--limit", type=int, default=None, help="Max packets to parse (debug)")
    parser.add_argument("--window", type=int, default=10, help="Flow window in seconds")
    args = parser.parse_args()
    logger = setup_logger()
    conn = get_conn()
    init_db(conn)
    logger.info("DB initialized.")
    evidence = {"reason": "startup", "module": "bootstrap"}
    insert_alert(
        conn=conn,
        time=iso_now(),
        alert_type="STARTUP",
        severity="LOW",
        confidence=0.2,
        src_ip=None,
        dst_ip=None,
        evidence_json=json.dumps(evidence),
    )

    if not args.pcap:
        logger.info("No --pcap provided. Done (DB + logging check).")
        return

    logger.info("Reading PCAP: %s", args.pcap)
    events = list(read_pcap_events(args.pcap, limit=args.limit))
    logger.info("Parsed events: %d", len(events))
    flows = build_flows(events, window_seconds=args.window)
    logger.info("Built flows: %d (window=%ds)", len(flows), args.window)

    stored = 0
    for f in flows:
        insert_flow(
            conn=conn,
            window_start=f.window_start,
            window_end=f.window_end,
            src_ip=f.src_ip,
            dst_ip=f.dst_ip,
            protocol=f.protocol,
            pkt_count=f.pkt_count,
            byte_count=f.byte_count,
            unique_dst_ports=f.unique_dst_ports,
            syn_count=f.syn_count,
            rst_count=f.rst_count,
            dns_query_count=f.dns_query_count,
            failed_login_count=f.failed_login_count,
            features_json=f.features_json,
        )
        stored += 1

    logger.info("Stored flows in DB: %d", stored)
    logger.info("Next: rules-based detector will read flows and emit alerts.")
    logger.info("Running rules-based detection...")
    run_rules(flows, conn)
    logger.info("Rules detection complete.")
    logger.info("Running anomaly-based detection...")
    detect_anomalies(flows, conn)
    logger.info("Anomaly detection complete.")

if __name__ == "__main__":
    main()