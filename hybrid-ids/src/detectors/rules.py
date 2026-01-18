from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Iterable
from storage.db import insert_alert
from flow_builder import Flow

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def detect_port_scan(flows: Iterable[Flow], conn):
    for f in flows:
        if f.protocol != "TCP":
            continue

        if f.unique_dst_ports >= 10 or f.syn_count >= 15:
            evidence = {
                "unique_dst_ports": f.unique_dst_ports,
                "syn_count": f.syn_count,
                "window": [f.window_start, f.window_end],
            }

            insert_alert(
                conn=conn,
                time=iso_now(),
                alert_type="PORT_SCAN",
                severity="HIGH",
                confidence=0.8,
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                evidence_json=json.dumps(evidence),
            )

def detect_traffic_spike(flows: Iterable[Flow], conn):
    for f in flows:
        if f.pkt_count >= 500 or f.byte_count >= 2_000_000:
            evidence = {
                "pkt_count": f.pkt_count,
                "byte_count": f.byte_count,
                "window": [f.window_start, f.window_end],
            }

            insert_alert(
                conn=conn,
                time=iso_now(),
                alert_type="TRAFFIC_SPIKE",
                severity="MEDIUM",
                confidence=0.6,
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                evidence_json=json.dumps(evidence),
            )

def detect_dns_burst(flows: Iterable[Flow], conn):
    """
    Detects excessive DNS querying (possible beaconing / malware).
    """
    for f in flows:
        if f.dns_query_count >= 20:
            evidence = {
                "dns_query_count": f.dns_query_count,
                "window": [f.window_start, f.window_end],
            }

            insert_alert(
                conn=conn,
                time=iso_now(),
                alert_type="DNS_BURST",
                severity="MEDIUM",
                confidence=0.7,
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                evidence_json=json.dumps(evidence),
            )

def run_rules(flows: Iterable[Flow], conn):
    detect_port_scan(flows, conn)
    detect_traffic_spike(flows, conn)
    detect_dns_burst(flows, conn)