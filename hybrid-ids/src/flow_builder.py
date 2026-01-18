from __future__ import annotations
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, Iterable, List, Optional, Tuple, Any, Set
from parser import Event

def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts).astimezone(timezone.utc)

def _floor_time(dt: datetime, window_seconds: int) -> datetime:
    epoch = int(dt.timestamp())
    floored = epoch - (epoch % window_seconds)
    return datetime.fromtimestamp(floored, tz=timezone.utc)

@dataclass
class Flow:
    window_start: str
    window_end: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: Optional[str]
    pkt_count: int
    byte_count: int
    unique_dst_ports: int
    syn_count: int
    rst_count: int
    dns_query_count: int
    failed_login_count: int  
    features_json: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def build_flows(events: Iterable[Event], window_seconds: int = 10) -> List[Flow]:
    buckets: Dict[Tuple[datetime, Optional[str], Optional[str], Optional[str]], Dict[str, Any]] = {}
    for ev in events:
        dt = _parse_iso(ev.ts)
        wstart = _floor_time(dt, window_seconds)
        wend = wstart + timedelta(seconds=window_seconds)

        key = (wstart, ev.src_ip, ev.dst_ip, ev.protocol)
        if key not in buckets:
            buckets[key] = {
                "pkt_count": 0,
                "byte_count": 0,
                "dst_ports": set(),   
                "syn_count": 0,
                "rst_count": 0,
                "dns_query_count": 0,
                "failed_login_count": 0,
                "tcp_flag_samples": [],
                "dns_qnames": [],
            }

        b = buckets[key]
        b["pkt_count"] += 1
        b["byte_count"] += int(ev.length_bytes or 0)

        if ev.dst_port is not None:
            b["dst_ports"].add(int(ev.dst_port))

        if ev.protocol == "TCP" and ev.tcp_flags:
            flags = str(ev.tcp_flags).upper()
            if "SYN" in flags or flags == "0X00000002":
                b["syn_count"] += 1
            if "RST" in flags or flags == "0X00000004":
                b["rst_count"] += 1
            if len(b["tcp_flag_samples"]) < 5:
                b["tcp_flag_samples"].append(flags)

        if ev.dns_qname:
            b["dns_query_count"] += 1
            if len(b["dns_qnames"]) < 5:
                b["dns_qnames"].append(str(ev.dns_qname))

    flows: List[Flow] = []
    for (wstart, src_ip, dst_ip, proto), b in buckets.items():
        wend = wstart + timedelta(seconds=window_seconds)

        features = {
            "tcp_flag_samples": b["tcp_flag_samples"],
            "dns_qnames_sample": b["dns_qnames"],
        }

        flows.append(
            Flow(
                window_start=wstart.isoformat(),
                window_end=wend.isoformat(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto,
                pkt_count=b["pkt_count"],
                byte_count=b["byte_count"],
                unique_dst_ports=len(b["dst_ports"]),
                syn_count=b["syn_count"],
                rst_count=b["rst_count"],
                dns_query_count=b["dns_query_count"],
                failed_login_count=b["failed_login_count"],
                features_json=json.dumps(features),
            )
        )

    flows.sort(key=lambda f: (f.window_start, f.src_ip or "", f.dst_ip or "", f.protocol or ""))
    return flows