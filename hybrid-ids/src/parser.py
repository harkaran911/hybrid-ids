from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

@dataclass
class Event:
    ts: str                      
    source: str                 
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]      

    tcp_flags: Optional[str] = None
    dns_qname: Optional[str] = None
    dns_qtype: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def _safe_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None

def _iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def parse_pyshark_packet(pkt: Any) -> Optional[Event]:
    """
    Convert a pyshark packet into our normalized Event.
    Works for PCAP reading via pyshark.FileCapture.
    """
    try:
        ts = _iso_utc(pkt.sniff_time)

        length_bytes = int(getattr(pkt, "length", 0))

        src_ip = None
        dst_ip = None
        protocol = None
        src_port = None
        dst_port = None
        tcp_flags = None
        dns_qname = None
        dns_qtype = None

        if hasattr(pkt, "ip"):
            src_ip = getattr(pkt.ip, "src", None)
            dst_ip = getattr(pkt.ip, "dst", None)

        if src_ip is None and hasattr(pkt, "ipv6"):
            src_ip = getattr(pkt.ipv6, "src", None)
            dst_ip = getattr(pkt.ipv6, "dst", None)

        if hasattr(pkt, "tcp"):
            protocol = "TCP"
            src_port = _safe_int(getattr(pkt.tcp, "srcport", None))
            dst_port = _safe_int(getattr(pkt.tcp, "dstport", None))
            tcp_flags = getattr(pkt.tcp, "flags_str", None) or getattr(pkt.tcp, "flags", None)

        elif hasattr(pkt, "udp"):
            protocol = "UDP"
            src_port = _safe_int(getattr(pkt.udp, "srcport", None))
            dst_port = _safe_int(getattr(pkt.udp, "dstport", None))

        elif hasattr(pkt, "icmp"):
            protocol = "ICMP"

        if hasattr(pkt, "dns"):
            dns_qname = getattr(pkt.dns, "qry_name", None)
            dns_qtype = getattr(pkt.dns, "qry_type", None)
        if not src_ip and not dst_ip:
            return None

        return Event(
            ts=ts,
            source="pcap",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length_bytes=length_bytes,
            tcp_flags=tcp_flags,
            dns_qname=dns_qname,
            dns_qtype=dns_qtype,
        )

    except Exception:
        return None