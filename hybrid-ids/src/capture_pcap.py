from __future__ import annotations
from typing import Iterator, Optional
from pathlib import Path
import pyshark
from parser import Event, parse_pyshark_packet

def read_pcap_events(pcap_path: str, limit: Optional[int] = None) -> Iterator[Event]:
    p = Path(pcap_path)
    if not p.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    cap = pyshark.FileCapture(str(p), keep_packets=False)
    count = 0
    try:
        for pkt in cap:
            ev = parse_pyshark_packet(pkt)
            if ev is None:
                continue

            yield ev
            count += 1

            if limit is not None and count >= limit:
                break
    finally:
        cap.close()