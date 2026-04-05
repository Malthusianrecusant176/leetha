"""TCP SYN fingerprint parser."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_tcp_syn(packet) -> CapturedPacket | None:
    """Extract TCP SYN fingerprint data from a scapy packet.

    Only matches pure SYN packets (SYN flag set, ACK flag clear).
    Extracts TTL, window size, MSS, TCP options, and window scale
    for OS fingerprinting via p0f-style signatures.
    """
    try:
        from scapy.layers.inet import IP, TCP
    except ImportError:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    ip = packet[IP]

    # Pure SYN only — SYN set, ACK clear
    if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
        return None

    options = []
    mss = None
    window_scale = None
    for opt_name, opt_val in tcp.options:
        if opt_name == "MSS":
            mss = opt_val
            options.append("M")
        elif opt_name == "NOP":
            options.append("N")
        elif opt_name == "WScale":
            window_scale = opt_val
            options.append("W")
        elif opt_name == "Timestamp":
            options.append("T")
        elif opt_name == "SAckOK":
            options.append("S")
        elif opt_name == "EOL":
            options.append("E")
        else:
            options.append("?")

    return CapturedPacket(
        protocol="tcp_syn",
        hw_addr=packet.src,
        ip_addr=ip.src,
        target_ip=ip.dst,
        target_hw=packet.dst,
        fields={
            "ttl": ip.ttl,
            "window_size": tcp.window,
            "mss": mss,
            "tcp_options": ",".join(options),
            "window_scale": window_scale,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )
