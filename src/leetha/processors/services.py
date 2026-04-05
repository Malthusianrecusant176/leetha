"""Service fingerprint processor -- TCP SYN, TLS, HTTP User-Agent."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence
from leetha.patterns.tls import lookup_ja3


@register_processor("tcp_syn", "tls", "http_useragent")
class ServiceFingerprintProcessor(Processor):
    """Handles protocols that reveal services, applications, and OS hints."""

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        protocol = packet.protocol
        if protocol == "tcp_syn":
            return self._analyze_tcp_syn(packet)
        elif protocol == "tls":
            return self._analyze_tls(packet)
        elif protocol == "http_useragent":
            return self._analyze_http_useragent(packet)
        return []

    def _analyze_tcp_syn(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        ttl = packet.get("ttl")
        window_size = packet.get("window_size")
        mss = packet.get("mss")
        tcp_options = packet.get("tcp_options", "")

        # TTL-based OS heuristic
        if ttl is not None:
            os_hint = self._ttl_os_hint(ttl)
            evidence.append(Evidence(
                source="tcp_syn_ttl", method="heuristic", certainty=0.50,
                platform=os_hint,
                raw={"ttl": ttl, "os_hint": os_hint},
            ))

        # TCP signature (window + MSS + options) for OS fingerprinting
        if window_size is not None:
            mss_str = str(mss) if mss else "*"
            sig = f"{ttl}:{window_size}:{mss_str}:{tcp_options}"
            evidence.append(Evidence(
                source="tcp_syn_sig", method="pattern", certainty=0.65,
                raw={"signature": sig, "window_size": window_size,
                     "mss": mss, "tcp_options": tcp_options},
            ))

        return evidence

    def _analyze_tls(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        ja3 = packet.get("ja3_hash")
        ja4 = packet.get("ja4")
        sni = packet.get("sni")

        if ja3:
            evidence.append(Evidence(
                source="tls_ja3", method="pattern", certainty=0.75,
                raw={"ja3_hash": ja3},
            ))
            match = lookup_ja3(ja3)
            if match:
                evidence[-1].vendor = match.get("app")
                evidence[-1].platform = match.get("os_family")

        if ja4:
            evidence.append(Evidence(
                source="tls_ja4", method="pattern", certainty=0.75,
                raw={"ja4": ja4},
            ))

        if sni:
            evidence.append(Evidence(
                source="tls_sni", method="exact", certainty=0.70,
                raw={"sni": sni},
            ))

        return evidence

    def _analyze_http_useragent(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        user_agent = packet.get("user_agent")
        host = packet.get("host")

        if user_agent:
            platform, vendor = self._parse_user_agent(user_agent)
            evidence.append(Evidence(
                source="http_useragent", method="pattern", certainty=0.80,
                platform=platform,
                vendor=vendor,
                raw={"user_agent": user_agent},
            ))

        if host:
            evidence.append(Evidence(
                source="http_host", method="pattern", certainty=0.40,
                raw={"host": host},
            ))

        return evidence

    @staticmethod
    def _ttl_os_hint(ttl: int) -> str | None:
        """Derive an OS hint from the initial TTL value.

        TTL is NOT a reliable platform indicator:
        - TTL 64: Linux, iOS, macOS, Android, FreeBSD, most embedded devices
        - TTL 128: Windows, but ALSO Ubiquiti UniFi OS, many routers/switches
        - TTL 255: Network devices (Cisco, etc.)

        We return None for all values — TTL alone should never set platform.
        Real platform identification comes from DHCP, mDNS, DNS, User-Agent.
        """
        # Do not set platform from TTL — too many false positives
        return None
        if ttl <= 64:
            return None  # ambiguous — don't guess
        elif ttl <= 128:
            return "Windows"
        return None

    @staticmethod
    def _parse_user_agent(ua: str) -> tuple[str | None, str | None]:
        """Extract platform and vendor hints from a User-Agent string."""
        ua_lower = ua.lower()
        platform = None
        vendor = None

        if "windows" in ua_lower:
            platform = "Windows"
            vendor = "Microsoft"
        elif "macintosh" in ua_lower or "mac os" in ua_lower:
            platform = "macOS"
            vendor = "Apple"
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            platform = "iOS"
            vendor = "Apple"
        elif "android" in ua_lower:
            platform = "Android"
            vendor = "Google"
        elif "linux" in ua_lower:
            platform = "Linux"
        elif "cros" in ua_lower:
            platform = "ChromeOS"
            vendor = "Google"

        return platform, vendor
