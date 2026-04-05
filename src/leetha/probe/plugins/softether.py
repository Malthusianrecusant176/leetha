"""SoftEther VPN probe plugin — detects SoftEther VPN server."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SoftEtherProbePlugin(ServiceProbe):
    name = "softether"
    protocol = "tcp"
    default_ports = [443, 992, 5555]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # SoftEther VPN uses a custom protocol that starts with an HTTP-like
            # handshake. Send an HTTP GET to detect SoftEther indicators.
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())

            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            metadata: dict = {}

            # Check for SoftEther markers
            softether_markers = [
                "softether",
                "SoftEther VPN",
                "PacketiX",
                "vpnserver",
                "SE-VPN",
            ]

            found_markers = []
            for marker in softether_markers:
                if marker.lower() in resp_lower:
                    found_markers.append(marker)

            if not found_markers:
                return None

            metadata["markers"] = found_markers

            status_match = self._STATUS_RE.match(response)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            # Try to extract version
            ver_match = re.search(
                r"SoftEther VPN[/ ]([\d.]+)", response, re.IGNORECASE
            )
            version = None
            if ver_match:
                version = ver_match.group(1)
                metadata["softether_version"] = version

            return ServiceIdentity(
                service="softether",
                certainty=75,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
