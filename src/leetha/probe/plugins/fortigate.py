"""FortiGate VPN probe plugin — detects Fortinet FortiGate SSL VPN portals."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FortiGateProbePlugin(ServiceProbe):
    name = "fortigate"
    protocol = "tcp"
    default_ports = [443, 10443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _FG_MARKERS = [
        "fortinet",
        "fortigate",
        "fortios",
        "SVPN",
        "fgt_lang",
        "FortiToken",
        "/remote/login",
        "FortiASE_MA",
    ]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send HTTP GET to FortiGate login page
            request = (
                f"GET /remote/login HTTP/1.1\r\n"
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

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            # Check for FortiGate markers
            found_markers = []
            for marker in self._FG_MARKERS:
                if marker.lower() in resp_lower:
                    found_markers.append(marker)

            if not found_markers:
                return None

            metadata["markers"] = found_markers

            # Try to extract version info
            ver_match = re.search(r"FortiOS[/ ]([\d.]+)", response, re.IGNORECASE)
            version = None
            if ver_match:
                version = ver_match.group(1)
                metadata["fortios_version"] = version

            return ServiceIdentity(
                service="fortigate",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
