"""GlobalProtect probe plugin — detects Palo Alto GlobalProtect VPN portals."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GlobalProtectProbePlugin(ServiceProbe):
    name = "globalprotect"
    protocol = "tcp"
    default_ports = [443, 4443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _GP_MARKERS = [
        "global-protect",
        "globalprotect",
        "palo alto",
        "panGPClientInfo",
        "cas-application-url",
        "/global-protect/",
        "/ssl-vpn/",
        "PanGP",
    ]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send HTTP GET to GlobalProtect login page
            request = (
                f"GET /global-protect/login.esp HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"User-Agent: PAN GlobalProtect\r\n"
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

            # Check for GlobalProtect markers
            found_markers = []
            for marker in self._GP_MARKERS:
                if marker.lower() in resp_lower:
                    found_markers.append(marker)

            if not found_markers:
                return None

            metadata["markers"] = found_markers

            # Try to extract version info
            ver_match = re.search(r"PanOS[/ ]([\d.]+)", response, re.IGNORECASE)
            version = None
            if ver_match:
                version = ver_match.group(1)
                metadata["panos_version"] = version

            return ServiceIdentity(
                service="globalprotect",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
