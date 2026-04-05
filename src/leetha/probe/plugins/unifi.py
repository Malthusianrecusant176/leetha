"""UniFi Controller probe plugin — HTTP GET to detect Ubiquiti UniFi controllers."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class UniFiProbePlugin(ServiceProbe):
    name = "unifi"
    protocol = "tcp"
    default_ports = [8443, 443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _MARKERS = [
        "unifi",
        "ubnt",
        "ubiquiti",
        "UniFi-Network",
    ]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/s/default/stat/sysinfo HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())

            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            # Check for UniFi markers
            found_markers = []
            for marker in self._MARKERS:
                if marker.lower() in resp_lower:
                    found_markers.append(marker)

            if not found_markers:
                return None

            metadata: dict = {"markers": found_markers}

            status_match = self._STATUS_RE.match(response)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            # Try to extract version
            version = None
            ver_match = re.search(
                r'"version"\s*:\s*"([^"]+)"', response, re.IGNORECASE
            )
            if ver_match:
                version = ver_match.group(1)
                metadata["unifi_version"] = version

            return ServiceIdentity(
                service="unifi",
                certainty=80,
                version=version,
                metadata=metadata,
                banner=response[:256],
            )
        except (socket.timeout, OSError):
            return None
