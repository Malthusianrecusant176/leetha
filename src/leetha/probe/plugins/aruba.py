"""Aruba Networks probe plugin — HTTP GET to detect Aruba wireless controllers."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ArubaProbePlugin(ServiceProbe):
    name = "aruba"
    protocol = "tcp"
    default_ports = [4343, 443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _MARKERS = [
        "aruba",
        "arubanetworks",
        "aruba networks",
        "ArubaOS",
        "Aruba Instant",
        "aruba-sec",
    ]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /screens/wms/wms.login HTTP/1.0\r\n"
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

            # Check for Aruba markers
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

            # Try to extract ArubaOS version
            version = None
            ver_match = re.search(
                r"ArubaOS[/ ]([\d.]+)", response, re.IGNORECASE
            )
            if ver_match:
                version = ver_match.group(1)
                metadata["arubaos_version"] = version

            return ServiceIdentity(
                service="aruba",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
