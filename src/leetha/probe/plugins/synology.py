"""Synology DSM probe plugin — HTTP GET to detect Synology NAS via SYNO API."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SynologyProbePlugin(ServiceProbe):
    name = "synology"
    protocol = "tcp"
    default_ports = [5000, 5001]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _MARKERS = [
        "syno",
        "synology",
        "SYNO.API",
        "DiskStation",
        "RackStation",
    ]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /webapi/query.cgi?api=SYNO.API.Info&version=1&method=query HTTP/1.0\r\n"
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

            # Check for Synology markers
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

            # Try to extract DSM version
            version = None
            ver_match = re.search(
                r'"version"\s*:\s*"?(\d+)"?', response
            )
            if ver_match:
                version = f"DSM API v{ver_match.group(1)}"
                metadata["api_version"] = ver_match.group(1)

            return ServiceIdentity(
                service="synology",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
