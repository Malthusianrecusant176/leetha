"""AnyConnect probe plugin — detects Cisco AnyConnect SSL VPN."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class AnyConnectProbePlugin(ServiceProbe):
    name = "anyconnect"
    protocol = "tcp"
    default_ports = [443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _AC_MARKERS = [
        "webvpn",
        "anyconnect",
        "+CSCOE+",
        "+CSCOT+",
        "X-Transcend-Version",
        "Cisco",
        "CSCOSSLC",
    ]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send HTTP request to Cisco AnyConnect endpoint
            request = (
                f"POST /+webvpn+/index.html HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"User-Agent: AnyConnect\r\n"
                f"Content-Length: 0\r\n"
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

            # Check for AnyConnect markers
            found_markers = []
            for marker in self._AC_MARKERS:
                if marker.lower() in resp_lower:
                    found_markers.append(marker)

            if not found_markers:
                return None

            metadata["markers"] = found_markers

            # Check for X-Transcend-Version header (AnyConnect specific)
            transcend_match = re.search(
                r"X-Transcend-Version:\s*(\S+)", response, re.IGNORECASE
            )
            version = None
            if transcend_match:
                version = transcend_match.group(1)
                metadata["transcend_version"] = version

            return ServiceIdentity(
                service="anyconnect",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
