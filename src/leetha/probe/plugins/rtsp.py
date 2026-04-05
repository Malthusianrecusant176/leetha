"""RTSP probe plugin — Real Time Streaming Protocol OPTIONS."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RTSPProbePlugin(ServiceProbe):
    name = "rtsp"
    protocol = "tcp"
    default_ports = [554, 8554]

    _STATUS_RE = re.compile(r"^RTSP/[\d.]+\s+(\d+)")
    _SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
    _PUBLIC_RE = re.compile(r"^Public:\s*(.+)$", re.MULTILINE | re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"OPTIONS rtsp://{conn.host}:{conn.port}/ RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(4096)

            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for RTSP response
            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            metadata: dict = {"status_code": status_code}
            version = None

            # Extract Server header
            server_match = self._SERVER_RE.search(response)
            if server_match:
                version = server_match.group(1).strip()
                metadata["server"] = version

            # Extract Public header (supported methods)
            public_match = self._PUBLIC_RE.search(response)
            if public_match:
                methods = [
                    m.strip() for m in public_match.group(1).split(",")
                ]
                metadata["methods"] = methods

            return ServiceIdentity(
                service="rtsp",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
