"""SHOUTcast probe plugin — SHOUTcast streaming server detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SHOUTcastProbePlugin(ServiceProbe):
    name = "shoutcast"
    protocol = "tcp"
    default_ports = [8000]

    _SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
    _SHOUT_RE = re.compile(r"SHOUTcast", re.IGNORECASE)
    _VER_RE = re.compile(r"SHOUTcast\S*?(\d+(?:\.\d+)+)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /admin.cgi HTTP/1.0\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Look for SHOUTcast in Server header or body
            if not self._SHOUT_RE.search(response):
                return None

            metadata: dict = {}
            version = None

            server_match = self._SERVER_RE.search(response)
            if server_match:
                metadata["server"] = server_match.group(1).strip()

            ver_match = self._VER_RE.search(response)
            if ver_match:
                version = ver_match.group(1)
                metadata["shoutcast_version"] = version

            return ServiceIdentity(
                service="shoutcast",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
