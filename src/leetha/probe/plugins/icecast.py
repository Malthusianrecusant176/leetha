"""Icecast probe plugin — Icecast streaming server detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IcecastProbePlugin(ServiceProbe):
    name = "icecast"
    protocol = "tcp"
    default_ports = [8000]

    _SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
    _ICE_RE = re.compile(r"icecast[/ ]*(\d[\d.]*)?", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET / HTTP/1.0\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Look for icecast in Server header or body
            ice_match = self._ICE_RE.search(response)
            if not ice_match:
                return None

            metadata: dict = {}
            version = None

            server_match = self._SERVER_RE.search(response)
            if server_match:
                metadata["server"] = server_match.group(1).strip()

            if ice_match.group(1):
                version = ice_match.group(1)
                metadata["icecast_version"] = version

            return ServiceIdentity(
                service="icecast",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
