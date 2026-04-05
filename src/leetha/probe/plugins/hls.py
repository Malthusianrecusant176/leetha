"""HLS probe plugin — HTTP Live Streaming detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HLSProbePlugin(ServiceProbe):
    name = "hls"
    protocol = "tcp"
    default_ports = [80, 443, 8080]

    _SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
    _VERSION_RE = re.compile(r"#EXT-X-VERSION:(\d+)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /stream HTTP/1.0\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Detect M3U8 playlist markers
            if "#EXTM3U" not in response:
                return None
            if "#EXT-X-" not in response:
                return None

            metadata: dict = {}
            version = None

            server_match = self._SERVER_RE.search(response)
            if server_match:
                version = server_match.group(1).strip()
                metadata["server"] = version

            ver_match = self._VERSION_RE.search(response)
            if ver_match:
                metadata["hls_version"] = int(ver_match.group(1))

            return ServiceIdentity(
                service="hls",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
