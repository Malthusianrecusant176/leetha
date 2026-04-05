"""HTTP probe plugin — sends HEAD request, parses response headers."""

from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HTTPProbePlugin(ServiceProbe):
    name = "http"
    protocol = "tcp"
    default_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = f"HEAD / HTTP/1.0\r\nHost: {conn.host}\r\nConnection: close\r\n\r\n"
            conn.write(request.encode())
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            headers = dict(self._HEADER_RE.findall(response))

            metadata: dict = {"status_code": status_code}
            server = headers.get("Server") or headers.get("server")
            if server:
                metadata["server"] = server

            powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
            if powered_by:
                metadata["powered_by"] = powered_by

            return ServiceIdentity(
                service="http",
                version=server,
                banner=response[:512],
                metadata=metadata,
                certainty=85,
            )
        except (socket.timeout, OSError):
            return None
