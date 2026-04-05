"""Cockpit probe plugin — HTTP GET / to detect Cockpit web console."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CockpitProbePlugin(ServiceProbe):
    name = "cockpit"
    protocol = "tcp"
    default_ports = [9090]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)
    _COCKPIT_RE = re.compile(r"cockpit-ws", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET / HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            if not response.startswith("HTTP/"):
                return None

            headers = dict(self._HEADER_RE.findall(response))

            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:]
            else:
                body = ""

            # Check for cockpit-ws in headers or body
            found_in_header = False
            found_in_body = False

            server = headers.get("Server", "")
            if self._COCKPIT_RE.search(server):
                found_in_header = True

            if self._COCKPIT_RE.search(body):
                found_in_body = True

            if not found_in_header and not found_in_body:
                return None

            metadata: dict = {}
            if found_in_header:
                metadata["server"] = server

            confidence = 90 if found_in_header else 80

            return ServiceIdentity(
                service="cockpit",
                certainty=confidence,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
