"""CAS (Central Authentication Service) probe plugin — detect CAS login page."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CASProbePlugin(ServiceProbe):
    name = "cas"
    protocol = "tcp"
    default_ports = [443, 8443]

    _CAS_RE = re.compile(r"(?:cas|Central\s+Authentication\s+Service)", re.IGNORECASE)
    _EXEC_RE = re.compile(r'name="execution"\s+value="([^"]*)"')
    _LT_RE = re.compile(r'name="lt"\s+value="([^"]*)"')
    _VERSION_RE = re.compile(r"CAS\s+([0-9]+(?:\.[0-9]+)*)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /cas/login HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(16384)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            if not self._CAS_RE.search(response):
                return None

            metadata: dict = {"protocol": "cas"}
            version = None

            exec_match = self._EXEC_RE.search(response)
            if exec_match:
                metadata["execution"] = exec_match.group(1)

            lt_match = self._LT_RE.search(response)
            if lt_match:
                metadata["lt"] = lt_match.group(1)

            ver_match = self._VERSION_RE.search(response)
            if ver_match:
                version = ver_match.group(1)

            return ServiceIdentity(
                service="cas",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
