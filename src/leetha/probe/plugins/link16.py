"""Link 16 / TADIL-J gateway probe plugin — HTTP GET to detect management interface."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class Link16ProbePlugin(ServiceProbe):
    name = "link16"
    protocol = "tcp"
    default_ports = [5001]

    _TADIL_RE = re.compile(r"(?:TADIL|Link\s*16|JTIDS|MIDS)", re.IGNORECASE)
    _VERSION_RE = re.compile(r"[Vv]ersion[:\s]+([0-9]+(?:\.[0-9]+)*)")

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

            if not self._TADIL_RE.search(response):
                return None

            metadata: dict = {}
            version = None

            ver_match = self._VERSION_RE.search(response)
            if ver_match:
                version = ver_match.group(1)

            if "JTIDS" in response.upper():
                metadata["terminal_type"] = "JTIDS"
            elif "MIDS" in response.upper():
                metadata["terminal_type"] = "MIDS"

            metadata["protocol"] = "link16"

            return ServiceIdentity(
                service="link16",
                certainty=80,
                version=version,
                metadata=metadata,
                banner=response[:256],
            )
        except (socket.timeout, OSError):
            return None
