"""phpMyAdmin probe plugin — HTTP GET / to detect phpMyAdmin login page."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PhpMyAdminProbePlugin(ServiceProbe):
    name = "phpmyadmin"
    protocol = "tcp"
    default_ports = [80, 443]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)
    _PMA_RE = re.compile(r"(?:pmahomme|phpMyAdmin|PMA_)", re.IGNORECASE)
    _VERSION_RE = re.compile(r"phpMyAdmin\s+([\d.]+)", re.IGNORECASE)

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

            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return None
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:]

            if not self._PMA_RE.search(body):
                return None

            metadata: dict = {"login_page": True}
            version = None

            ver_match = self._VERSION_RE.search(body)
            if ver_match:
                version = ver_match.group(1)
                metadata["version"] = version

            return ServiceIdentity(
                service="phpmyadmin",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
