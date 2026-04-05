"""pgAdmin probe plugin — HTTP GET /login to detect pgAdmin web interface."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PgAdminProbePlugin(ServiceProbe):
    name = "pgadmin"
    protocol = "tcp"
    default_ports = [80, 443]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)
    _TITLE_RE = re.compile(r"<title[^>]*>([^<]*pgAdmin[^<]*)</title>", re.IGNORECASE)
    _CSRF_RE = re.compile(r'name=["\']csrf_token["\']', re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /login HTTP/1.0\r\n"
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
            metadata: dict = {}
            confidence = 0

            # Check for pgAdmin title
            title_match = self._TITLE_RE.search(body)
            if title_match:
                metadata["title"] = title_match.group(1).strip()
                confidence = 85

            # Check for CSRF token (common in pgAdmin login forms)
            if self._CSRF_RE.search(body) and confidence > 0:
                metadata["has_csrf"] = True
                confidence = 90

            if confidence == 0:
                return None

            return ServiceIdentity(
                service="pgadmin",
                certainty=confidence,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
