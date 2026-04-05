"""pfSense probe plugin — HTTP GET / to detect pfSense login page."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PfSenseProbePlugin(ServiceProbe):
    name = "pfsense"
    protocol = "tcp"
    default_ports = [443, 80]

    _PFSENSE_RE = re.compile(r"(?:pfSense|Login to pfSense)", re.IGNORECASE)
    _LOGO_RE = re.compile(r"pfsense-logo", re.IGNORECASE)

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

            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                return None

            body = response[body_start + 4:]

            has_pfsense = bool(self._PFSENSE_RE.search(body))
            has_logo = bool(self._LOGO_RE.search(body))

            if not has_pfsense and not has_logo:
                return None

            metadata: dict = {"login_page": True}
            confidence = 85 if has_pfsense else 75

            if has_pfsense and has_logo:
                confidence = 90

            return ServiceIdentity(
                service="pfsense",
                certainty=confidence,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
