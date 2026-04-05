"""Webmin probe plugin — HTTP GET / to detect Webmin via MiniServ header or login page."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class WebminProbePlugin(ServiceProbe):
    name = "webmin"
    protocol = "tcp"
    default_ports = [10000]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)
    _MINISERV_RE = re.compile(r"MiniServ/([\d.]+)")
    _WEBMIN_PAGE_RE = re.compile(r"Webmin", re.IGNORECASE)

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
            server = headers.get("Server", "")

            metadata: dict = {}
            version = None
            confidence = 0

            # Check for MiniServ in Server header
            miniserv_match = self._MINISERV_RE.search(server)
            if miniserv_match:
                version = miniserv_match.group(1)
                metadata["server"] = server
                metadata["miniserv_version"] = version
                confidence = 90

            # Check body for Webmin login page
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:]
                if self._WEBMIN_PAGE_RE.search(body):
                    if confidence == 0:
                        confidence = 80
                    metadata["login_page"] = True

            if confidence == 0:
                return None

            return ServiceIdentity(
                service="webmin",
                certainty=confidence,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
