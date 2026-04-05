"""Jenkins CI probe plugin — HTTP GET / to detect Jenkins via X-Jenkins header."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class JenkinsProbePlugin(ServiceProbe):
    name = "jenkins"
    protocol = "tcp"
    default_ports = [8080, 443]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)
    _JENKINS_PAGE_RE = re.compile(r"(?:Jenkins|hudson)", re.IGNORECASE)

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

            headers = dict(self._HEADER_RE.findall(response))

            version = None
            confidence = 0
            metadata: dict = {}

            # Check X-Jenkins header (strongest signal)
            x_jenkins = headers.get("X-Jenkins")
            if x_jenkins:
                version = x_jenkins.strip()
                metadata["x_jenkins"] = version
                confidence = 90

            # Check body for Jenkins login page patterns
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:]
                if self._JENKINS_PAGE_RE.search(body):
                    if confidence == 0:
                        confidence = 75
                    metadata["login_page"] = True

            if confidence == 0:
                return None

            return ServiceIdentity(
                service="jenkins",
                certainty=confidence,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
