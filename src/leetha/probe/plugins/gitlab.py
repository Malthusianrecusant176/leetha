"""GitLab probe plugin — HTTP GET to detect GitLab via API or login page."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GitLabProbePlugin(ServiceProbe):
    name = "gitlab"
    protocol = "tcp"
    default_ports = [80, 443]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)
    _GITLAB_META_RE = re.compile(
        r'<meta\s+[^>]*content=["\'][^"\']*gitlab[^"\']*["\']', re.IGNORECASE,
    )

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/v4/version HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Try JSON API response first
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return None
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            metadata: dict = {}
            version = None
            confidence = 0

            if body:
                try:
                    info = json.loads(body)
                    if isinstance(info, dict) and "version" in info:
                        version = info["version"]
                        metadata["version"] = version
                        if "revision" in info:
                            metadata["revision"] = info["revision"]
                        confidence = 90
                except (json.JSONDecodeError, ValueError):
                    pass

            # Fall back to HTML page detection
            if confidence == 0 and self._GITLAB_META_RE.search(response):
                confidence = 75
                metadata["login_page"] = True

            if confidence == 0:
                return None

            return ServiceIdentity(
                service="gitlab",
                certainty=confidence,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
