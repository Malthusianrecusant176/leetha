"""Rancher probe plugin — HTTP GET /v3 to detect Rancher server."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RancherProbePlugin(ServiceProbe):
    name = "rancher"
    protocol = "tcp"
    default_ports = [443, 8443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v3 HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            # Must contain Rancher indicator
            if "rancher" not in resp_lower:
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:].strip()
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        if "type" in info:
                            metadata["api_type"] = info["type"]
                        if "apiVersion" in info:
                            metadata["api_version"] = info["apiVersion"]
                        # Rancher API collections have links
                        if "links" in info:
                            metadata["has_links"] = True
                except (json.JSONDecodeError, ValueError):
                    pass

            # Try to extract version from headers
            ver_match = re.search(
                r"[Rr]ancher[/ ](v?[\d.]+)", response
            )
            if ver_match:
                version = ver_match.group(1)

            return ServiceIdentity(
                service="rancher",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
