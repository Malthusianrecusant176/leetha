"""Nutanix Prism probe plugin — HTTPS GET /api/nutanix/v3/clusters to detect Nutanix."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NutanixProbePlugin(ServiceProbe):
    name = "nutanix"
    protocol = "tcp"
    default_ports = [9440]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/nutanix/v3/clusters HTTP/1.1\r\n"
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

            # Must contain Nutanix or Prism indicators
            if "nutanix" not in resp_lower and "prism" not in resp_lower:
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
                        if "entities" in info:
                            metadata["entity_count"] = len(info["entities"])
                        ver = info.get("version") or info.get("api_version")
                        if ver:
                            version = str(ver)
                            metadata["api_version"] = version
                except (json.JSONDecodeError, ValueError):
                    pass

            # Check headers for Nutanix server info
            server_match = re.search(
                r"Server:\s*([^\r\n]+)", response, re.IGNORECASE
            )
            if server_match:
                metadata["server"] = server_match.group(1).strip()

            return ServiceIdentity(
                service="nutanix",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
