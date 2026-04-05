"""Grafana probe plugin — HTTP GET /api/health to detect Grafana."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GrafanaProbePlugin(ServiceProbe):
    name = "grafana"
    protocol = "tcp"
    default_ports = [3000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/health HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
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

            body = response[body_start:].strip()
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(info, dict):
                return None

            # Grafana health endpoint returns "database": "ok" and "version"
            if "database" not in info or "version" not in info:
                return None

            version = info["version"]
            metadata: dict = {
                "database": info["database"],
                "version": version,
            }
            if "commit" in info:
                metadata["commit"] = info["commit"]

            return ServiceIdentity(
                service="grafana",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
