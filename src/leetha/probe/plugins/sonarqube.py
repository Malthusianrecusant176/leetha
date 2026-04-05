"""SonarQube probe plugin — HTTP GET /api/system/status to detect SonarQube."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SonarQubeProbePlugin(ServiceProbe):
    name = "sonarqube"
    protocol = "tcp"
    default_ports = [9000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/system/status HTTP/1.0\r\n"
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

            # SonarQube status has "id", "version", and "status"
            if "id" not in info or "version" not in info or "status" not in info:
                return None

            version = info["version"]
            metadata: dict = {
                "id": info["id"],
                "version": version,
                "status": info["status"],
            }

            return ServiceIdentity(
                service="sonarqube",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
