"""Kibana probe plugin — HTTP GET /api/status to detect Kibana."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class KibanaProbePlugin(ServiceProbe):
    name = "kibana"
    protocol = "tcp"
    default_ports = [5601]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/status HTTP/1.0\r\n"
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

            body = response[body_start:].strip()
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(info, dict):
                return None

            # Kibana status JSON has "name": "kibana" and version info
            name = info.get("name")
            if name != "kibana":
                return None

            version = None
            metadata: dict = {"name": name}

            ver_info = info.get("version")
            if isinstance(ver_info, dict):
                version = ver_info.get("number")
                metadata["version"] = version
                if "build_hash" in ver_info:
                    metadata["build_hash"] = ver_info["build_hash"]
            elif isinstance(ver_info, str):
                version = ver_info
                metadata["version"] = version

            status = info.get("status")
            if isinstance(status, dict) and "overall" in status:
                metadata["overall_status"] = status["overall"].get("state")

            return ServiceIdentity(
                service="kibana",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
