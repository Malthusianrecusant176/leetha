"""Ray cluster probe plugin — HTTP GET to Ray Dashboard API, detects Ray JSON response."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RayProbePlugin(ServiceProbe):
    name = "ray"
    protocol = "tcp"
    default_ports = [6379, 8265]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/cluster_status HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                return None
            body = response[body_start + 4:].strip()
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(info, dict):
                return None

            # Ray cluster_status returns data with ray-specific keys
            has_ray = (
                "result" in info
                or "data" in info
                or "autoscaling_status" in info
            )

            data_section = info.get("data", info)
            if isinstance(data_section, dict):
                has_ray = has_ray or "node_status" in data_section

            if not has_ray:
                return None

            metadata: dict = {}
            version = None

            if "data" in info and isinstance(info["data"], dict):
                d = info["data"]
                if "node_status" in d:
                    metadata["node_status"] = d["node_status"]
                if "ray_version" in d:
                    version = d["ray_version"]
            elif "ray_version" in info:
                version = info["ray_version"]

            return ServiceIdentity(
                service="ray",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
