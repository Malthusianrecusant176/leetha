"""YARN ResourceManager probe plugin — HTTP GET /ws/v1/cluster/info, detects YARN cluster."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class YARNProbePlugin(ServiceProbe):
    name = "yarn"
    protocol = "tcp"
    default_ports = [8088]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /ws/v1/cluster/info HTTP/1.0\r\n"
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

            # YARN response wraps data in "clusterInfo"
            cluster_info = info.get("clusterInfo")
            if not isinstance(cluster_info, dict):
                return None

            # Require at least one YARN-specific field
            if "hadoopVersion" not in cluster_info and "resourceManagerVersion" not in cluster_info:
                return None

            metadata: dict = {}
            version = None

            if "resourceManagerVersion" in cluster_info:
                version = cluster_info["resourceManagerVersion"]
            if "hadoopVersion" in cluster_info:
                metadata["hadoop_version"] = cluster_info["hadoopVersion"]
            if "state" in cluster_info:
                metadata["state"] = cluster_info["state"]
            if "haState" in cluster_info:
                metadata["ha_state"] = cluster_info["haState"]
            if "id" in cluster_info:
                metadata["cluster_id"] = cluster_info["id"]

            return ServiceIdentity(
                service="yarn",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
