"""Apache Spark Master probe plugin — HTTP GET /json/, detects Spark master JSON."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SparkMasterProbePlugin(ServiceProbe):
    name = "spark_master"
    protocol = "tcp"
    default_ports = [7077, 8080]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /json/ HTTP/1.0\r\n"
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

            # Spark master JSON has distinctive keys
            has_spark = (
                ("workers" in info or "activeapps" in info or "activedrivers" in info)
                and ("url" in info or "status" in info)
            )
            if not has_spark:
                return None

            metadata: dict = {}
            version = None

            if "spark.version" in info:
                version = info["spark.version"]
            elif "version" in info:
                version = info["version"]

            if "workers" in info and isinstance(info["workers"], list):
                metadata["worker_count"] = len(info["workers"])
            if "activeapps" in info and isinstance(info["activeapps"], list):
                metadata["active_apps"] = len(info["activeapps"])
            if "status" in info:
                metadata["status"] = info["status"]
            if "url" in info:
                metadata["master_url"] = info["url"]

            return ServiceIdentity(
                service="spark_master",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
