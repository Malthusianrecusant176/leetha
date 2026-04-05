"""Prometheus probe plugin — HTTP GET /api/v1/status/buildinfo for Prometheus detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PrometheusProbePlugin(ServiceProbe):
    name = "prometheus"
    protocol = "tcp"
    default_ports = [9090]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/v1/status/buildinfo HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Find JSON body after HTTP headers
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

            # Prometheus wraps data in {"status":"success","data":{...}}
            build_data = info.get("data", info)
            if not isinstance(build_data, dict):
                return None

            version = build_data.get("version")
            go_version = build_data.get("goVersion")

            if not version and not go_version:
                return None

            metadata: dict = {}
            if version:
                metadata["version"] = version
            if go_version:
                metadata["go_version"] = go_version
            if "revision" in build_data:
                metadata["revision"] = build_data["revision"]
            if "branch" in build_data:
                metadata["branch"] = build_data["branch"]

            return ServiceIdentity(
                service="prometheus",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
