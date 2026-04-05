"""Nuclio probe plugin — HTTP GET /api/versions for Nuclio serverless detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NuclioProbePlugin(ServiceProbe):
    name = "nuclio"
    protocol = "tcp"
    default_ports = [8070]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/versions HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for Nuclio markers
            resp_lower = response.lower()
            has_nuclio = "nuclio" in resp_lower

            if not has_nuclio:
                return None

            metadata: dict = {}
            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="nuclio",
                        certainty=65,
                        metadata=metadata,
                    )
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            if body:
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        if "dashboard" in info:
                            dashboard = info["dashboard"]
                            if isinstance(dashboard, dict):
                                if "label" in dashboard:
                                    version = dashboard["label"]
                                    metadata["label"] = version
                                if "gitCommit" in dashboard:
                                    metadata["git_commit"] = dashboard["gitCommit"]
                                if "arch" in dashboard:
                                    metadata["arch"] = dashboard["arch"]
                            else:
                                version = str(dashboard)
                        if "label" in info:
                            version = info["label"]
                            metadata["label"] = version
                        if "gitCommit" in info:
                            metadata["git_commit"] = info["gitCommit"]
                        if "arch" in info:
                            metadata["arch"] = info["arch"]
                except (json.JSONDecodeError, ValueError):
                    pass

            return ServiceIdentity(
                service="nuclio",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
