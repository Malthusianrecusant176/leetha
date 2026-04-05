"""Calico probe plugin — HTTP GET /readiness for Calico/Felix detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CalicoProbePlugin(ServiceProbe):
    name = "calico"
    protocol = "tcp"
    default_ports = [9099]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /readiness HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for calico/felix markers
            resp_lower = response.lower()
            has_calico = "calico" in resp_lower or "felix" in resp_lower

            if not has_calico:
                return None

            metadata: dict = {}
            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="calico",
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
                        if "felix" in info:
                            metadata["component"] = "felix"
                        if "ready" in info:
                            metadata["ready"] = info["ready"]
                        if "version" in info:
                            version = info["version"]
                            metadata["version"] = version
                except (json.JSONDecodeError, ValueError):
                    pass

            # Check status code for readiness
            status_line = response.split("\r\n")[0]
            if "200" in status_line:
                metadata["ready"] = metadata.get("ready", True)
            elif "503" in status_line:
                metadata["ready"] = False

            return ServiceIdentity(
                service="calico",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
