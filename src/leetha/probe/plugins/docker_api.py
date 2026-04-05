"""Docker API probe plugin — HTTP GET /version for Docker daemon detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DockerAPIProbePlugin(ServiceProbe):
    name = "docker_api"
    protocol = "tcp"
    default_ports = [2375, 2376]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /version HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
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

            # Check for Docker-specific fields
            if not isinstance(info, dict):
                return None

            has_api_version = "ApiVersion" in info
            has_version = "Version" in info
            has_os = "Os" in info
            has_arch = "Arch" in info

            if not (has_api_version or has_version):
                return None

            metadata: dict = {}
            version = None

            if has_version:
                metadata["version"] = info["Version"]
                version = info["Version"]
            if has_api_version:
                metadata["api_version"] = info["ApiVersion"]
            if has_os:
                metadata["os"] = info["Os"]
            if has_arch:
                metadata["arch"] = info["Arch"]
            if "GoVersion" in info:
                metadata["go_version"] = info["GoVersion"]
            if "MinAPIVersion" in info:
                metadata["min_api_version"] = info["MinAPIVersion"]

            return ServiceIdentity(
                service="docker_api",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
