"""OpenWhisk probe plugin — HTTP GET /api/v1 for Apache OpenWhisk detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OpenWhiskProbePlugin(ServiceProbe):
    name = "openwhisk"
    protocol = "tcp"
    default_ports = [443, 3233]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/v1 HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for OpenWhisk markers
            resp_lower = response.lower()
            has_openwhisk = "openwhisk" in resp_lower or "whisk" in resp_lower

            if not has_openwhisk:
                return None

            metadata: dict = {}
            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="openwhisk",
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
                        if "api_paths" in info:
                            metadata["api_paths"] = info["api_paths"]
                        if "description" in info:
                            metadata["description"] = info["description"]
                        if "build" in info:
                            version = info["build"]
                            metadata["build"] = version
                        if "runtimes" in info:
                            if isinstance(info["runtimes"], dict):
                                metadata["runtime_count"] = len(info["runtimes"])
                            elif isinstance(info["runtimes"], list):
                                metadata["runtime_count"] = len(info["runtimes"])
                        if "support" in info and isinstance(info["support"], dict):
                            if "github" in info["support"]:
                                metadata["github"] = info["support"]["github"]
                except (json.JSONDecodeError, ValueError):
                    pass

            return ServiceIdentity(
                service="openwhisk",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
