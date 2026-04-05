"""Fission probe plugin — HTTP GET /v2/apidocs.json for Fission serverless detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FissionProbePlugin(ServiceProbe):
    name = "fission"
    protocol = "tcp"
    default_ports = [443]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v2/apidocs.json HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for Fission markers
            resp_lower = response.lower()
            has_fission = "fission" in resp_lower

            if not has_fission:
                return None

            metadata: dict = {}
            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="fission",
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
                        if "info" in info and isinstance(info["info"], dict):
                            api_info = info["info"]
                            if "title" in api_info:
                                metadata["title"] = api_info["title"]
                            if "version" in api_info:
                                version = api_info["version"]
                                metadata["version"] = version
                        if "swagger" in info:
                            metadata["swagger_version"] = info["swagger"]
                        if "basePath" in info:
                            metadata["base_path"] = info["basePath"]
                        if "paths" in info and isinstance(info["paths"], dict):
                            metadata["path_count"] = len(info["paths"])
                except (json.JSONDecodeError, ValueError):
                    pass

            return ServiceIdentity(
                service="fission",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
