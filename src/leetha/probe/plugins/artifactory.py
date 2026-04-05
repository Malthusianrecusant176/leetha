"""JFrog Artifactory probe plugin — HTTP GET /api/system/ping or /api/system/version."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ArtifactoryProbePlugin(ServiceProbe):
    name = "artifactory"
    protocol = "tcp"
    default_ports = [8082, 8081]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/system/version HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            headers = dict(self._HEADER_RE.findall(response))
            server = headers.get("Server", "")

            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return None
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            metadata: dict = {}
            version = None

            if body:
                try:
                    info = json.loads(body)
                    if isinstance(info, dict) and "version" in info:
                        version = info["version"]
                        metadata["version"] = version
                        if "revision" in info:
                            metadata["revision"] = info["revision"]
                        if "license" in info:
                            metadata["license"] = info["license"]
                        return ServiceIdentity(
                            service="artifactory",
                            certainty=90,
                            version=version,
                            metadata=metadata,
                            banner=response[:512],
                        )
                except (json.JSONDecodeError, ValueError):
                    pass

            # Check for "OK" ping response or Artifactory in server header
            if body == "OK" and "Artifactory" in server:
                metadata["server"] = server
                return ServiceIdentity(
                    service="artifactory",
                    certainty=80,
                    metadata=metadata,
                    banner=response[:512],
                )

            if "Artifactory" in server:
                metadata["server"] = server
                return ServiceIdentity(
                    service="artifactory",
                    certainty=70,
                    metadata=metadata,
                    banner=response[:512],
                )

            return None
        except (socket.timeout, OSError):
            return None
