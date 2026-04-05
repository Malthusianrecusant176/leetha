"""Nexus Repository Manager probe plugin — HTTP GET /service/rest/v1/status."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NexusRMProbePlugin(ServiceProbe):
    name = "nexus_rm"
    protocol = "tcp"
    default_ports = [8081]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /service/rest/v1/status HTTP/1.0\r\n"
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

            # Nexus uses "Nexus" or "Sonatype" in Server header
            is_nexus = "Nexus" in server or "Sonatype" in server

            # Check HTTP status line for 200 OK
            if not response.startswith("HTTP/"):
                return None

            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    if is_nexus:
                        return ServiceIdentity(
                            service="nexus_rm",
                            certainty=70,
                            metadata={"server": server},
                            banner=response[:512],
                        )
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
                    if isinstance(info, dict):
                        if "edition" in info:
                            metadata["edition"] = info["edition"]
                        if "version" in info:
                            version = info["version"]
                            metadata["version"] = version
                        if version or "edition" in info:
                            return ServiceIdentity(
                                service="nexus_rm",
                                certainty=90,
                                version=version,
                                metadata=metadata,
                                banner=response[:512],
                            )
                except (json.JSONDecodeError, ValueError):
                    pass

            if is_nexus:
                metadata["server"] = server
                return ServiceIdentity(
                    service="nexus_rm",
                    certainty=75,
                    version=version,
                    metadata=metadata,
                    banner=response[:512],
                )

            return None
        except (socket.timeout, OSError):
            return None
