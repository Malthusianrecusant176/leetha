"""Nexus probe plugin — HTTP GET /service/rest/v1/status for Sonatype Nexus detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NexusProbePlugin(ServiceProbe):
    name = "nexus"
    protocol = "tcp"
    default_ports = [8081]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /service/rest/v1/status HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for Nexus markers
            resp_lower = response.lower()
            has_nexus = "nexus" in resp_lower or "sonatype" in resp_lower

            if not has_nexus:
                return None

            metadata: dict = {}
            version = None

            # Extract server header
            for line in response.split("\r\n"):
                lower_line = line.lower()
                if lower_line.startswith("server:"):
                    server_val = line.split(":", 1)[1].strip()
                    metadata["server"] = server_val
                    # Try to extract version from server header
                    if "nexus" in server_val.lower():
                        parts = server_val.split("/")
                        if len(parts) > 1:
                            version = parts[1].strip().split(" ")[0]

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="nexus",
                        certainty=70,
                        version=version,
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
                        if "version" in info:
                            version = info["version"]
                            metadata["version"] = version
                        if "edition" in info:
                            metadata["edition"] = info["edition"]
                except (json.JSONDecodeError, ValueError):
                    pass

            return ServiceIdentity(
                service="nexus",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
