"""Matrix federation probe plugin — version endpoint detection."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MatrixProbePlugin(ServiceProbe):
    name = "matrix"
    protocol = "tcp"
    default_ports = [8448, 443]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send HTTP GET request to Matrix federation version endpoint
            request = (
                f"GET /_matrix/federation/v1/version HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            # Must be an HTTP response
            if not text.startswith("HTTP/"):
                return None

            # Extract the JSON body
            body_start = text.find("\r\n\r\n")
            if body_start < 0:
                return None

            body = text[body_start + 4:]
            metadata = {}
            version = None

            try:
                info = json.loads(body)
                server_info = info.get("server", {})
                if isinstance(server_info, dict):
                    name = server_info.get("name")
                    ver = server_info.get("version")
                    if name:
                        metadata["server_name"] = name
                    if ver:
                        version = ver
                        metadata["server_version"] = ver
                else:
                    return None
            except (json.JSONDecodeError, ValueError):
                # Check for Matrix-like indicators in headers
                if "matrix" not in text.lower() and "synapse" not in text.lower():
                    return None
                metadata["parse_error"] = True

            # Must have found a server name or a parse-error fallback
            if not metadata:
                return None

            return ServiceIdentity(
                service="matrix",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
