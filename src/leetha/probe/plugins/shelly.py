"""Shelly device probe plugin — /shelly endpoint detection."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ShellyProbePlugin(ServiceProbe):
    name = "shelly"
    protocol = "tcp"
    default_ports = [80]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /shelly HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(4096)

            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            if status_code != 200:
                return None

            # Find JSON body
            body_start = response.find("\r\n\r\n")
            if body_start == -1:
                return None
            body = response[body_start + 4:].strip()
            if not body:
                return None

            try:
                obj = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(obj, dict):
                return None

            # Check for Shelly indicators
            if "type" not in obj and "mac" not in obj:
                return None

            metadata: dict = {}
            version = None

            if "type" in obj:
                metadata["type"] = obj["type"]
            if "mac" in obj:
                metadata["mac"] = obj["mac"]
            if "fw" in obj:
                version = obj["fw"]
            if "auth" in obj:
                metadata["auth"] = obj["auth"]
            if "gen" in obj:
                metadata["gen"] = obj["gen"]

            return ServiceIdentity(
                service="shelly",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
