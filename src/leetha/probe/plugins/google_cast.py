"""Google Cast probe plugin — Eureka info endpoint detection."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GoogleCastProbePlugin(ServiceProbe):
    name = "google_cast"
    protocol = "tcp"
    default_ports = [8008, 8009]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /setup/eureka_info HTTP/1.0\r\n"
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

            # Check for Cast device indicators
            if "name" not in obj and "cast" not in response.lower():
                return None

            metadata: dict = {}
            version = None

            if "name" in obj:
                metadata["device_name"] = obj["name"]
            if "cast_build_revision" in obj:
                version = obj["cast_build_revision"]
            if "model_name" in obj:
                metadata["model_name"] = obj["model_name"]
            if "ssid" in obj:
                metadata["ssid"] = obj["ssid"]

            return ServiceIdentity(
                service="google_cast",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
