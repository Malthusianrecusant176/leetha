"""AirPlay probe plugin — Apple AirPlay detection via /info."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class AirPlayProbePlugin(ServiceProbe):
    name = "airplay"
    protocol = "tcp"
    default_ports = [7000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /info HTTP/1.0\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Find JSON body after headers
            parts = response.split("\r\n\r\n", 1)
            if len(parts) < 2:
                return None

            body = parts[1]
            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            # Must contain AirPlay-characteristic fields
            if "deviceid" not in info and "model" not in info and "features" not in info:
                return None

            metadata: dict = {}
            version = None

            if "deviceid" in info:
                metadata["device_id"] = info["deviceid"]
            if "model" in info:
                metadata["model"] = info["model"]
            if "features" in info:
                metadata["features"] = info["features"]
            if "srcvers" in info:
                version = info["srcvers"]

            return ServiceIdentity(
                service="airplay",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
