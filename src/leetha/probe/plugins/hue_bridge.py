"""Philips Hue Bridge probe plugin — /api/config endpoint."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HueBridgeProbePlugin(ServiceProbe):
    name = "hue_bridge"
    protocol = "tcp"
    default_ports = [80, 443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/config HTTP/1.0\r\n"
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

            # Check for Hue Bridge indicators
            has_indicator = (
                "modelid" in obj
                or "bridgeid" in obj
                or "name" in obj and "hue" in response.lower()
            )
            if not has_indicator:
                return None

            metadata: dict = {}
            version = None

            if "name" in obj:
                metadata["name"] = obj["name"]
            if "modelid" in obj:
                metadata["modelid"] = obj["modelid"]
            if "bridgeid" in obj:
                metadata["bridgeid"] = obj["bridgeid"]
            if "swversion" in obj:
                version = obj["swversion"]
            if "apiversion" in obj:
                metadata["apiversion"] = obj["apiversion"]
            if "mac" in obj:
                metadata["mac"] = obj["mac"]

            return ServiceIdentity(
                service="hue_bridge",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
