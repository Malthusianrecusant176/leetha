"""Sonos probe plugin — ZonePlayer status endpoint."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SonosProbePlugin(ServiceProbe):
    name = "sonos"
    protocol = "tcp"
    default_ports = [1400]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /status/zp HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
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

            lower = response.lower()
            if "zoneplayer" not in lower and "sonos" not in lower:
                return None

            metadata: dict = {}
            version = None

            # Extract ZonePlayer info
            zp_match = re.search(
                r"<ZPInfo[^>]*>", response, re.IGNORECASE
            )
            if zp_match:
                metadata["zoneplayer_info"] = True

            # Extract software version
            sw_match = re.search(
                r"<SoftwareVersion>([^<]+)</SoftwareVersion>", response,
                re.IGNORECASE,
            )
            if sw_match:
                version = sw_match.group(1)

            # Extract zone name
            name_match = re.search(
                r"<ZoneName>([^<]+)</ZoneName>", response, re.IGNORECASE
            )
            if name_match:
                metadata["zone_name"] = name_match.group(1)

            # Extract model number
            model_match = re.search(
                r"<ModelNumber>([^<]+)</ModelNumber>", response, re.IGNORECASE
            )
            if model_match:
                metadata["model_number"] = model_match.group(1)

            return ServiceIdentity(
                service="sonos",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
