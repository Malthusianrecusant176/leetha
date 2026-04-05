"""HomeKit/HAP probe plugin — Apple HomeKit Accessory Protocol."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HomeKitProbePlugin(ServiceProbe):
    name = "homekit"
    protocol = "tcp"
    default_ports = [51826, 51827]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /accessories HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Content-Type: application/hap+json\r\n"
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
            metadata: dict = {"status_code": status_code}

            # HAP-specific status 470 = Authentication Required
            if status_code == 470:
                metadata["hap_auth_required"] = True
                return ServiceIdentity(
                    service="homekit",
                    certainty=90,
                    metadata=metadata,
                    banner=response[:512],
                )

            if status_code == 200:
                lower = response.lower()
                if "accessories" in lower or "hap" in lower:
                    metadata["accessories_found"] = True
                    return ServiceIdentity(
                        service="homekit",
                        certainty=90,
                        metadata=metadata,
                        banner=response[:512],
                    )

            # Accept other HTTP responses that contain HAP indicators
            lower = response.lower()
            if "hap" in lower or "homekit" in lower or status_code == 470:
                return ServiceIdentity(
                    service="homekit",
                    certainty=70,
                    metadata=metadata,
                    banner=response[:512],
                )

            return None
        except (socket.timeout, OSError):
            return None
