"""openHAB probe plugin — REST API detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OpenHABProbePlugin(ServiceProbe):
    name = "openhab"
    protocol = "tcp"
    default_ports = [8080, 8443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /rest/ HTTP/1.0\r\n"
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
            lower = response.lower()

            if "openhab" not in lower and '"links"' not in lower:
                return None

            metadata: dict = {"status_code": status_code}
            version = None

            # Try to extract version
            ver_match = re.search(r'"version"\s*:\s*"([^"]+)"', response)
            if ver_match:
                version = ver_match.group(1)

            if "openhab" in lower:
                metadata["openhab_detected"] = True

            return ServiceIdentity(
                service="openhab",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
