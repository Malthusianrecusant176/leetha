"""TP-Link probe plugin — HTTP GET / to detect TP-Link devices."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TPLinkProbePlugin(ServiceProbe):
    name = "tplink"
    protocol = "tcp"
    default_ports = [80]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _MARKERS = [
        "tp-link",
        "tplink",
        "tplinkwifi",
        "tplinkrepeater",
        "tplinkap",
    ]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET / HTTP/1.0\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())

            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            # Check for TP-Link markers
            found_markers = []
            for marker in self._MARKERS:
                if marker.lower() in resp_lower:
                    found_markers.append(marker)

            if not found_markers:
                return None

            metadata: dict = {"markers": found_markers}

            status_match = self._STATUS_RE.match(response)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            # Try to extract model info from title or body
            version = None
            model_match = re.search(
                r"<title>\s*(.*?TP-Link[^<]*)</title>", response, re.IGNORECASE
            )
            if model_match:
                version = model_match.group(1).strip()
                metadata["model"] = version

            return ServiceIdentity(
                service="tplink",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
