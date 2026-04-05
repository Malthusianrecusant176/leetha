"""Hikvision probe plugin — ISAPI device info endpoint."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HikvisionProbePlugin(ServiceProbe):
    name = "hikvision"
    protocol = "tcp"
    default_ports = [80, 8000]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /ISAPI/System/deviceInfo HTTP/1.0\r\n"
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
            # Check for Hikvision/ISAPI indicators
            if (
                "<deviceinfo" not in lower
                and "hikvision" not in lower
                and "isapi" not in lower
            ):
                return None

            metadata: dict = {}
            version = None

            # Extract device info fields
            name_match = re.search(
                r"<deviceName>([^<]+)</deviceName>", response, re.IGNORECASE
            )
            if name_match:
                metadata["device_name"] = name_match.group(1)

            model_match = re.search(
                r"<model>([^<]+)</model>", response, re.IGNORECASE
            )
            if model_match:
                metadata["model"] = model_match.group(1)

            fw_match = re.search(
                r"<firmwareVersion>([^<]+)</firmwareVersion>",
                response,
                re.IGNORECASE,
            )
            if fw_match:
                version = fw_match.group(1)

            serial_match = re.search(
                r"<serialNumber>([^<]+)</serialNumber>",
                response,
                re.IGNORECASE,
            )
            if serial_match:
                metadata["serial_number"] = serial_match.group(1)

            mfr_match = re.search(
                r"<manufacturer>([^<]+)</manufacturer>",
                response,
                re.IGNORECASE,
            )
            if mfr_match:
                metadata["manufacturer"] = mfr_match.group(1)

            return ServiceIdentity(
                service="hikvision",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
