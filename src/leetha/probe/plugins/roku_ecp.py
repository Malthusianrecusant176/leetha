"""Roku ECP probe plugin — External Control Protocol device-info."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RokuECPProbePlugin(ServiceProbe):
    name = "roku_ecp"
    protocol = "tcp"
    default_ports = [8060]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /query/device-info HTTP/1.0\r\n"
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

            # Check for device-info XML indicators
            if "<device-info>" not in response:
                return None

            metadata: dict = {}
            version = None

            # Extract model name
            model_match = re.search(
                r"<model-name>([^<]+)</model-name>", response
            )
            if model_match:
                metadata["model_name"] = model_match.group(1)

            # Extract software version
            sw_match = re.search(
                r"<software-version>([^<]+)</software-version>", response
            )
            if sw_match:
                version = sw_match.group(1)

            # Extract serial number
            serial_match = re.search(
                r"<serial-number>([^<]+)</serial-number>", response
            )
            if serial_match:
                metadata["serial_number"] = serial_match.group(1)

            # Extract friendly name
            name_match = re.search(
                r"<friendly-device-name>([^<]+)</friendly-device-name>", response
            )
            if name_match:
                metadata["device_name"] = name_match.group(1)

            return ServiceIdentity(
                service="roku_ecp",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
