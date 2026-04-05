"""DLNA/UPnP probe plugin — MediaServer/MediaRenderer detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DLNAProbePlugin(ServiceProbe):
    name = "dlna"
    protocol = "tcp"
    default_ports = [8200]

    _DEVICE_TYPE_RE = re.compile(
        r"<deviceType>[^<]*(?:MediaServer|MediaRenderer)[^<]*</deviceType>",
        re.IGNORECASE,
    )
    _FRIENDLY_RE = re.compile(r"<friendlyName>([^<]+)</friendlyName>", re.IGNORECASE)
    _MODEL_RE = re.compile(r"<modelName>([^<]+)</modelName>", re.IGNORECASE)
    _MODEL_NUM_RE = re.compile(r"<modelNumber>([^<]+)</modelNumber>", re.IGNORECASE)
    _SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.MULTILINE | re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /rootDesc.xml HTTP/1.0\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(16384)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Must contain a MediaServer or MediaRenderer device type
            if not self._DEVICE_TYPE_RE.search(response):
                return None

            metadata: dict = {}
            version = None

            friendly = self._FRIENDLY_RE.search(response)
            if friendly:
                metadata["friendly_name"] = friendly.group(1)

            model = self._MODEL_RE.search(response)
            if model:
                metadata["model"] = model.group(1)

            model_num = self._MODEL_NUM_RE.search(response)
            if model_num:
                version = model_num.group(1)

            server = self._SERVER_RE.search(response)
            if server:
                metadata["server"] = server.group(1).strip()

            return ServiceIdentity(
                service="dlna",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
