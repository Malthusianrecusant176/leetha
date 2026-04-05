"""Plex probe plugin — Plex Media Server detection via /identity."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PlexProbePlugin(ServiceProbe):
    name = "plex"
    protocol = "tcp"
    default_ports = [32400]

    _MACHINE_ID_RE = re.compile(r"machineIdentifier=\"([^\"]+)\"", re.IGNORECASE)
    _VERSION_RE = re.compile(r"version=\"([^\"]+)\"", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /identity HTTP/1.0\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Must contain MediaContainer to be Plex
            if "MediaContainer" not in response:
                return None
            if "machineIdentifier" not in response:
                return None

            metadata: dict = {}
            version = None

            mid = self._MACHINE_ID_RE.search(response)
            if mid:
                metadata["machine_id"] = mid.group(1)

            ver = self._VERSION_RE.search(response)
            if ver:
                version = ver.group(1)

            return ServiceIdentity(
                service="plex",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
