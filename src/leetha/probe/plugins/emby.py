"""Emby/Jellyfin probe plugin — media server detection via /System/Info/Public."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class EmbyProbePlugin(ServiceProbe):
    name = "emby"
    protocol = "tcp"
    default_ports = [8096, 8920]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /System/Info/Public HTTP/1.0\r\n"
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

            # Must have characteristic fields
            if "ServerName" not in info and "Version" not in info and "Id" not in info:
                return None

            metadata: dict = {}
            version = None

            if "ServerName" in info:
                metadata["server_name"] = info["ServerName"]
            if "Id" in info:
                metadata["server_id"] = info["Id"]
            if "Version" in info:
                version = info["Version"]
            if "ProductName" in info:
                metadata["product"] = info["ProductName"]

            return ServiceIdentity(
                service="emby",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
