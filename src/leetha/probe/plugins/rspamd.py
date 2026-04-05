"""Rspamd probe plugin — spam filter HTTP API detection."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RspamdProbePlugin(ServiceProbe):
    name = "rspamd"
    protocol = "tcp"
    default_ports = [11333, 11334]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /stat HTTP/1.0\r\n"
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
                stats = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            # Must contain Rspamd-characteristic stat fields
            if "scanned" not in stats and "learned" not in stats:
                return None

            metadata: dict = {}
            version = None

            if "scanned" in stats:
                metadata["scanned"] = stats["scanned"]
            if "learned" in stats:
                metadata["learned"] = stats["learned"]
            if "version" in stats:
                version = stats["version"]

            return ServiceIdentity(
                service="rspamd",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
