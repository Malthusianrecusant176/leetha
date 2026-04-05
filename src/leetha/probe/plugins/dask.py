"""Dask Distributed scheduler probe plugin — HTTP or TCP detection of Dask scheduler."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DaskProbePlugin(ServiceProbe):
    name = "dask"
    protocol = "tcp"
    default_ports = [8786, 8787]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /info/main/workers.html HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            # Check for Dask identifiers
            if "dask" not in resp_lower:
                return None

            metadata: dict = {}
            version = None

            # Try to extract version from response
            ver_match = re.search(r"dask[/ ]([\d.]+)", response, re.IGNORECASE)
            if ver_match:
                version = ver_match.group(1)

            # Parse JSON body if present
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:].strip()
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        if "workers" in info:
                            metadata["worker_count"] = len(info["workers"])
                        if "type" in info:
                            metadata["scheduler_type"] = info["type"]
                except (json.JSONDecodeError, ValueError):
                    pass

            if "scheduler" in resp_lower:
                metadata["scheduler_detected"] = True

            return ServiceIdentity(
                service="dask",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
