"""Podman probe plugin — HTTP GET /v4.0.0/libpod/info to detect Podman API."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PodmanProbePlugin(ServiceProbe):
    name = "podman"
    protocol = "tcp"
    default_ports = [8080]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v4.0.0/libpod/info HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            # Must contain Podman indicators
            if "podman" not in resp_lower and "libpod" not in resp_lower:
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:].strip()
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        ver_info = info.get("version", {})
                        if isinstance(ver_info, dict):
                            version = ver_info.get("Version")
                            if "APIVersion" in ver_info:
                                metadata["api_version"] = ver_info["APIVersion"]
                        host_info = info.get("host", {})
                        if isinstance(host_info, dict):
                            if "os" in host_info:
                                metadata["os"] = host_info["os"]
                            if "arch" in host_info:
                                metadata["arch"] = host_info["arch"]
                except (json.JSONDecodeError, ValueError):
                    pass

            return ServiceIdentity(
                service="podman",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
