"""Proxmox VE probe plugin — HTTPS GET /api2/json to detect Proxmox VE."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ProxmoxVEProbePlugin(ServiceProbe):
    name = "proxmox_ve"
    protocol = "tcp"
    default_ports = [8006]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api2/json HTTP/1.1\r\n"
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

            # Look for Proxmox VE indicators
            if "proxmox" not in resp_lower and "pve" not in resp_lower:
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None

            # Try to extract JSON body
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:].strip()
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        data_field = info.get("data", info)
                        if isinstance(data_field, dict):
                            version = data_field.get("version") or data_field.get("repoid")
                            if "release" in data_field:
                                metadata["release"] = data_field["release"]
                            if "repoid" in data_field:
                                metadata["repoid"] = data_field["repoid"]
                except (json.JSONDecodeError, ValueError):
                    pass

            # Also check Server header for version
            ver_match = re.search(
                r"[Pp]roxmox\s+VE[/ ]([\d.]+)", response
            )
            if ver_match and not version:
                version = ver_match.group(1)

            return ServiceIdentity(
                service="proxmox_ve",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
