"""TrueNAS probe plugin — HTTP GET /api/v2.0/system/info to detect TrueNAS."""
from __future__ import annotations
import json
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TrueNASProbePlugin(ServiceProbe):
    name = "truenas"
    protocol = "tcp"
    default_ports = [80, 443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/v2.0/system/info HTTP/1.0\r\n"
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

            # Primary check: look for TrueNAS in response
            if "truenas" not in resp_lower and "freenas" not in resp_lower:
                return None

            metadata: dict = {}

            status_match = self._STATUS_RE.match(response)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            # Try to parse JSON body
            version = None
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:].strip()
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        if "version" in info:
                            version = info["version"]
                            metadata["truenas_version"] = version
                        if "hostname" in info:
                            metadata["hostname"] = info["hostname"]
                        if "system_product" in info:
                            metadata["product"] = info["system_product"]
                except (json.JSONDecodeError, ValueError):
                    pass

            # Fallback version extraction from headers/body
            if version is None:
                ver_match = re.search(
                    r"TrueNAS[- ]([\w.]+)", response, re.IGNORECASE
                )
                if ver_match:
                    version = ver_match.group(1)

            return ServiceIdentity(
                service="truenas",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
