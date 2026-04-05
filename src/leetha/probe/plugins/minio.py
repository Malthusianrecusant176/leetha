"""MinIO probe plugin — HTTP GET /minio/health/live to detect MinIO."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MinIOProbePlugin(ServiceProbe):
    name = "minio"
    protocol = "tcp"
    default_ports = [9000]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /minio/health/live HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            if not response.startswith("HTTP/"):
                return None

            headers = dict(self._HEADER_RE.findall(response))
            server = headers.get("Server", "")

            # MinIO identifies via Server header containing "MinIO"
            is_minio = "MinIO" in server

            # Check for 200 OK response on health endpoint
            has_200 = " 200 " in response.split("\r\n", 1)[0]

            if not is_minio and not has_200:
                return None

            if not is_minio:
                return None

            metadata: dict = {"server": server}
            version = None

            # Extract version from Server header (e.g., "MinIO/RELEASE.2023-10-07")
            if "/" in server:
                version = server.split("/", 1)[1].strip()
                metadata["version"] = version

            return ServiceIdentity(
                service="minio",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
