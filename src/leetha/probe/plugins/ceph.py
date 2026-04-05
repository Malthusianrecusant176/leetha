"""Ceph RADOS Gateway probe plugin — HTTP GET / to detect Ceph RGW."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CephProbePlugin(ServiceProbe):
    name = "ceph"
    protocol = "tcp"
    default_ports = [7480, 8003]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _HEADER_RE = re.compile(r"^([\w-]+):\s*(.+)$", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET / HTTP/1.0\r\n"
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

            # Parse headers
            headers: dict[str, str] = {}
            for match in self._HEADER_RE.finditer(response):
                headers[match.group(1).lower()] = match.group(2).strip()

            metadata: dict = {}
            is_ceph = False

            # Check for Ceph RGW specific header
            if "x-rgw-request-id" in headers:
                is_ceph = True
                metadata["rgw_request_id"] = headers["x-rgw-request-id"]

            # Check for ceph in response body or headers
            if "ceph" in resp_lower:
                is_ceph = True

            # Check Server header
            server = headers.get("server", "")
            if "ceph" in server.lower() or "rgw" in server.lower():
                is_ceph = True
                metadata["server"] = server

            if not is_ceph:
                return None

            status_match = self._STATUS_RE.match(response)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            # Try to extract version
            version = None
            ver_match = re.search(r"ceph[/ ]([\d.]+)", response, re.IGNORECASE)
            if ver_match:
                version = ver_match.group(1)
                metadata["ceph_version"] = version

            return ServiceIdentity(
                service="ceph",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
