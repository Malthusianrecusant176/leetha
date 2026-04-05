"""HAProxy Stats probe plugin — HAProxy statistics/monitoring endpoint."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HAProxyStatsProbePlugin(ServiceProbe):
    name = "haproxy_stats"
    protocol = "tcp"
    default_ports = [9000, 1936]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /haproxy?stats HTTP/1.0\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

            conn.write(request)
            data = conn.read(8192)

            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Must be a valid HTTP response
            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            lower_resp = response.lower()

            # Check for HAProxy indicators in response
            is_haproxy = (
                "haproxy" in lower_resp
                or "# pxname,svname" in lower_resp  # CSV stats header
                or "statistics report" in lower_resp
            )

            if not is_haproxy:
                return None

            headers = dict(self._HEADER_RE.findall(response))
            metadata: dict = {"status_code": status_code}
            version = None

            server = headers.get("Server") or headers.get("server")
            if server:
                metadata["server"] = server
                version = server

            # Check for CSV stats format
            if "# pxname,svname" in lower_resp:
                metadata["csv_stats"] = True

            # Check if auth required
            if status_code == 401:
                metadata["auth_required"] = True

            return ServiceIdentity(
                service="haproxy_stats",
                certainty=80,
                version=version,
                banner=response[:512],
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
