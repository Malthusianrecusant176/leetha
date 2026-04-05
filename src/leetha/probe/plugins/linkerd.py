"""Linkerd probe plugin — HTTP GET /metrics for Linkerd service mesh detection."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class LinkerdProbePlugin(ServiceProbe):
    name = "linkerd"
    protocol = "tcp"
    default_ports = [4191]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /metrics HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for HTTP 200
            status_line = response.split("\r\n")[0]
            if "200" not in status_line:
                return None

            # Look for Linkerd-specific metrics
            has_linkerd = "linkerd" in response.lower()

            if not has_linkerd:
                return None

            metadata: dict = {}
            version = None

            # Try to extract version from metrics
            ver_match = re.search(r'linkerd_version="([^"]+)"', response)
            if ver_match:
                version = ver_match.group(1)
                metadata["version"] = version

            # Check for proxy-specific metrics
            if "process_cpu_seconds_total" in response:
                metadata["has_process_metrics"] = True
            if "request_total" in response:
                metadata["has_request_metrics"] = True

            return ServiceIdentity(
                service="linkerd",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
