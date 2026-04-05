"""Knative probe plugin — HTTP GET /healthz for Knative serving detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class KnativeProbePlugin(ServiceProbe):
    name = "knative"
    protocol = "tcp"
    default_ports = [8012]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /healthz HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for Knative markers
            resp_lower = response.lower()
            has_knative = "knative" in resp_lower

            if not has_knative:
                return None

            metadata: dict = {}
            version = None

            # Extract headers for version info
            headers_end = response.find("\r\n\r\n")
            if headers_end < 0:
                headers_end = response.find("\n\n")
            if headers_end > 0:
                header_section = response[:headers_end]
                for line in header_section.split("\r\n"):
                    lower_line = line.lower()
                    if "knative-version" in lower_line or "x-knative-version" in lower_line:
                        version = line.split(":", 1)[1].strip()
                        metadata["version"] = version
                    elif lower_line.startswith("server:"):
                        metadata["server"] = line.split(":", 1)[1].strip()

            # Check status code
            status_line = response.split("\r\n")[0]
            if "200" in status_line:
                metadata["healthy"] = True
            elif "503" in status_line:
                metadata["healthy"] = False

            # Check body for additional info
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:].strip()
                if body:
                    metadata["status_text"] = body[:200]

            return ServiceIdentity(
                service="knative",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
