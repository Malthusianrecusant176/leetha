"""Graphite probe plugin — HTTP GET /version on the web interface."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GraphiteProbePlugin(ServiceProbe):
    name = "graphite"
    protocol = "tcp"
    default_ports = [8080, 2003]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /version HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            lower = response.lower()

            # Look for Graphite markers in the response
            if "graphite" not in lower and "carbon" not in lower:
                return None

            # Try to extract version from response body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    body = ""
                else:
                    body = response[body_start + 2:].strip()
            else:
                body = response[body_start + 4:].strip()

            metadata: dict = {}
            version = None

            if body:
                # Body may just be a version string like "1.1.10"
                clean = body.strip().strip('"').strip("'")
                # Check if it looks like a version
                parts = clean.split(".")
                if len(parts) >= 2 and all(p.isdigit() for p in parts[:2]):
                    version = clean
                    metadata["version"] = version

            if "carbon" in lower:
                metadata["component"] = "carbon"
            if "graphite-web" in lower or "graphite" in lower:
                metadata["component"] = metadata.get("component", "graphite-web")

            return ServiceIdentity(
                service="graphite",
                certainty=75,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
