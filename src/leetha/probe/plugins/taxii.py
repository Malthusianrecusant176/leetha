"""TAXII probe plugin — HTTP GET /taxii2/ for TAXII 2.x server detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TAXIIProbePlugin(ServiceProbe):
    name = "taxii"
    protocol = "tcp"
    default_ports = [443, 9000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /taxii2/ HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Accept: application/taxii+json;version=2.1\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            lower = response.lower()

            # Look for TAXII markers
            if "taxii" not in lower:
                return None

            metadata: dict = {}
            version = None

            # Check Content-Type for TAXII
            for line in response.split("\r\n"):
                low = line.lower()
                if low.startswith("content-type:") and "taxii" in low:
                    metadata["content_type"] = line.split(":", 1)[1].strip()

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="taxii",
                        certainty=65,
                        metadata=metadata,
                    )
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            if body:
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        if "title" in info:
                            metadata["title"] = info["title"]
                        if "description" in info:
                            metadata["description"] = info["description"]
                        if "api_roots" in info:
                            metadata["api_roots"] = info["api_roots"]
                        if "default" in info:
                            metadata["default_api_root"] = info["default"]
                except (json.JSONDecodeError, ValueError):
                    pass

            # Extract version from Content-Type header (version=2.1)
            ct = metadata.get("content_type", "")
            if "version=" in ct:
                for part in ct.split(";"):
                    part = part.strip()
                    if part.startswith("version="):
                        version = part.split("=", 1)[1].strip()
                        metadata["taxii_version"] = version

            return ServiceIdentity(
                service="taxii",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
