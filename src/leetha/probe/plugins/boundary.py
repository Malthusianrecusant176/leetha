"""HashiCorp Boundary probe plugin — HTTP GET /v1/scopes for Boundary detection."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class BoundaryProbePlugin(ServiceProbe):
    name = "boundary"
    protocol = "tcp"
    default_ports = [9200, 9201]

    _BOUNDARY_RE = re.compile(r"boundary", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v1/scopes HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return None
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            headers_text = response[:body_start] if body_start > 0 else response
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                # Fall back to header check
                if self._BOUNDARY_RE.search(headers_text):
                    return ServiceIdentity(
                        service="boundary",
                        certainty=60,
                        metadata={"detected_via": "headers"},
                    )
                return None

            if not isinstance(info, dict):
                return None

            # Boundary scopes response has "items" or "kind" fields
            has_items = "items" in info
            has_kind = "kind" in info
            has_status = "status_code" in info or "status" in info

            if not (has_items or has_kind or has_status):
                # Check if it looks like a Boundary error response
                if not self._BOUNDARY_RE.search(response):
                    return None

            metadata: dict = {"protocol": "boundary"}
            version = None

            if has_kind:
                metadata["kind"] = info["kind"]
            if has_items and isinstance(info["items"], list):
                metadata["scope_count"] = len(info["items"])

            return ServiceIdentity(
                service="boundary",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
