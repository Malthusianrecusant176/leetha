"""Weaviate probe plugin — HTTP GET /v1/meta."""
from __future__ import annotations
import json
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class WeaviateProbePlugin(ServiceProbe):
    name = "weaviate"
    protocol = "tcp"
    default_ports = [8080]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = f"GET /v1/meta HTTP/1.0\r\nHost: {conn.host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
            conn.write(request.encode())
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            body_start = response.find("\r\n\r\n")
            if body_start == -1:
                return None
            body = response[body_start + 4:].strip()
            if not body:
                return None

            try:
                obj = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(obj, dict):
                return None

            # Check for "hostname" and "version" fields
            if "hostname" not in obj and "version" not in obj:
                return None

            version = obj.get("version")
            metadata: dict = {}
            if "hostname" in obj:
                metadata["hostname"] = obj["hostname"]
            if "modules" in obj:
                metadata["modules"] = obj["modules"]

            return ServiceIdentity(
                service="weaviate",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
