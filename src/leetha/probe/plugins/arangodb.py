"""ArangoDB probe plugin — HTTP GET /_api/version."""
from __future__ import annotations
import json
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ArangoDBProbePlugin(ServiceProbe):
    name = "arangodb"
    protocol = "tcp"
    default_ports = [8529]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = f"GET /_api/version HTTP/1.0\r\nHost: {conn.host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
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

            # Check for "server" field containing "arango"
            server = obj.get("server", "")
            if "arango" not in server.lower():
                return None

            version = obj.get("version")
            metadata: dict = {"server": server}
            if "license" in obj:
                metadata["license"] = obj["license"]

            return ServiceIdentity(
                service="arangodb",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
