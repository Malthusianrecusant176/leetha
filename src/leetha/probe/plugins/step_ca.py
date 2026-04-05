"""step-ca (Smallstep CA) probe plugin — HTTP GET /health for step-ca detection."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class StepCAProbePlugin(ServiceProbe):
    name = "step_ca"
    protocol = "tcp"
    default_ports = [9000, 443]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /health HTTP/1.0\r\n"
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
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(info, dict):
                return None

            # step-ca health response must contain "status": "ok"
            status = info.get("status")
            if status != "ok":
                return None

            metadata: dict = {"protocol": "step_ca"}
            version = None

            if "version" in info:
                version = info["version"]
                metadata["version"] = version

            return ServiceIdentity(
                service="step_ca",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
