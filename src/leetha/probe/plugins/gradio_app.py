"""Gradio probe plugin — HTTP GET /config for Gradio app detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GradioProbePlugin(ServiceProbe):
    name = "gradio"
    protocol = "tcp"
    default_ports = [7860]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /config HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                return None
            body = response[body_start + 4:].strip()
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(info, dict):
                return None

            # Check for Gradio-specific keys
            if "mode" not in info and "components" not in info:
                return None

            return ServiceIdentity(
                service="gradio",
                certainty=85,
                metadata={
                    "ai_service": "Gradio",
                    "device_type": "ai_platform",
                },
            )
        except (socket.timeout, OSError):
            return None
