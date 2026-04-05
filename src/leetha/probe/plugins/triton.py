"""NVIDIA Triton Inference Server probe plugin — HTTP GET /v2."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TritonProbePlugin(ServiceProbe):
    name = "triton"
    protocol = "tcp"
    default_ports = [8000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v2 HTTP/1.0\r\n"
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

            # Check for Triton-specific markers
            if "extensions" not in info:
                return None
            if "triton" not in response.lower():
                return None

            version = info.get("version")

            return ServiceIdentity(
                service="triton",
                certainty=90,
                version=version,
                metadata={
                    "ai_service": "NVIDIA Triton",
                    "device_type": "ai_inference",
                    "manufacturer": "NVIDIA",
                },
            )
        except (socket.timeout, OSError):
            return None
