"""OpenAI-compatible API probe plugin — HTTP GET /v1/models for generic detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OpenAICompatProbePlugin(ServiceProbe):
    name = "openai_compat"
    protocol = "tcp"
    default_ports = [8000, 8080, 3000, 5000, 5001, 1234]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v1/models HTTP/1.0\r\n"
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
            if "data" not in info or "object" not in info:
                return None

            # Extract model list
            models = []
            for item in info.get("data", []):
                if isinstance(item, dict) and "id" in item:
                    models.append(item["id"])

            metadata: dict = {
                "ai_service": "OpenAI-compatible",
                "device_type": "ai_inference",
            }
            if models:
                metadata["ai_models"] = models

            return ServiceIdentity(
                service="openai_compat",
                certainty=75,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
