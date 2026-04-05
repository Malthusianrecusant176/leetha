"""LiteLLM probe plugin — HTTP GET /health for LiteLLM gateway detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class LiteLLMProbePlugin(ServiceProbe):
    name = "litellm"
    protocol = "tcp"
    default_ports = [4000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /health HTTP/1.0\r\n"
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

            # Check for LiteLLM-specific keys
            has_healthy = "healthy_endpoints" in info
            has_metadata = "litellm_metadata" in info
            has_version = "litellm_version" in info

            if not (has_healthy or has_metadata or has_version):
                return None

            metadata: dict = {
                "ai_service": "LiteLLM",
                "device_type": "ai_gateway",
                "manufacturer": "BerriAI",
            }
            if has_version:
                metadata["litellm_version"] = info["litellm_version"]

            return ServiceIdentity(
                service="litellm",
                certainty=90,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
