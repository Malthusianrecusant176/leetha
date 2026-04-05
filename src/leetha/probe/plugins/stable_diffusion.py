"""Stable Diffusion WebUI probe plugin — HTTP GET /sdapi/v1/options."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class StableDiffusionProbePlugin(ServiceProbe):
    name = "stable_diffusion"
    protocol = "tcp"
    default_ports = [7860]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /sdapi/v1/options HTTP/1.0\r\n"
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

            if "sd_model_checkpoint" not in info:
                return None

            metadata: dict = {
                "ai_service": "Stable Diffusion WebUI",
                "device_type": "ai_inference",
                "ai_category": "image_gen",
            }
            if info.get("sd_model_checkpoint"):
                metadata["sd_model"] = info["sd_model_checkpoint"]

            return ServiceIdentity(
                service="stable_diffusion",
                certainty=90,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
