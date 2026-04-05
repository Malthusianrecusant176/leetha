"""HuggingFace Text Generation Inference probe plugin — HTTP GET /info."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HuggingFaceTGIProbePlugin(ServiceProbe):
    name = "huggingface_tgi"
    protocol = "tcp"
    default_ports = [3000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /info HTTP/1.0\r\n"
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

            if "model_id" not in info:
                return None

            metadata: dict = {
                "ai_service": "HuggingFace TGI",
                "device_type": "ai_inference",
            }
            model_id = info.get("model_id")
            if model_id:
                metadata["model_id"] = model_id

            return ServiceIdentity(
                service="huggingface_tgi",
                certainty=85,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
