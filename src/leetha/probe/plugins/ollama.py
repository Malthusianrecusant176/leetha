"""Ollama probe plugin — HTTP GET / for Ollama inference server detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OllamaProbePlugin(ServiceProbe):
    name = "ollama"
    protocol = "tcp"
    default_ports = [11434]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET / HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            if "Ollama is running" not in response:
                return None

            # Extract version from X-Ollama-Version header
            version = None
            for line in response.split("\r\n"):
                if line.lower().startswith("x-ollama-version:"):
                    version = line.split(":", 1)[1].strip()
                    break

            return ServiceIdentity(
                service="ollama",
                certainty=95,
                version=version,
                metadata={
                    "ai_service": "Ollama",
                    "device_type": "ai_inference",
                    "manufacturer": "Ollama",
                },
            )
        except (socket.timeout, OSError):
            return None
