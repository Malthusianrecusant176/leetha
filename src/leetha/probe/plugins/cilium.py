"""Cilium probe plugin — HTTP GET /healthz for Cilium CNI detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CiliumProbePlugin(ServiceProbe):
    name = "cilium"
    protocol = "tcp"
    default_ports = [4244]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /healthz HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for Cilium markers in response
            resp_lower = response.lower()
            has_cilium = "cilium" in resp_lower

            if not has_cilium:
                return None

            metadata: dict = {}
            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="cilium",
                        certainty=65,
                        metadata=metadata,
                    )
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            if body:
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        if "cilium" in info:
                            cilium_info = info["cilium"]
                            if isinstance(cilium_info, dict) and "state" in cilium_info:
                                metadata["state"] = cilium_info["state"]
                        if "cluster" in info:
                            metadata["cluster"] = info["cluster"]
                except (json.JSONDecodeError, ValueError):
                    pass

            # Extract version from headers if present
            for line in response.split("\r\n"):
                if line.lower().startswith("x-cilium-version:"):
                    version = line.split(":", 1)[1].strip()
                    metadata["version"] = version

            return ServiceIdentity(
                service="cilium",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
