"""Veeam probe plugin — HTTP GET /api/sessionMngr/latestSession for Veeam detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class VeeamProbePlugin(ServiceProbe):
    name = "veeam"
    protocol = "tcp"
    default_ports = [9392]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/sessionMngr/latestSession HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            lower = response.lower()

            # Look for Veeam markers in response
            if "veeam" not in lower:
                return None

            metadata: dict = {}
            version = None

            # Parse headers for Veeam-specific information
            for line in response.split("\r\n"):
                low = line.lower()
                if low.startswith("server:") and "veeam" in low:
                    val = line.split(":", 1)[1].strip()
                    metadata["server"] = val
                elif low.startswith("x-restsvctaskid:"):
                    metadata["rest_task_id"] = line.split(":", 1)[1].strip()

            # Try to parse JSON body for version info
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="veeam",
                        certainty=70,
                        metadata=metadata,
                    )
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            if body:
                # Look for version patterns in body
                import re
                ver_match = re.search(
                    r"[Vv]eeam[^\"]*?(\d+\.\d+(?:\.\d+)*)", body
                )
                if ver_match:
                    version = ver_match.group(1)
                    metadata["version"] = version

                # Check for XML or JSON product info
                if "ProductVersion" in body:
                    import json
                    try:
                        info = json.loads(body)
                        if isinstance(info, dict):
                            if "ProductVersion" in info:
                                version = info["ProductVersion"]
                                metadata["version"] = version
                    except (json.JSONDecodeError, ValueError):
                        pass

            return ServiceIdentity(
                service="veeam",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
