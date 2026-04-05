"""Puppet probe plugin — HTTP GET /puppet/v3/status for Puppet Server detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PuppetProbePlugin(ServiceProbe):
    name = "puppet"
    protocol = "tcp"
    default_ports = [8140]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /puppet/v3/status/whatever HTTP/1.0\r\n"
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

            # Look for Puppet markers
            if "puppet" not in lower and "is_alive" not in lower:
                return None

            metadata: dict = {}
            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    # Puppet marker found in headers but no body
                    return ServiceIdentity(
                        service="puppet",
                        certainty=60,
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
                        if "is_alive" in info:
                            metadata["is_alive"] = info["is_alive"]
                        if "version" in info:
                            version = info["version"]
                            metadata["version"] = version
                except (json.JSONDecodeError, ValueError):
                    pass

            # Check headers for Puppet server info
            for line in response.split("\r\n"):
                low = line.lower()
                if low.startswith("x-puppet-version:"):
                    val = line.split(":", 1)[1].strip()
                    version = version or val
                    metadata["puppet_version"] = val
                elif low.startswith("server:") and "puppet" in low:
                    metadata["server"] = line.split(":", 1)[1].strip()

            return ServiceIdentity(
                service="puppet",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
