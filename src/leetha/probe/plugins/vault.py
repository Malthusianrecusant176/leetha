"""HashiCorp Vault probe plugin — HTTP GET /v1/sys/health for Vault detection."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class VaultProbePlugin(ServiceProbe):
    name = "vault"
    protocol = "tcp"
    default_ports = [8200]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v1/sys/health HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return None
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(info, dict):
                return None

            # Vault health endpoint must contain "initialized" and "sealed"
            has_initialized = "initialized" in info
            has_sealed = "sealed" in info

            if not (has_initialized and has_sealed):
                return None

            metadata: dict = {
                "initialized": info["initialized"],
                "sealed": info["sealed"],
            }
            version = None

            if "version" in info:
                version = info["version"]
                metadata["version"] = version
            if "cluster_name" in info:
                metadata["cluster_name"] = info["cluster_name"]
            if "standby" in info:
                metadata["standby"] = info["standby"]

            return ServiceIdentity(
                service="vault",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
