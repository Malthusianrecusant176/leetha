"""Envoy Admin probe plugin — HTTP GET /server_info for Envoy proxy detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class EnvoyAdminProbePlugin(ServiceProbe):
    name = "envoy_admin"
    protocol = "tcp"
    default_ports = [9901]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /server_info HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for HTTP 200
            status_line = response.split("\r\n")[0]
            if "200" not in status_line:
                return None

            # Find JSON body after HTTP headers
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
                # Fallback: check raw response for Envoy markers
                if "envoy" not in response.lower():
                    return None
                return ServiceIdentity(
                    service="envoy_admin",
                    certainty=60,
                )

            if not isinstance(info, dict):
                return None

            # Check for Envoy-specific fields
            has_version = "version" in info
            has_hot_restart = "hot_restart_version" in info
            has_state = "state" in info

            if not any(k in response.lower() for k in ("envoy", "hot_restart", "concurrency")):
                return None

            metadata: dict = {}
            version = None

            if has_version:
                version = info["version"]
                metadata["version"] = version
            if has_hot_restart:
                metadata["hot_restart_version"] = info["hot_restart_version"]
            if has_state:
                metadata["state"] = info["state"]
            if "concurrency" in info:
                metadata["concurrency"] = info["concurrency"]

            return ServiceIdentity(
                service="envoy_admin",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
