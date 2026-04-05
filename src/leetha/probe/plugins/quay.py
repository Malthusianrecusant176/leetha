"""Quay probe plugin — HTTP GET /api/v1/discovery for Quay registry detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class QuayProbePlugin(ServiceProbe):
    name = "quay"
    protocol = "tcp"
    default_ports = [443]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/v1/discovery HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

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
                return None

            if not isinstance(info, dict):
                return None

            # Check for Quay-specific fields
            resp_lower = response.lower()
            has_quay = "quay" in resp_lower
            has_apis = "apis" in info
            has_name = "name" in info

            if not (has_quay or (has_apis and has_name)):
                return None

            metadata: dict = {}
            version = None

            if has_name:
                metadata["name"] = info["name"]
            if "version" in info:
                version = info["version"]
                metadata["version"] = version
            if has_apis and isinstance(info["apis"], dict):
                metadata["api_count"] = len(info["apis"])
            if "basePath" in info:
                metadata["base_path"] = info["basePath"]

            return ServiceIdentity(
                service="quay",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
