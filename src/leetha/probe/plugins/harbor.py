"""Harbor probe plugin — HTTP GET /api/v2.0/systeminfo for Harbor registry detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HarborProbePlugin(ServiceProbe):
    name = "harbor"
    protocol = "tcp"
    default_ports = [80, 443]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/v2.0/systeminfo HTTP/1.0\r\n"
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

            # Check for Harbor-specific fields
            resp_lower = response.lower()
            has_harbor = "harbor" in resp_lower
            has_registry_url = "registry_url" in info
            has_harbor_version = "harbor_version" in info

            if not (has_harbor or has_registry_url or has_harbor_version):
                return None

            metadata: dict = {}
            version = None

            if has_harbor_version:
                version = info["harbor_version"]
                metadata["version"] = version
            if has_registry_url:
                metadata["registry_url"] = info["registry_url"]
            if "with_notary" in info:
                metadata["with_notary"] = info["with_notary"]
            if "auth_mode" in info:
                metadata["auth_mode"] = info["auth_mode"]
            if "project_creation_restriction" in info:
                metadata["project_creation_restriction"] = info["project_creation_restriction"]
            if "has_ca_root" in info:
                metadata["has_ca_root"] = info["has_ca_root"]

            return ServiceIdentity(
                service="harbor",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
