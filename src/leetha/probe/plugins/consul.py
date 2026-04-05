"""Consul probe plugin — HTTP GET /v1/agent/self for HashiCorp Consul detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ConsulProbePlugin(ServiceProbe):
    name = "consul"
    protocol = "tcp"
    default_ports = [8500, 8501]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v1/agent/self HTTP/1.0\r\n"
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

            # Check for Consul-specific fields
            has_config = "Config" in info
            has_member = "Member" in info

            if not (has_config or has_member):
                return None

            metadata: dict = {}
            version = None

            if has_config and isinstance(info["Config"], dict):
                config = info["Config"]
                if "Datacenter" in config:
                    metadata["datacenter"] = config["Datacenter"]
                if "NodeName" in config:
                    metadata["node_name"] = config["NodeName"]
                if "Version" in config:
                    version = config["Version"]
                    metadata["version"] = version

            if has_member and isinstance(info["Member"], dict):
                member = info["Member"]
                if "Name" in member:
                    metadata["member_name"] = member["Name"]
                if "Addr" in member:
                    metadata["member_addr"] = member["Addr"]

            return ServiceIdentity(
                service="consul",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
