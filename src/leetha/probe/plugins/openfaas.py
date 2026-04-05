"""OpenFaaS probe plugin — HTTP GET /system/info for OpenFaaS gateway detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OpenFaaSProbePlugin(ServiceProbe):
    name = "openfaas"
    protocol = "tcp"
    default_ports = [8080]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /system/info HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for OpenFaaS markers
            resp_lower = response.lower()
            has_openfaas = "openfaas" in resp_lower or "faas" in resp_lower

            if not has_openfaas:
                return None

            metadata: dict = {}
            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="openfaas",
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
                        if "version" in info:
                            ver = info["version"]
                            if isinstance(ver, dict):
                                if "release" in ver:
                                    version = ver["release"]
                                    metadata["release"] = version
                                if "sha" in ver:
                                    metadata["sha"] = ver["sha"]
                            else:
                                version = str(ver)
                                metadata["version"] = version
                        if "provider" in info:
                            provider = info["provider"]
                            if isinstance(provider, dict):
                                if "name" in provider:
                                    metadata["provider"] = provider["name"]
                                if "version" in provider:
                                    metadata["provider_version"] = provider["version"]
                            else:
                                metadata["provider"] = str(provider)
                        if "arch" in info:
                            metadata["arch"] = info["arch"]
                except (json.JSONDecodeError, ValueError):
                    pass

            return ServiceIdentity(
                service="openfaas",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
