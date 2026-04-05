"""Kong probe plugin — HTTP GET / for Kong API Gateway detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class KongProbePlugin(ServiceProbe):
    name = "kong"
    protocol = "tcp"
    default_ports = [8001]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET / HTTP/1.0\r\n"
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

            # Check for Kong-specific fields
            has_tagline = "tagline" in info
            has_version = "version" in info

            if not (has_tagline or has_version):
                # Fallback: check for Kong in response
                if "kong" not in response.lower():
                    return None

            # Verify it looks like Kong — require "kong" somewhere
            tagline = info.get("tagline", "")
            if has_tagline and "kong" in tagline.lower():
                pass  # confirmed via tagline
            elif "kong" in response.lower():
                pass  # confirmed via headers/body
            else:
                return None

            metadata: dict = {}
            version = None

            if has_version:
                version = info["version"]
                metadata["version"] = version
            if has_tagline:
                metadata["tagline"] = tagline
            if "hostname" in info:
                metadata["hostname"] = info["hostname"]
            if "node_id" in info:
                metadata["node_id"] = info["node_id"]
            if "lua_version" in info:
                metadata["lua_version"] = info["lua_version"]

            return ServiceIdentity(
                service="kong",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
