"""Nomad probe plugin — HTTP GET /v1/agent/self to detect HashiCorp Nomad."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NomadProbePlugin(ServiceProbe):
    name = "nomad"
    protocol = "tcp"
    default_ports = [4646]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v1/agent/self HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            # Must contain Nomad indicator
            if "nomad" not in resp_lower:
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:].strip()
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        # Nomad returns config with version info
                        config = info.get("config", {})
                        if isinstance(config, dict):
                            ver = config.get("Version", {})
                            if isinstance(ver, dict):
                                version = ver.get("Version")
                                if "Revision" in ver:
                                    metadata["revision"] = ver["Revision"]
                                if "Prerelease" in ver:
                                    metadata["prerelease"] = ver["Prerelease"]
                            if "Region" in config:
                                metadata["region"] = config["Region"]
                            if "Datacenter" in config:
                                metadata["datacenter"] = config["Datacenter"]
                        # Also check member info
                        member = info.get("member", {})
                        if isinstance(member, dict):
                            if "Name" in member:
                                metadata["member_name"] = member["Name"]
                except (json.JSONDecodeError, ValueError):
                    pass

            return ServiceIdentity(
                service="nomad",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
