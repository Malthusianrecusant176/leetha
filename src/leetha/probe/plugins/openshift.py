"""OpenShift probe plugin — HTTPS GET /version to detect OpenShift Kubernetes."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OpenShiftProbePlugin(ServiceProbe):
    name = "openshift"
    protocol = "tcp"
    default_ports = [6443, 8443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /version HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Must contain openshift indicator
            if "openshift" not in response.lower():
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None

            # Parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:].strip()
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        git_version = info.get("gitVersion", "")
                        if git_version:
                            version = git_version
                            metadata["git_version"] = git_version
                        if "goVersion" in info:
                            metadata["go_version"] = info["goVersion"]
                        if "platform" in info:
                            metadata["platform"] = info["platform"]
                        if "major" in info:
                            metadata["major"] = info["major"]
                        if "minor" in info:
                            metadata["minor"] = info["minor"]
                except (json.JSONDecodeError, ValueError):
                    pass

            return ServiceIdentity(
                service="openshift",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
