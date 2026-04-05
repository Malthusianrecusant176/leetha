"""Docker Registry probe plugin — HTTP GET /v2/ to detect Docker Distribution registry."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DockerRegistryProbePlugin(ServiceProbe):
    name = "docker_registry"
    protocol = "tcp"
    default_ports = [5000]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /v2/ HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            headers: dict[str, str] = {}
            for key, val in self._HEADER_RE.findall(response):
                headers[key.lower()] = val

            # Docker Distribution API Version header is the definitive marker
            api_version = headers.get("docker-distribution-api-version", "")

            if not api_version and "registry" not in response.lower():
                return None

            metadata: dict = {
                "status_code": status_code,
            }

            version = None
            if api_version:
                metadata["api_version"] = api_version
                version = api_version

            # Check for Docker-Content-Digest header (another registry marker)
            digest = headers.get("docker-content-digest")
            if digest:
                metadata["content_digest"] = digest

            # Check Www-Authenticate for auth info
            www_auth = headers.get("www-authenticate")
            if www_auth:
                metadata["auth_scheme"] = www_auth

            return ServiceIdentity(
                service="docker_registry",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
