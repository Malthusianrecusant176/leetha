"""Mattermost probe plugin — system ping endpoint detection."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MattermostProbePlugin(ServiceProbe):
    name = "mattermost"
    protocol = "tcp"
    default_ports = [8065, 443]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send HTTP GET to Mattermost system ping endpoint
            request = (
                f"GET /api/v4/system/ping HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            # Must be an HTTP response
            if not text.startswith("HTTP/"):
                return None

            metadata = {}
            version = None
            is_mattermost = False

            # Check headers for Mattermost indicators
            header_end = text.find("\r\n\r\n")
            if header_end < 0:
                return None

            headers = text[:header_end].lower()
            body = text[header_end + 4:]

            # Check for Mattermost-specific headers
            if "x-version-id" in headers:
                is_mattermost = True
                for line in text[:header_end].split("\r\n"):
                    if line.lower().startswith("x-version-id:"):
                        version = line.split(":", 1)[1].strip()
                        metadata["version_id"] = version

            # Parse JSON body
            try:
                info = json.loads(body)
                if isinstance(info, dict):
                    status = info.get("status")
                    if status:
                        metadata["status"] = status
                        if status == "OK":
                            is_mattermost = True
                    # ActiveMQ won't have these Mattermost-specific keys
                    for key in ("AndroidLatestVersion", "IosLatestVersion",
                                "DatabaseStatus"):
                        if key in info:
                            is_mattermost = True
                            metadata[key] = info[key]
            except (json.JSONDecodeError, ValueError):
                pass

            if not is_mattermost:
                return None

            return ServiceIdentity(
                service="mattermost",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
