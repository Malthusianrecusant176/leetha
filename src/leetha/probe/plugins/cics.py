"""CICS Transaction Server probe plugin — HTTP probe to /CICSSystemManagement."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CICSProbePlugin(ServiceProbe):
    name = "cics"
    protocol = "tcp"
    default_ports = [1435]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _CICS_HEADER_RE = re.compile(r"CICS", re.IGNORECASE)
    _VERSION_RE = re.compile(r"CICS\s+Transaction\s+Server[/ ]+(\S+)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /CICSSystemManagement HTTP/1.0\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())

            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            # Look for CICS indicators in headers or body
            if not self._CICS_HEADER_RE.search(response):
                return None

            metadata: dict = {}
            status_code = int(status_match.group(1))
            metadata["status_code"] = status_code

            # Extract version if present
            version = None
            ver_match = self._VERSION_RE.search(response)
            if ver_match:
                version = ver_match.group(1)

            # Check for specific CICS headers
            for line in response.split("\r\n"):
                lower = line.lower()
                if lower.startswith("server:") and "cics" in lower:
                    metadata["server"] = line.split(":", 1)[1].strip()

            return ServiceIdentity(
                service="cics",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
