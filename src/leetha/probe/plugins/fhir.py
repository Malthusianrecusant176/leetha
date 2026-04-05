"""FHIR probe plugin — Fast Healthcare Interoperability Resources."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FHIRProbePlugin(ServiceProbe):
    name = "fhir"
    protocol = "tcp"
    default_ports = [443, 8080]

    _CAP_RE = re.compile(r'"resourceType"\s*:\s*"CapabilityStatement"')
    _VER_RE = re.compile(r'"fhirVersion"\s*:\s*"([^"]+)"')
    _SW_RE = re.compile(r'"software"\s*:\s*\{[^}]*"name"\s*:\s*"([^"]+)"')

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /metadata HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Accept: application/fhir+json\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            if not self._CAP_RE.search(text):
                return None

            metadata: dict = {}
            version = None

            m = self._VER_RE.search(text)
            if m:
                version = m.group(1)
                metadata["fhir_version"] = version

            m = self._SW_RE.search(text)
            if m:
                metadata["software"] = m.group(1)

            return ServiceIdentity(
                service="fhir",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=text[:512],
            )

        except (socket.timeout, OSError):
            return None
