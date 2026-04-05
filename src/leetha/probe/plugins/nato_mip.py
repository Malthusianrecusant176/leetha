"""NATO MIP (Multilateral Interoperability Programme) probe plugin — HTTP detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NATOMIPProbePlugin(ServiceProbe):
    name = "nato_mip"
    protocol = "tcp"
    default_ports = [8443]

    _MIP_RE = re.compile(r"(?:MIP|JC3IEDM|NFFI|Multilateral\s+Interoperability)", re.IGNORECASE)
    _VERSION_RE = re.compile(r"MIP\s+(?:Block|Version)\s+([0-9]+(?:\.[0-9]+)*)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /mip/service HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            if not self._MIP_RE.search(response):
                return None

            metadata: dict = {"protocol": "nato_mip"}
            version = None

            ver_match = self._VERSION_RE.search(response)
            if ver_match:
                version = ver_match.group(1)

            if "JC3IEDM" in response.upper():
                metadata["data_model"] = "JC3IEDM"
            if "NFFI" in response.upper():
                metadata["format"] = "NFFI"

            return ServiceIdentity(
                service="nato_mip",
                certainty=80,
                version=version,
                metadata=metadata,
                banner=response[:256],
            )
        except (socket.timeout, OSError):
            return None
