"""Apache HBase Master probe plugin — HTTP GET /status/cluster, detects HBase status."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HBaseProbePlugin(ServiceProbe):
    name = "hbase"
    protocol = "tcp"
    default_ports = [16010]

    _VERSION_RE = re.compile(r"HBase[- /]*([\d.]+)", re.IGNORECASE)
    _REGION_RE = re.compile(r"(\d+)\s+region\s*server", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /status/cluster HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            if "hbase" not in resp_lower:
                return None

            metadata: dict = {}
            version = None

            m = self._VERSION_RE.search(response)
            if m:
                version = m.group(1)

            rm = self._REGION_RE.search(response)
            if rm:
                metadata["region_servers"] = int(rm.group(1))

            if "master" in resp_lower:
                metadata["master_detected"] = True

            return ServiceIdentity(
                service="hbase",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
