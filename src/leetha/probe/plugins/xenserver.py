"""XenServer probe plugin — HTTP GET / to detect XenServer/XCP-ng."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class XenServerProbePlugin(ServiceProbe):
    name = "xenserver"
    protocol = "tcp"
    default_ports = [80, 443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET / HTTP/1.1\r\n"
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

            # Must contain XenServer or XCP-ng indicators
            if (
                "xenserver" not in resp_lower
                and "xcp-ng" not in resp_lower
                and "xen " not in resp_lower
                and "citrix hypervisor" not in resp_lower
            ):
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None
            # Detect product variant
            if "xcp-ng" in resp_lower:
                metadata["product"] = "XCP-ng"
            elif "xenserver" in resp_lower:
                metadata["product"] = "XenServer"
            elif "citrix hypervisor" in resp_lower:
                metadata["product"] = "Citrix Hypervisor"

            # Try to extract version
            ver_match = re.search(
                r"(?:XenServer|XCP-ng|Citrix Hypervisor)[/ ]([\d.]+)",
                response,
                re.IGNORECASE,
            )
            if ver_match:
                version = ver_match.group(1)

            return ServiceIdentity(
                service="xenserver",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
