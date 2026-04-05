"""MGCP probe plugin — AuditEndpoint command for media gateway detection."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MGCPProbePlugin(ServiceProbe):
    name = "mgcp"
    protocol = "udp"
    default_ports = [2427, 2727]

    _RESPONSE_RE = re.compile(r"^(\d{3})\s+(\d+)\s*(.*)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # AUEP (AuditEndpoint) command
            command = f"AUEP 1234 *@{conn.host} MGCP 1.0\r\n\r\n"
            conn.write(command.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            match = self._RESPONSE_RE.match(response)
            if not match:
                return None

            response_code = int(match.group(1))
            transaction_id = int(match.group(2))
            reason = match.group(3).strip() if match.group(3) else ""

            metadata: dict = {
                "response_code": response_code,
                "transaction_id": transaction_id,
            }
            if reason:
                metadata["reason"] = reason

            return ServiceIdentity(
                service="mgcp",
                certainty=80,
                metadata=metadata,
                banner=response[:256],
            )
        except (socket.timeout, OSError):
            return None
