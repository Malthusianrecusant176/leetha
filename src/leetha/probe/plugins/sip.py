"""SIP probe plugin — SIP OPTIONS request for VoIP service detection."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SIPProbePlugin(ServiceProbe):
    name = "sip"
    protocol = "udp"
    default_ports = [5060, 5061]

    _STATUS_RE = re.compile(r"^SIP/2\.0\s+(\d+)\s+(.+)")
    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"OPTIONS sip:test@{conn.host} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {conn.host}:{conn.port};branch=z9hG4bK-leetha\r\n"
                f"From: <sip:leetha@localhost>;tag=leetha\r\n"
                f"To: <sip:test@{conn.host}>\r\n"
                f"Call-ID: leetha@localhost\r\n"
                f"CSeq: 1 OPTIONS\r\n"
                f"Max-Forwards: 0\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            if "SIP/2.0" not in response:
                return None

            metadata: dict = {}
            version = None

            status_match = self._STATUS_RE.match(response)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))
                metadata["status_text"] = status_match.group(2).strip()

            headers = dict(self._HEADER_RE.findall(response))

            server = headers.get("Server") or headers.get("server")
            if server:
                metadata["server"] = server
                version = server

            allow = headers.get("Allow") or headers.get("allow")
            if allow:
                metadata["allow"] = allow

            return ServiceIdentity(
                service="sip",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
