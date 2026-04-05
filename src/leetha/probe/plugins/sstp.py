"""SSTP probe plugin — sends SSTP Call Connect Request over HTTP."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SSTPProbePlugin(ServiceProbe):
    name = "sstp"
    protocol = "tcp"
    default_ports = [443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # SSTP uses HTTP DUPLEX POST to a specific URI
            sstp_uri = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
            request = (
                f"SSTP_DUPLEX_POST {sstp_uri} HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Content-Length: 18446744073709551615\r\n"
                f"SSTPCORRELATIONID: {{leetha0000-0000-0000-0000-000000000000}}\r\n"
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

            status_code = int(status_match.group(1))
            metadata: dict = {"status_code": status_code}

            # SSTP server responds with HTTP 200 OK
            if status_code == 200:
                # Check for SSTP-specific indicators
                resp_lower = response.lower()
                if "content-length" in resp_lower or "sstp" in resp_lower:
                    metadata["sstp_confirmed"] = True

                return ServiceIdentity(
                    service="sstp",
                    certainty=75,
                    metadata=metadata,
                )

            # Some SSTP servers may respond with other codes but still indicate SSTP
            if "sstp" in response.lower() or "sra_" in response.lower():
                metadata["sstp_hint"] = True
                return ServiceIdentity(
                    service="sstp",
                    certainty=60,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError):
            return None
