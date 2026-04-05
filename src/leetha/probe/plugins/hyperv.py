"""Hyper-V probe plugin — HTTP POST /wsman with SOAP Identify to detect Hyper-V."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HyperVProbePlugin(ServiceProbe):
    name = "hyperv"
    protocol = "tcp"
    default_ports = [5985, 5986]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            soap_body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
                ' xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">'
                "<s:Header/>"
                "<s:Body>"
                "<wsmid:Identify/>"
                "</s:Body>"
                "</s:Envelope>"
            )

            request = (
                f"POST /wsman HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
                f"Content-Length: {len(soap_body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{soap_body}"
            )

            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            # Must contain Hyper-V or Microsoft indicators with wsman
            has_hyperv = "hyper-v" in resp_lower
            has_microsoft = "microsoft" in resp_lower
            has_wsman = "wsman" in resp_lower or "ws-management" in resp_lower

            if not (has_hyperv or (has_microsoft and has_wsman)):
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None

            # Try to extract product version from SOAP response
            prod_match = re.search(
                r"<wsmid:ProductVersion>([^<]+)</wsmid:ProductVersion>",
                response,
            )
            if prod_match:
                version = prod_match.group(1)

            vendor_match = re.search(
                r"<wsmid:ProductVendor>([^<]+)</wsmid:ProductVendor>",
                response,
            )
            if vendor_match:
                metadata["vendor"] = vendor_match.group(1)

            if has_hyperv:
                metadata["hyperv_detected"] = True

            # Check Server header
            server_match = re.search(
                r"Server:\s*([^\r\n]+)", response, re.IGNORECASE
            )
            if server_match:
                metadata["server"] = server_match.group(1).strip()

            return ServiceIdentity(
                service="hyperv",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
