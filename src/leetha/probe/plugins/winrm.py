"""WinRM probe plugin — HTTP POST to /wsman to detect WinRM/WS-Management."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class WinRMProbePlugin(ServiceProbe):
    name = "winrm"
    protocol = "tcp"
    default_ports = [5985, 5986]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Minimal SOAP envelope for WS-Management identify request
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
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for HTTP response
            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            headers = dict(self._HEADER_RE.findall(response))

            # WinRM responds with SOAP content-type even on errors
            content_type = headers.get("Content-Type", "") or headers.get(
                "content-type", ""
            )
            is_soap = "soap" in content_type.lower() or "xml" in content_type.lower()

            # Also check for WinRM-specific headers or known status codes
            server = headers.get("Server", "") or headers.get("server", "")
            is_winrm = (
                is_soap
                or "wsman" in response.lower()
                or "Microsoft-HTTPAPI" in server
                or status_code == 401  # Auth required is common for WinRM
            )

            if not is_winrm:
                return None

            metadata: dict = {
                "status_code": status_code,
            }
            if server:
                metadata["server"] = server
            if content_type:
                metadata["content_type"] = content_type

            # Try to extract product info from SOAP response
            version = None
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

            return ServiceIdentity(
                service="winrm",
                certainty=80,
                version=version,
                banner=response[:512],
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
