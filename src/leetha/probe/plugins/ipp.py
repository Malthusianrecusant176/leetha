"""IPP probe plugin — Internet Printing Protocol / CUPS detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IPPProbePlugin(ServiceProbe):
    name = "ipp"
    protocol = "tcp"
    default_ports = [631]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build IPP Get-Printer-Attributes request
            # IPP version 1.1, operation Get-Printer-Attributes (0x000B)
            ipp_body = struct.pack(">BBH", 1, 1, 0x000B)  # version-major, minor, op
            ipp_body += struct.pack(">I", 1)  # request-id

            # Operation attributes
            ipp_body += b"\x01"  # operation-attributes-tag

            # charset: utf-8
            ipp_body += b"\x47"  # charset type
            ipp_body += struct.pack(">H", 18)  # name-length
            ipp_body += b"attributes-charset"
            ipp_body += struct.pack(">H", 5)  # value-length
            ipp_body += b"utf-8"

            # natural-language: en
            ipp_body += b"\x48"  # naturalLanguage type
            ipp_body += struct.pack(">H", 27)  # name-length
            ipp_body += b"attributes-natural-language"
            ipp_body += struct.pack(">H", 2)  # value-length
            ipp_body += b"en"

            # printer-uri
            printer_uri = f"ipp://{conn.host}:{631}/".encode()
            ipp_body += b"\x45"  # uri type
            ipp_body += struct.pack(">H", 11)  # name-length
            ipp_body += b"printer-uri"
            ipp_body += struct.pack(">H", len(printer_uri))  # value-length
            ipp_body += printer_uri

            # End of attributes
            ipp_body += b"\x03"  # end-of-attributes-tag

            # Wrap in HTTP POST
            http_request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {conn.host}:{631}\r\n"
                f"Content-Type: application/ipp\r\n"
                f"Content-Length: {len(ipp_body)}\r\n"
                f"\r\n"
            ).encode() + ipp_body

            conn.write(http_request)
            data = conn.read(4096)

            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            metadata: dict = {}
            version = None

            # Check for HTTP response
            if not response.startswith("HTTP/"):
                return None

            # Check for IPP content in response
            # Look for application/ipp content-type or IPP-specific content
            lower_resp = response.lower()
            is_ipp = (
                "application/ipp" in lower_resp
                or "ipp/" in lower_resp
                or "cups" in lower_resp
                or "printer" in lower_resp
            )

            if not is_ipp:
                return None

            # Try to extract server info
            for line in response.split("\r\n"):
                lower_line = line.lower()
                if lower_line.startswith("server:"):
                    server_val = line.split(":", 1)[1].strip()
                    metadata["server"] = server_val
                    version = server_val

            # Try to find IPP status in raw bytes
            # Look for IPP response bytes after HTTP headers
            header_end = data.find(b"\r\n\r\n")
            if header_end != -1 and header_end + 8 <= len(data):
                ipp_data = data[header_end + 4:]
                if len(ipp_data) >= 4:
                    ipp_major = ipp_data[0]
                    ipp_minor = ipp_data[1]
                    ipp_status = struct.unpack(">H", ipp_data[2:4])[0]
                    metadata["ipp_version"] = f"{ipp_major}.{ipp_minor}"
                    metadata["ipp_status"] = ipp_status

            return ServiceIdentity(
                service="ipp",
                certainty=85,
                version=version,
                banner=response[:512],
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
