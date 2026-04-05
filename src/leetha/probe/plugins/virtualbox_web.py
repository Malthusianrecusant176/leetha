"""VirtualBox Web Service probe plugin — SOAP GetVersion request to detect VirtualBox."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class VirtualBoxWebProbePlugin(ServiceProbe):
    name = "virtualbox_web"
    protocol = "tcp"
    default_ports = [18083]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            soap_body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
                ' xmlns:vbox="http://www.virtualbox.org/">'
                "<soap:Body>"
                "<vbox:IVirtualBox_getVersion>"
                "<_this>managed-object-ref</_this>"
                "</vbox:IVirtualBox_getVersion>"
                "</soap:Body>"
                "</soap:Envelope>"
            )

            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Content-Type: text/xml;charset=UTF-8\r\n"
                f"SOAPAction: \"\"\r\n"
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

            # Must contain VirtualBox indicators
            if "virtualbox" not in resp_lower and "vbox" not in resp_lower:
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None

            # Try to extract version from SOAP response
            ver_match = re.search(
                r"<returnval>([^<]+)</returnval>", response
            )
            if ver_match:
                version = ver_match.group(1)

            # Check for SOAP fault (still indicates VirtualBox)
            fault_match = re.search(
                r"<faultstring>([^<]+)</faultstring>", response
            )
            if fault_match:
                metadata["fault"] = fault_match.group(1)

            return ServiceIdentity(
                service="virtualbox_web",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
