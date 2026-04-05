"""ONVIF probe plugin — SOAP GetDeviceInformation."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ONVIFProbePlugin(ServiceProbe):
    name = "onvif"
    protocol = "tcp"
    default_ports = [80, 8080]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    _SOAP_ENVELOPE = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        "<s:Body>"
        "<tds:GetDeviceInformation/>"
        "</s:Body>"
        "</s:Envelope>"
    )

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            body = self._SOAP_ENVELOPE.encode()
            request = (
                f"POST /onvif/device_service HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Content-Type: application/soap+xml; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + body

            conn.write(request)
            data = conn.read(4096)

            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            # Check for ONVIF/SOAP indicators
            if (
                "GetDeviceInformationResponse" not in response
                and "onvif" not in response.lower()
                and "DeviceInformation" not in response
            ):
                return None

            metadata: dict = {}
            version = None

            # Extract device information fields
            mfr_match = re.search(
                r"<(?:\w+:)?Manufacturer>([^<]+)</(?:\w+:)?Manufacturer>",
                response,
            )
            if mfr_match:
                metadata["manufacturer"] = mfr_match.group(1)

            model_match = re.search(
                r"<(?:\w+:)?Model>([^<]+)</(?:\w+:)?Model>",
                response,
            )
            if model_match:
                metadata["model"] = model_match.group(1)

            fw_match = re.search(
                r"<(?:\w+:)?FirmwareVersion>([^<]+)</(?:\w+:)?FirmwareVersion>",
                response,
            )
            if fw_match:
                version = fw_match.group(1)

            serial_match = re.search(
                r"<(?:\w+:)?SerialNumber>([^<]+)</(?:\w+:)?SerialNumber>",
                response,
            )
            if serial_match:
                metadata["serial_number"] = serial_match.group(1)

            return ServiceIdentity(
                service="onvif",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
