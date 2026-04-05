"""QNAP NAS probe plugin — HTTP GET /cgi-bin/authLogin.cgi to detect QNAP devices."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class QNAPProbePlugin(ServiceProbe):
    name = "qnap"
    protocol = "tcp"
    default_ports = [8080, 443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _MARKERS = [
        "qnap",
        "qts",
        "quts",
        "authLogin",
        "QNAP Systems",
    ]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /cgi-bin/authLogin.cgi HTTP/1.0\r\n"
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

            # Check for QNAP markers
            found_markers = []
            for marker in self._MARKERS:
                if marker.lower() in resp_lower:
                    found_markers.append(marker)

            if not found_markers:
                return None

            metadata: dict = {"markers": found_markers}

            status_match = self._STATUS_RE.match(response)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            # Try to extract QTS/QuTS version
            version = None
            ver_match = re.search(
                r"(?:QTS|QuTS)[/ hero]*([\d.]+)", response, re.IGNORECASE
            )
            if ver_match:
                version = ver_match.group(1)
                metadata["qts_version"] = version

            # Try to extract model from response XML
            model_match = re.search(
                r"<modelName><!\\[CDATA\\[(.*?)\\]\\]></modelName>|<modelName>(.*?)</modelName>",
                response, re.IGNORECASE,
            )
            if model_match:
                model = model_match.group(1) or model_match.group(2)
                if model:
                    metadata["model"] = model

            return ServiceIdentity(
                service="qnap",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
