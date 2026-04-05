"""REDCap probe plugin — Research Electronic Data Capture."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class REDCapProbePlugin(ServiceProbe):
    name = "redcap"
    protocol = "tcp"
    default_ports = [443, 80]

    _REDCAP_RE = re.compile(r"REDCap|redcap", re.IGNORECASE)
    _VER_RE = re.compile(r"REDCap\s+v?(\d+\.\d+[\.\d]*)", re.IGNORECASE)
    _LOGIN_RE = re.compile(r'redcap_login|redcap_csrf_token|id="redcap', re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            has_redcap = bool(self._REDCAP_RE.search(text))
            has_login = bool(self._LOGIN_RE.search(text))

            if not (has_redcap or has_login):
                return None

            metadata: dict = {}
            version = None

            if has_redcap:
                metadata["redcap_detected"] = True
            if has_login:
                metadata["login_page"] = True

            m = self._VER_RE.search(text)
            if m:
                version = m.group(1)

            confidence = 90 if (has_redcap and has_login) else 80

            return ServiceIdentity(
                service="redcap",
                certainty=confidence,
                version=version,
                metadata=metadata,
                banner=text[:512],
            )

        except (socket.timeout, OSError):
            return None
