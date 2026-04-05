"""XNAT probe plugin — neuroimaging research platform."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class XNATProbePlugin(ServiceProbe):
    name = "xnat"
    protocol = "tcp"
    default_ports = [8080, 443]

    _XNAT_RE = re.compile(r"XNAT|xnat", re.IGNORECASE)
    _VER_RE = re.compile(r'"version"\s*:\s*"([^"]+)"')

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /data/JSESSION HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(8192)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            # Check for XNAT indicators
            has_xnat = bool(self._XNAT_RE.search(text))
            has_jsession = "JSESSIONID" in text or "JSESSION" in text

            if not (has_xnat or has_jsession):
                return None

            # Need at least one XNAT-specific indicator
            if not has_xnat and has_jsession:
                # JSESSION alone is too generic; skip unless X-XNAT header present
                if "X-XNAT" not in text:
                    return None

            metadata: dict = {}
            if has_xnat:
                metadata["xnat_detected"] = True
            if has_jsession:
                metadata["jsession_present"] = True

            version = None
            m = self._VER_RE.search(text)
            if m:
                version = m.group(1)

            confidence = 90 if has_xnat else 70

            return ServiceIdentity(
                service="xnat",
                certainty=confidence,
                version=version,
                metadata=metadata,
                banner=text[:512],
            )

        except (socket.timeout, OSError):
            return None
