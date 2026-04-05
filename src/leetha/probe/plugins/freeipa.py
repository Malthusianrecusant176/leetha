"""FreeIPA probe plugin — HTTP GET /ipa/config/ca.crt or detect FreeIPA response."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FreeIPAProbePlugin(ServiceProbe):
    name = "freeipa"
    protocol = "tcp"
    default_ports = [443, 389]

    _IPA_RE = re.compile(r"(?:FreeIPA|IPA|ipa)", re.IGNORECASE)
    _CERT_RE = re.compile(r"BEGIN CERTIFICATE")
    _VERSION_RE = re.compile(r"IPA\s+(?:Server\s+)?([0-9]+(?:\.[0-9]+)*)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /ipa/config/ca.crt HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(16384)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Detect FreeIPA either by IPA identifiers or by CA cert on the IPA path
            has_ipa_marker = self._IPA_RE.search(response)
            has_cert = self._CERT_RE.search(response)

            if not (has_ipa_marker or has_cert):
                return None

            metadata: dict = {"protocol": "freeipa"}
            version = None
            confidence = 70

            if has_ipa_marker:
                confidence = 85

            if has_cert:
                metadata["ca_cert_available"] = True
                if has_ipa_marker:
                    confidence = 90

            ver_match = self._VERSION_RE.search(response)
            if ver_match:
                version = ver_match.group(1)

            return ServiceIdentity(
                service="freeipa",
                certainty=confidence,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
