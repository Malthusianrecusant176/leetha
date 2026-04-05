"""SAML IdP (Identity Provider) probe plugin — HTTP GET for SAML metadata."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SAMLProbePlugin(ServiceProbe):
    name = "saml"
    protocol = "tcp"
    default_ports = [443, 8443]

    _ENTITY_RE = re.compile(r"EntityDescriptor", re.IGNORECASE)
    _ENTITY_ID_RE = re.compile(r'entityID="([^"]+)"')
    _BINDING_RE = re.compile(
        r'Binding="urn:oasis:names:tc:SAML:2\.0:bindings:([\w-]+)"'
    )

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /saml/metadata HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(16384)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            if not self._ENTITY_RE.search(response):
                return None

            metadata: dict = {"protocol": "saml2"}
            version = "2.0"

            entity_match = self._ENTITY_ID_RE.search(response)
            if entity_match:
                metadata["entity_id"] = entity_match.group(1)

            bindings = self._BINDING_RE.findall(response)
            if bindings:
                metadata["bindings"] = list(set(bindings))

            if "IDPSSODescriptor" in response:
                metadata["role"] = "idp"
            elif "SPSSODescriptor" in response:
                metadata["role"] = "sp"

            return ServiceIdentity(
                service="saml",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
