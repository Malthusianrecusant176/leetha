"""XDS probe plugin — Cross-Enterprise Document Sharing (IHE XDS.b)."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class XDSProbePlugin(ServiceProbe):
    name = "xds"
    protocol = "tcp"
    default_ports = [8080, 443]

    _XDS_NS_RE = re.compile(r"urn:ihe:iti:xds-b:2007|urn:oasis:names:tc:ebxml")
    _REGISTRY_RE = re.compile(r"<(rs:)?RegistryResponse|AdhocQueryResponse")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send a minimal ITI-18 (Registry Stored Query) SOAP request
            soap_body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
                ' xmlns:a="http://www.w3.org/2005/08/addressing">'
                "<s:Header>"
                '<a:Action>urn:ihe:iti:2007:RegistryStoredQuery</a:Action>'
                "</s:Header>"
                "<s:Body>"
                '<query:AdhocQueryRequest xmlns:query="urn:oasis:names:tc:ebxml-regrep:xsd:query:3.0">'
                '<query:ResponseOption returnType="LeafClass"/>'
                '<rim:AdhocQuery xmlns:rim="urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0"'
                ' id="urn:uuid:14d4debf-8f97-4251-9a74-a90016b0af0d"/>'
                "</query:AdhocQueryRequest>"
                "</s:Body>"
                "</s:Envelope>"
            )
            request = (
                f"POST /xds/iti18 HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Content-Type: application/soap+xml; charset=utf-8\r\n"
                f"Content-Length: {len(soap_body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{soap_body}"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            has_ns = bool(self._XDS_NS_RE.search(text))
            has_registry = bool(self._REGISTRY_RE.search(text))

            if not (has_ns or has_registry):
                return None

            metadata: dict = {}
            if has_ns:
                metadata["xds_namespace"] = True
            if has_registry:
                metadata["registry_response"] = True

            confidence = 90 if (has_ns and has_registry) else 75

            return ServiceIdentity(
                service="xds",
                certainty=confidence,
                metadata=metadata,
                banner=text[:512],
            )

        except (socket.timeout, OSError):
            return None
