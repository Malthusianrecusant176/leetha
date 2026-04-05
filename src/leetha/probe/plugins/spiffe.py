"""SPIFFE/SPIRE probe plugin — HTTP probe to SPIRE server API for trust domain info."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SPIFFEProbePlugin(ServiceProbe):
    name = "spiffe"
    protocol = "tcp"
    default_ports = [8081]

    _SPIFFE_RE = re.compile(r"spiffe://", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/v1/trust-domain HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return None
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()

            # Check for SPIFFE trust domain identifiers
            has_spiffe = self._SPIFFE_RE.search(response)

            # Try JSON parse
            info = None
            if body:
                try:
                    info = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    pass

            if not has_spiffe and info is None:
                return None

            if info is not None and isinstance(info, dict):
                has_trust_domain = "trust_domain" in info or "trustDomain" in info
                if not has_trust_domain and not has_spiffe:
                    return None

            metadata: dict = {"protocol": "spiffe"}
            version = None

            if info and isinstance(info, dict):
                td = info.get("trust_domain") or info.get("trustDomain")
                if td:
                    metadata["trust_domain"] = td
                if "spire" in response.lower():
                    metadata["implementation"] = "spire"

            return ServiceIdentity(
                service="spiffe",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
