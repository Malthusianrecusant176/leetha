"""ACME probe plugin — detects ACME (Let's Encrypt) directory endpoints."""
from __future__ import annotations
import json
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ACMEProbePlugin(ServiceProbe):
    name = "acme"
    protocol = "tcp"
    default_ports = [443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    # Required ACME directory fields per RFC 8555
    _ACME_FIELDS = ["newNonce", "newAccount", "newOrder"]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send HTTP GET to ACME directory endpoint
            request = (
                f"GET /directory HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())

            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            if status_code != 200:
                return None

            # Find JSON body (after \r\n\r\n)
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                return None

            body = response[body_start + 4:]

            # Try to parse JSON
            try:
                directory = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(directory, dict):
                return None

            # Check for required ACME directory fields
            found_fields = []
            for field in self._ACME_FIELDS:
                if field in directory:
                    found_fields.append(field)

            if len(found_fields) < 2:
                return None

            metadata: dict = {
                "status_code": status_code,
                "directory_fields": found_fields,
            }

            # Extract optional metadata
            if "meta" in directory and isinstance(directory["meta"], dict):
                meta = directory["meta"]
                if "termsOfService" in meta:
                    metadata["terms_of_service"] = meta["termsOfService"]
                if "website" in meta:
                    metadata["website"] = meta["website"]
                if "caaIdentities" in meta:
                    metadata["caa_identities"] = meta["caaIdentities"]

            # Check for revokeCert, keyChange (additional ACME endpoints)
            if "newAuthz" in directory:
                found_fields.append("newAuthz")
            if "revokeCert" in directory:
                found_fields.append("revokeCert")

            return ServiceIdentity(
                service="acme",
                certainty=85,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
