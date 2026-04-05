"""Keycloak Identity Server probe plugin — HTTP GET realm JSON response."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class KeycloakProbePlugin(ServiceProbe):
    name = "keycloak"
    protocol = "tcp"
    default_ports = [8080, 8443]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /auth/realms/master HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(16384)
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
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(info, dict):
                return None

            # Keycloak realm response must contain "realm" and "public_key"
            has_realm = "realm" in info
            has_public_key = "public_key" in info

            if not (has_realm and has_public_key):
                return None

            metadata: dict = {
                "realm": info["realm"],
            }
            version = None

            if "token-service" in info:
                metadata["token_service"] = info["token-service"]
            if "account-service" in info:
                metadata["account_service"] = info["account-service"]

            return ServiceIdentity(
                service="keycloak",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
