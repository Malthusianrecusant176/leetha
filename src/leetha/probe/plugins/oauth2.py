"""OAuth2 Authorization Server probe plugin — OpenID Connect discovery document."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OAuth2ProbePlugin(ServiceProbe):
    name = "oauth2"
    protocol = "tcp"
    default_ports = [443, 8080]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /.well-known/openid-configuration HTTP/1.0\r\n"
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

            # Must have at least one OAuth2/OIDC discovery field
            has_issuer = "issuer" in info
            has_auth_endpoint = "authorization_endpoint" in info
            has_token_endpoint = "token_endpoint" in info

            if not (has_issuer or has_auth_endpoint or has_token_endpoint):
                return None

            metadata: dict = {}
            version = None

            if has_issuer:
                metadata["issuer"] = info["issuer"]
            if has_auth_endpoint:
                metadata["authorization_endpoint"] = info["authorization_endpoint"]
            if has_token_endpoint:
                metadata["token_endpoint"] = info["token_endpoint"]
            if "grant_types_supported" in info:
                metadata["grant_types"] = info["grant_types_supported"]
            if "scopes_supported" in info:
                metadata["scopes"] = info["scopes_supported"]

            return ServiceIdentity(
                service="oauth2",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
