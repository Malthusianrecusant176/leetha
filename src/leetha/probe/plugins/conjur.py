"""CyberArk Conjur probe plugin — HTTP GET /info for Conjur detection."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ConjurProbePlugin(ServiceProbe):
    name = "conjur"
    protocol = "tcp"
    default_ports = [443, 80]

    _CONJUR_RE = re.compile(r"conjur", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /info HTTP/1.0\r\n"
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
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                # Fall back to regex check
                if self._CONJUR_RE.search(response):
                    return ServiceIdentity(
                        service="conjur",
                        certainty=60,
                        metadata={"detected_via": "banner"},
                    )
                return None

            if not isinstance(info, dict):
                return None

            # Conjur /info returns authenticators, account, or version fields
            has_authenticators = "authenticators" in info
            has_account = "account" in info or "configuration" in info
            has_conjur = self._CONJUR_RE.search(response)

            if not (has_authenticators or has_account or has_conjur):
                return None

            metadata: dict = {"protocol": "conjur"}
            version = None

            if "version" in info:
                version = info["version"]
            if has_authenticators:
                metadata["authenticators"] = info["authenticators"]
            if "account" in info:
                metadata["account"] = info["account"]
            if "configuration" in info and isinstance(info["configuration"], dict):
                conf = info["configuration"]
                if "conjur" in conf:
                    metadata["conjur_config"] = conf["conjur"]

            return ServiceIdentity(
                service="conjur",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
