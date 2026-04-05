"""IO-Link Master Gateway probe plugin — HTTP/REST endpoint discovery."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

# Standard IO-Link master REST endpoints to try in order
_ENDPOINTS = [
    "/iolinkmaster/port/*/iolinkdevice/pdin",
    "/iolinkmaster/port",
    "/api/v1/iolink/ports",
]

class IOLinkProbePlugin(ServiceProbe):
    name = "iolink"
    protocol = "tcp"
    default_ports = [80, 443]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            for endpoint in _ENDPOINTS:
                result = self._try_endpoint(conn.raw_socket, conn.host, conn.port, endpoint)
                if result is not None:
                    return result
                # After the first send/recv cycle the socket is consumed;
                # subsequent endpoints would need a new connection, so we
                # only try the first endpoint on the provided socket.
                break
            return None
        except (socket.timeout, OSError):
            return None

    def _try_endpoint(
        self, sock: socket.socket, host: str, port: int, endpoint: str
    ) -> ServiceIdentity | None:
        """Send HTTP GET and parse JSON response."""
        try:
            request = (
                f"GET {endpoint} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

            sock.sendall(request)
            data = sock.recv(8192)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            # Check for HTTP 200
            if not text.startswith("HTTP/1.") or " 200 " not in text.split("\r\n")[0]:
                return None

            # Split headers from body
            header_end = text.find("\r\n\r\n")
            if header_end < 0:
                return None
            body = text[header_end + 4:]

            # Parse JSON body
            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            # Extract port data — look for a list of port entries
            ports = None
            if isinstance(payload, dict):
                # Try common keys
                for key in ("ports", "data", "portList"):
                    if key in payload and isinstance(payload[key], list):
                        ports = payload[key]
                        break
                if ports is None:
                    return None
            elif isinstance(payload, list):
                ports = payload
            else:
                return None

            if not ports:
                return None

            metadata = {
                "endpoint": endpoint,
                "ports": ports,
            }

            return ServiceIdentity(
                service="iolink",
                certainty=90,
                version=None,
                metadata=metadata,
            )

        except (socket.timeout, OSError):
            return None
