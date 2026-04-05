"""WebSocket probe plugin — upgrade handshake detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class WebSocketProbePlugin(ServiceProbe):
    name = "websocket"
    protocol = "tcp"
    default_ports = [80, 443]

    # Fixed key for the probe (base64 of "the sample nonce")
    WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
    # Expected accept value for this key (SHA-1 + base64)
    WS_EXPECTED_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send WebSocket upgrade request
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {self.WS_KEY}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            # Must be an HTTP response with 101 Switching Protocols
            if not text.startswith("HTTP/"):
                return None

            metadata = {}
            version = None

            # Parse status line
            status_match = re.match(r"HTTP/(\d+\.\d+)\s+(\d+)", text)
            if not status_match:
                return None

            status_code = int(status_match.group(2))
            metadata["status_code"] = status_code

            if status_code != 101:
                return None

            # Check for required WebSocket upgrade headers
            text_lower = text.lower()
            has_upgrade = "upgrade: websocket" in text_lower
            has_accept = "sec-websocket-accept" in text_lower

            if not has_upgrade or not has_accept:
                return None

            # Parse headers for additional info
            header_end = text.find("\r\n\r\n")
            if header_end >= 0:
                header_section = text[:header_end]
            else:
                header_section = text

            for line in header_section.split("\r\n")[1:]:
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key_lower = key.strip().lower()
                val = val.strip()

                if key_lower == "sec-websocket-accept":
                    metadata["accept"] = val
                elif key_lower == "sec-websocket-protocol":
                    metadata["protocol"] = val
                elif key_lower == "sec-websocket-extensions":
                    metadata["extensions"] = val
                elif key_lower == "server":
                    metadata["server"] = val
                    version = val

            return ServiceIdentity(
                service="websocket",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
