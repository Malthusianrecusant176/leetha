"""WebDAV probe plugin — PROPFIND request detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class WebDAVProbePlugin(ServiceProbe):
    name = "webdav"
    protocol = "tcp"
    default_ports = [80, 443]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send PROPFIND request
            request = (
                f"PROPFIND / HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Depth: 0\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            # Must be an HTTP response
            if not text.startswith("HTTP/"):
                return None

            metadata = {}
            version = None
            is_webdav = False

            # Parse status line
            status_match = re.match(r"HTTP/(\d+\.\d+)\s+(\d+)\s+(.*)", text)
            if not status_match:
                return None

            status_code = int(status_match.group(2))
            metadata["status_code"] = status_code

            # 207 Multi-Status is the definitive WebDAV response
            if status_code == 207:
                is_webdav = True

            # Parse headers
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

                if key_lower == "dav":
                    is_webdav = True
                    metadata["dav"] = val
                elif key_lower == "server":
                    metadata["server"] = val
                    version = val
                elif key_lower == "ms-author-via":
                    if val.upper() == "DAV":
                        is_webdav = True
                    metadata["ms_author_via"] = val
                elif key_lower == "allow":
                    methods = [m.strip() for m in val.split(",")]
                    metadata["methods"] = methods
                    # If PROPFIND is in Allow header, it's WebDAV-capable
                    if "PROPFIND" in val.upper():
                        is_webdav = True

            # Check body for WebDAV XML
            if header_end >= 0:
                body = text[header_end + 4:]
                if "multistatus" in body.lower() or "DAV:" in body:
                    is_webdav = True

            if not is_webdav:
                return None

            confidence = 90 if status_code == 207 else 75

            return ServiceIdentity(
                service="webdav",
                certainty=confidence,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
