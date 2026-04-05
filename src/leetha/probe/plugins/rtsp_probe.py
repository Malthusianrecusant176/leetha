"""RTSP probe plugin — OPTIONS request detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RtspProbePlugin(ServiceProbe):
    name = "rtsp_probe"
    protocol = "tcp"
    default_ports = [554, 8554]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send RTSP OPTIONS request
            request = (
                f"OPTIONS rtsp://{conn.host} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            # Must be an RTSP response
            if not text.startswith("RTSP/"):
                return None

            metadata = {}
            version = None
            banner = text.strip()

            # Parse status line
            status_match = re.match(r"RTSP/(\d+\.\d+)\s+(\d+)\s+(.*)", text)
            if status_match:
                metadata["rtsp_version"] = status_match.group(1)
                metadata["status_code"] = int(status_match.group(2))
                metadata["status_text"] = status_match.group(3).strip()

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
                key = key.strip().lower()
                val = val.strip()

                if key == "server":
                    metadata["server"] = val
                    version = val
                elif key == "public":
                    methods = [m.strip() for m in val.split(",")]
                    metadata["methods"] = methods
                elif key == "cseq":
                    metadata["cseq"] = val

            return ServiceIdentity(
                service="rtsp",
                certainty=90,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
