"""OpenStack Swift storage probe plugin — HTTP GET /info to detect Swift proxy."""
from __future__ import annotations
import json
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SwiftStorageProbePlugin(ServiceProbe):
    name = "swift_storage"
    protocol = "tcp"
    default_ports = [8080]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /info HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())

            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            metadata: dict = {}
            is_swift = False

            status_match = self._STATUS_RE.match(response)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            # Try to parse JSON body for Swift capabilities
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                body = response[body_start + 4:].strip()
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        # Swift /info returns capabilities including "swift", "tempurl", etc.
                        if "swift" in info:
                            is_swift = True
                            metadata["swift_info"] = True
                            swift_info = info["swift"]
                            if isinstance(swift_info, dict):
                                if "version" in swift_info:
                                    metadata["swift_version"] = swift_info["version"]
                        if "tempurl" in info:
                            is_swift = True
                            metadata["tempurl"] = True
                        if "bulk_upload" in info:
                            metadata["bulk_upload"] = True
                        if "slo" in info:
                            metadata["slo"] = True
                except (json.JSONDecodeError, ValueError):
                    pass

            # Fallback: check for Swift mentions in response text
            if not is_swift:
                if "swift" in resp_lower and "tempurl" in resp_lower:
                    is_swift = True
                elif "x-trans-id" in resp_lower:
                    is_swift = True
                    metadata["has_trans_id"] = True

            if not is_swift:
                return None

            version = metadata.get("swift_version")
            if isinstance(version, (int, float)):
                version = str(version)

            return ServiceIdentity(
                service="swift_storage",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
