"""Splunk HEC probe plugin — HTTP POST /services/collector for Splunk detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SplunkHECProbePlugin(ServiceProbe):
    name = "splunk_hec"
    protocol = "tcp"
    default_ports = [8088]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            body = '{"event":"probe"}'
            request = (
                f"POST /services/collector HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            lower = response.lower()

            # Look for Splunk or HEC markers in the response
            if "splunk" not in lower and "hec" not in lower and "x-splunk" not in lower:
                return None

            metadata: dict = {}
            version = None

            # Parse headers for Splunk-specific info
            for line in response.split("\r\n"):
                low = line.lower()
                if low.startswith("server:") and "splunk" in low:
                    val = line.split(":", 1)[1].strip()
                    metadata["server"] = val
                elif low.startswith("x-splunk-"):
                    key, _, val = line.partition(":")
                    metadata[key.lower()] = val.strip()

            # Check response body for HEC-specific JSON
            body_start = response.find("\r\n\r\n")
            if body_start >= 0:
                resp_body = response[body_start + 4:].strip()
                if "invalid" in resp_body.lower() or "token" in resp_body.lower():
                    metadata["auth_required"] = True
                elif "success" in resp_body.lower():
                    metadata["auth_required"] = False

            return ServiceIdentity(
                service="splunk_hec",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
