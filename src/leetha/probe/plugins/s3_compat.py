"""S3-compatible storage probe plugin — HTTP GET / to detect MinIO and S3 endpoints."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class S3CompatProbePlugin(ServiceProbe):
    name = "s3_compat"
    protocol = "tcp"
    default_ports = [9000, 443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _HEADER_RE = re.compile(r"^([\w-]+):\s*(.+)$", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET / HTTP/1.0\r\n"
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

            # Parse headers
            headers: dict[str, str] = {}
            for match in self._HEADER_RE.finditer(response):
                headers[match.group(1).lower()] = match.group(2).strip()

            metadata: dict = {}
            is_s3 = False

            # Check for S3 specific headers
            if "x-amz-request-id" in headers:
                is_s3 = True
                metadata["amz_request_id"] = headers["x-amz-request-id"]

            if "x-amz-id-2" in headers:
                metadata["amz_id_2"] = headers["x-amz-id-2"]

            # Check Server header for MinIO
            server = headers.get("server", "")
            if "minio" in server.lower():
                is_s3 = True
                metadata["server"] = server

            # Check for S3 error XML
            if "<code>accessdenied</code>" in resp_lower or "s3" in resp_lower:
                if "x-amz-request-id" in resp_lower or "amz" in resp_lower:
                    is_s3 = True

            if not is_s3:
                return None

            status_match = self._STATUS_RE.match(response)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None
            if "minio" in server.lower():
                ver_match = re.search(r"MinIO[/ ]([\w.-]+)", server)
                if ver_match:
                    version = ver_match.group(1)

            return ServiceIdentity(
                service="s3_compat",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
