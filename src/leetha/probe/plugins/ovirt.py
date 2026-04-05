"""oVirt probe plugin — HTTPS GET /ovirt-engine/api to detect oVirt/RHEV."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OvirtProbePlugin(ServiceProbe):
    name = "ovirt"
    protocol = "tcp"
    default_ports = [443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /ovirt-engine/api HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Accept: application/xml\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            # Must contain oVirt or RHEV indicators
            if "ovirt" not in resp_lower and "rhev" not in resp_lower:
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None

            # Try to extract version from XML body
            ver_match = re.search(
                r"<full_version>([\d.]+(?:-[\w.]+)?)</full_version>", response
            )
            if ver_match:
                version = ver_match.group(1)
                metadata["full_version"] = version

            major_match = re.search(r"<major>([\d]+)</major>", response)
            minor_match = re.search(r"<minor>([\d]+)</minor>", response)
            if major_match and minor_match:
                metadata["version_major"] = major_match.group(1)
                metadata["version_minor"] = minor_match.group(1)

            product_match = re.search(
                r"<product_info>.*?<name>([^<]+)</name>", response, re.DOTALL
            )
            if product_match:
                metadata["product"] = product_match.group(1)

            return ServiceIdentity(
                service="ovirt",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
