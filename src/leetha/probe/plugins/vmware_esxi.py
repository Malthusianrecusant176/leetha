"""VMware ESXi probe plugin — HTTPS GET /sdk to detect VMware ESXi/vCenter."""
from __future__ import annotations

import re
import socket
import ssl

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class VMwareESXiProbePlugin(ServiceProbe):
    name = "vmware_esxi"
    protocol = "tcp"
    default_ports = [443, 902]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # ESXi/vCenter require TLS on conn.port 443
            if conn.port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn.raw_socket = ctx.wrap_socket(conn.raw_socket, server_hostname=conn.host)

            request = (
                f"GET /sdk HTTP/1.1\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            # Must contain VMware indicators
            if "vmware" not in resp_lower and "vsphere" not in resp_lower:
                return None

            status_match = self._STATUS_RE.match(response)
            metadata: dict = {}
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

            version = None
            # Try to extract version from response body
            ver_match = re.search(
                r"<version>([\d.]+)</version>", response, re.IGNORECASE
            )
            if ver_match:
                version = ver_match.group(1)
                metadata["esxi_version"] = version

            build_match = re.search(
                r"<build>([\d]+)</build>", response, re.IGNORECASE
            )
            if build_match:
                metadata["build"] = build_match.group(1)

            name_match = re.search(
                r"<name>([^<]+)</name>", response, re.IGNORECASE
            )
            product_name = ""
            if name_match:
                product_name = name_match.group(1)
                metadata["product_name"] = product_name

            # Set os_family and device_type for evidence aggregation
            # Product name from /sdk XML: "VMware vCenter Server" or "VMware ESXi"
            product_lower = product_name.lower()
            if "vcenter" in product_lower:
                metadata["os_family"] = "vCenter"
                metadata["device_type"] = "vcenter"
                metadata["manufacturer"] = "VMware"
            elif "esxi" in product_lower or "esxi" in resp_lower:
                metadata["os_family"] = "ESXi"
                metadata["device_type"] = "hypervisor"
                metadata["manufacturer"] = "VMware"
            else:
                # Generic VMware infrastructure — likely vCenter or ESXi
                metadata["os_family"] = "VMware"
                metadata["device_type"] = "hypervisor"
                metadata["manufacturer"] = "VMware"

            return ServiceIdentity(
                service="vmware_esxi",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
