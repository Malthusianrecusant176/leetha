"""InfluxDB probe plugin — HTTP /ping endpoint."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class InfluxDBProbePlugin(ServiceProbe):
    name = "influxdb"
    protocol = "tcp"
    default_ports = [8086, 8088]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")
    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = f"GET /ping HTTP/1.0\r\nHost: {conn.host}\r\nConnection: close\r\n\r\n"
            conn.write(request.encode())
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            headers = {}
            for key, val in self._HEADER_RE.findall(response):
                headers[key.lower()] = val

            version = None
            metadata: dict = {"status_code": status_code}

            # Check for InfluxDB-specific headers
            influx_version = headers.get("x-influxdb-version")
            influx_build = headers.get("x-influxdb-build")

            if influx_version:
                version = influx_version
                metadata["influxdb_version"] = influx_version
            if influx_build:
                metadata["influxdb_build"] = influx_build

            if not influx_version and not influx_build:
                return None

            return ServiceIdentity(
                service="influxdb",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
