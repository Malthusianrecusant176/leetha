"""etcd probe plugin — HTTP GET /version for etcd cluster detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class EtcdProbePlugin(ServiceProbe):
    name = "etcd"
    protocol = "tcp"
    default_ports = [2379, 2380]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /version HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Find JSON body after HTTP headers
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return None
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(info, dict):
                return None

            # Check for etcd-specific fields
            has_server = "etcdserver" in info
            has_cluster = "etcdcluster" in info

            if not (has_server and has_cluster):
                return None

            metadata: dict = {
                "etcdserver": info["etcdserver"],
                "etcdcluster": info["etcdcluster"],
            }
            version = info["etcdserver"]

            return ServiceIdentity(
                service="etcd",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
