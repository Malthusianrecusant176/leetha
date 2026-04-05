"""Kubernetes API probe plugin — HTTP GET /version for K8s API server detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class KubernetesAPIProbePlugin(ServiceProbe):
    name = "kubernetes_api"
    protocol = "tcp"
    default_ports = [6443, 8443]

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

            # Check for Kubernetes-specific fields
            has_major = "major" in info
            has_minor = "minor" in info
            has_git_version = "gitVersion" in info

            if not (has_major and has_minor):
                return None

            metadata: dict = {
                "major": info["major"],
                "minor": info["minor"],
            }
            version = None

            if has_git_version:
                metadata["git_version"] = info["gitVersion"]
                version = info["gitVersion"]
            if "platform" in info:
                metadata["platform"] = info["platform"]
            if "goVersion" in info:
                metadata["go_version"] = info["goVersion"]
            if "compiler" in info:
                metadata["compiler"] = info["compiler"]
            if "buildDate" in info:
                metadata["build_date"] = info["buildDate"]

            return ServiceIdentity(
                service="kubernetes_api",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
