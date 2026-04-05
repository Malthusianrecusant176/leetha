"""ArgoCD probe plugin — HTTP GET /api/version for ArgoCD detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ArgoCDProbePlugin(ServiceProbe):
    name = "argocd"
    protocol = "tcp"
    default_ports = [443, 8080]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /api/version HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for ArgoCD markers
            resp_lower = response.lower()
            has_argocd = "argocd" in resp_lower or "argo-cd" in resp_lower or "argo cd" in resp_lower

            if not has_argocd:
                return None

            metadata: dict = {}
            version = None

            # Try to parse JSON body
            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                body_start = response.find("\n\n")
                if body_start < 0:
                    return ServiceIdentity(
                        service="argocd",
                        certainty=65,
                        metadata=metadata,
                    )
                body_start += 2
            else:
                body_start += 4

            body = response[body_start:].strip()
            if body:
                try:
                    info = json.loads(body)
                    if isinstance(info, dict):
                        if "Version" in info:
                            version = info["Version"]
                            metadata["version"] = version
                        if "BuildDate" in info:
                            metadata["build_date"] = info["BuildDate"]
                        if "GitCommit" in info:
                            metadata["git_commit"] = info["GitCommit"]
                        if "GoVersion" in info:
                            metadata["go_version"] = info["GoVersion"]
                        if "Compiler" in info:
                            metadata["compiler"] = info["Compiler"]
                        if "Platform" in info:
                            metadata["platform"] = info["Platform"]
                except (json.JSONDecodeError, ValueError):
                    pass

            return ServiceIdentity(
                service="argocd",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
