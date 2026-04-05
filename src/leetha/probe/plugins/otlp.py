"""OTLP probe plugin — detect OpenTelemetry Collector via HTTP or gRPC."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OTLPProbePlugin(ServiceProbe):
    name = "otlp"
    protocol = "tcp"
    default_ports = [4317, 4318]

    # gRPC connection preface
    _GRPC_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # Minimal gRPC SETTINGS frame (type=0x04, length=0, flags=0, stream=0)
    _GRPC_SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            if conn.port == 4317:
                return self._probe_grpc(conn.raw_socket, conn.host, conn.port)
            return self._probe_http(conn.raw_socket, conn.host, conn.port)
        except (socket.timeout, OSError):
            return None

    def _probe_http(self, sock: socket.socket, host: str, port: int) -> ServiceIdentity | None:
        """Probe the OTLP HTTP endpoint (4318)."""
        request = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {host}:{port}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode("utf-8"))
        data = sock.recv(8192)
        if not data:
            return None

        response = data.decode("utf-8", errors="replace")
        lower = response.lower()

        # Look for OpenTelemetry or OTLP markers
        if "opentelemetry" not in lower and "otlp" not in lower:
            return None

        metadata: dict = {"transport": "http"}
        version = None

        # Try to extract version from headers
        for line in response.split("\r\n"):
            low = line.lower()
            if "server:" in low and "opentelemetry" in low:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    val = parts[1].strip()
                    # Try to extract version from server header
                    for token in val.split("/"):
                        token = token.strip()
                        if token and token[0].isdigit():
                            version = token
                            break

        if version:
            metadata["version"] = version

        return ServiceIdentity(
            service="otlp",
            certainty=80,
            version=version,
            metadata=metadata,
        )

    def _probe_grpc(self, sock: socket.socket, host: str, port: int) -> ServiceIdentity | None:
        """Probe gRPC port by sending HTTP/2 connection preface."""
        sock.sendall(self._GRPC_PREFACE + self._GRPC_SETTINGS)
        data = sock.recv(4096)
        if not data or len(data) < 9:
            return None

        # Check for HTTP/2 SETTINGS frame response (type=0x04)
        # Frame format: length(3) + type(1) + flags(1) + stream_id(4)
        frame_type = data[3] if len(data) > 3 else 0

        if frame_type != 0x04:
            return None

        metadata: dict = {"transport": "grpc"}
        return ServiceIdentity(
            service="otlp",
            certainty=70,
            metadata=metadata,
        )
