"""ClickHouse probe plugin — HTTP /ping or native client hello."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ClickHouseProbePlugin(ServiceProbe):
    name = "clickhouse"
    protocol = "tcp"
    default_ports = [9000, 8123, 9440]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            if conn.port in (8123, 9440):
                return self._probe_http(conn.raw_socket, conn.host, conn.port)
            else:
                return self._probe_native(conn.raw_socket, conn.host, conn.port)
        except (socket.timeout, OSError):
            return None

    def _probe_http(self, sock: socket.socket, host: str, port: int) -> ServiceIdentity | None:
        """Probe ClickHouse HTTP interface via /ping."""
        request = f"GET /ping HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        data = sock.recv(4096)
        if not data:
            return None

        response = data.decode("utf-8", errors="replace")
        status_match = self._STATUS_RE.match(response)
        if not status_match:
            return None

        # Find body
        body_start = response.find("\r\n\r\n")
        if body_start == -1:
            return None
        body = response[body_start + 4:].strip()

        if body != "Ok.":
            return None

        metadata: dict = {"interface": "http", "status_code": int(status_match.group(1))}
        return ServiceIdentity(
            service="clickhouse",
            certainty=90,
            version=None,
            metadata=metadata,
        )

    def _probe_native(self, sock: socket.socket, host: str, port: int) -> ServiceIdentity | None:
        """Probe ClickHouse native protocol with client hello."""
        # Build client hello packet
        # Packet type 0x00 = Hello
        packet = b"\x00"
        # Client name: "leetha"
        packet += self._encode_string(b"leetha")
        # Client version major (varint)
        packet += self._encode_varint(21)
        # Client version minor (varint)
        packet += self._encode_varint(1)
        # Client revision (varint)
        packet += self._encode_varint(54449)
        # Database name (string)
        packet += self._encode_string(b"default")
        # User (string)
        packet += self._encode_string(b"default")
        # Password (string)
        packet += self._encode_string(b"")

        sock.sendall(packet)
        data = sock.recv(4096)
        if not data or len(data) < 2:
            return None

        # Server hello response: packet type 0x00
        if data[0] != 0x00:
            return None

        # Parse server hello
        offset = 1
        metadata: dict = {"interface": "native"}
        version = None

        try:
            # Server name (string)
            server_name, offset = self._read_string(data, offset)
            metadata["server_name"] = server_name

            # Server version major (varint)
            major, offset = self._read_varint(data, offset)
            # Server version minor (varint)
            minor, offset = self._read_varint(data, offset)
            # Server revision (varint)
            revision, offset = self._read_varint(data, offset)

            version = f"{major}.{minor}.{revision}"
            metadata["version_major"] = major
            metadata["version_minor"] = minor
            metadata["revision"] = revision
        except (IndexError, ValueError):
            pass

        if not metadata.get("server_name"):
            return None

        return ServiceIdentity(
            service="clickhouse",
            certainty=90,
            version=version,
            metadata=metadata,
        )

    @staticmethod
    def _encode_varint(value: int) -> bytes:
        """Encode an integer as a varint."""
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    @staticmethod
    def _encode_string(data: bytes) -> bytes:
        """Encode a string as varint_length + bytes."""
        result = bytearray()
        length = len(data)
        while length > 0x7F:
            result.append((length & 0x7F) | 0x80)
            length >>= 7
        result.append(length & 0x7F)
        return bytes(result) + data

    @staticmethod
    def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
        """Read a varint from data at offset, return (value, new_offset)."""
        result = 0
        shift = 0
        while True:
            if offset >= len(data):
                raise IndexError("varint extends beyond data")
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, offset

    @staticmethod
    def _read_string(data: bytes, offset: int) -> tuple[str, int]:
        """Read a varint-length-prefixed string from data."""
        length = 0
        shift = 0
        while True:
            if offset >= len(data):
                raise IndexError("string length varint extends beyond data")
            byte = data[offset]
            offset += 1
            length |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        s = data[offset:offset + length].decode("utf-8", errors="replace")
        return s, offset + length
