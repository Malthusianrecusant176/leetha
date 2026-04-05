"""OPC UA probe plugin — Hello / Acknowledge handshake."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OPCUAProbePlugin(ServiceProbe):
    name = "opcua"
    protocol = "tcp"
    default_ports = [4840, 4843]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            endpoint_url = f"opc.tcp://{conn.host}:{conn.port}".encode("utf-8")

            # OPC UA Hello message
            # Message type: "HEL" + reserved byte "F" (Final)
            # Then: message size (4), protocol version (4),
            #       receive buffer size (4), send buffer size (4),
            #       max message size (4), max chunk count (4),
            #       endpoint URL length (4) + endpoint URL
            body = struct.pack(
                "<IIIIII",
                0,           # Protocol version
                65536,       # Receive buffer size
                65536,       # Send buffer size
                0,           # Max message size (0 = no limit)
                0,           # Max chunk count (0 = no limit)
                len(endpoint_url),
            ) + endpoint_url

            message_size = 8 + len(body)  # 8 = type(3) + reserved(1) + size(4)
            hello = b"HELF" + struct.pack("<I", message_size) + body

            conn.write(hello)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Check for Acknowledge message ("ACK" + "F")
            msg_type = data[0:3]
            if msg_type != b"ACK":
                # Could be an error message ("ERR")
                if msg_type == b"ERR" and len(data) >= 16:
                    error_code = struct.unpack("<I", data[8:12])[0]
                    return ServiceIdentity(
                        service="opcua",
                        certainty=85,
                        metadata={"error_code": error_code, "error": True},
                    )
                return None

            metadata = {}
            # Parse ACK message body
            if len(data) >= 28:
                (
                    ack_msg_size,
                    protocol_version,
                    recv_buf_size,
                    send_buf_size,
                    max_msg_size,
                    max_chunk_count,
                ) = struct.unpack("<IIIIII", data[4:28])

                metadata["protocol_version"] = protocol_version
                metadata["receive_buffer_size"] = recv_buf_size
                metadata["send_buffer_size"] = send_buf_size
                metadata["max_message_size"] = max_msg_size
                metadata["max_chunk_count"] = max_chunk_count

            return ServiceIdentity(
                service="opcua",
                certainty=90,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None
