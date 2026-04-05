"""NTLM/HTTP probe plugin — detects NTLM authentication and parses challenge."""
from __future__ import annotations
import base64
import re
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NTLMProbePlugin(ServiceProbe):
    name = "ntlm"
    protocol = "tcp"
    default_ports = [80, 443]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build NTLM Type 1 (Negotiate) message
            ntlm_negotiate = self._build_type1()
            ntlm_b64 = base64.b64encode(ntlm_negotiate).decode("ascii")

            # Send HTTP request with NTLM Type 1
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Authorization: NTLM {ntlm_b64}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            conn.write(request.encode())

            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            metadata: dict = {"status_code": status_code}

            # Look for 401 with WWW-Authenticate: NTLM (Type 2 challenge)
            if status_code != 401:
                return None

            # Extract NTLM Type 2 challenge from WWW-Authenticate header
            auth_match = re.search(
                r"WWW-Authenticate:[ \t]*NTLM[ \t]+(\S+)", response, re.IGNORECASE
            )
            if not auth_match:
                # Check if NTLM is listed as an auth method (without challenge)
                if re.search(r"WWW-Authenticate:\s*NTLM", response, re.IGNORECASE):
                    metadata["ntlm_supported"] = True
                    return ServiceIdentity(
                        service="ntlm",
                        certainty=70,
                        metadata=metadata,
                    )
                return None

            # Decode Type 2 (Challenge) message
            try:
                type2_data = base64.b64decode(auth_match.group(1))
            except Exception:
                return None

            challenge_info = self._parse_type2(type2_data)
            if challenge_info is None:
                return None

            metadata.update(challenge_info)
            metadata["ntlm_supported"] = True

            version = None
            if "dns_domain" in challenge_info:
                version = challenge_info["dns_domain"]

            return ServiceIdentity(
                service="ntlm",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None

    @staticmethod
    def _build_type1() -> bytes:
        """Build NTLM Type 1 (Negotiate) message."""
        signature = b"NTLMSSP\x00"
        msg_type = struct.pack("<I", 1)  # Type 1

        # Negotiate flags:
        # NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_OEM |
        # NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM |
        # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        flags = 0x00008207
        flags |= 0x00080000  # NTLMSSP_NEGOTIATE_NTLM
        negotiate_flags = struct.pack("<I", flags)

        # Domain name fields (offset/length = 0, not supplied)
        domain_fields = struct.pack("<HHI", 0, 0, 0)
        # Workstation fields (offset/length = 0, not supplied)
        workstation_fields = struct.pack("<HHI", 0, 0, 0)

        return signature + msg_type + negotiate_flags + domain_fields + workstation_fields

    @staticmethod
    def _parse_type2(data: bytes) -> dict | None:
        """Parse NTLM Type 2 (Challenge) message and extract target info."""
        if len(data) < 32:
            return None

        # Verify signature
        if data[:8] != b"NTLMSSP\x00":
            return None

        # Verify message type (3 = Type 2)
        msg_type = struct.unpack("<I", data[8:12])[0]
        if msg_type != 2:
            return None

        result: dict = {}

        # Target name (security buffer at offset 12)
        target_len = struct.unpack("<H", data[12:14])[0]
        target_offset = struct.unpack("<I", data[16:20])[0]
        if target_offset + target_len <= len(data):
            target_name = data[target_offset:target_offset + target_len]
            result["target_name"] = target_name.decode("utf-16-le", errors="replace")

        # Negotiate flags at offset 20
        if len(data) >= 24:
            flags = struct.unpack("<I", data[20:24])[0]
            result["negotiate_flags"] = flags

        # Target info (security buffer at offset 40)
        if len(data) >= 48:
            info_len = struct.unpack("<H", data[40:42])[0]
            info_offset = struct.unpack("<I", data[44:48])[0]
            if info_offset + info_len <= len(data):
                target_info = data[info_offset:info_offset + info_len]
                parsed_info = NTLMProbePlugin._parse_target_info(target_info)
                result.update(parsed_info)

        return result

    @staticmethod
    def _parse_target_info(data: bytes) -> dict:
        """Parse NTLM target info AV_PAIR structures."""
        result: dict = {}
        offset = 0

        av_id_names = {
            1: "netbios_domain",
            2: "netbios_computer",
            3: "dns_domain",
            4: "dns_computer",
            5: "dns_tree",
        }

        while offset + 4 <= len(data):
            av_id = struct.unpack("<H", data[offset:offset + 2])[0]
            av_len = struct.unpack("<H", data[offset + 2:offset + 4])[0]
            offset += 4

            if av_id == 0:  # MsvAvEOL
                break

            if offset + av_len > len(data):
                break

            av_value = data[offset:offset + av_len]
            offset += av_len

            if av_id in av_id_names:
                result[av_id_names[av_id]] = av_value.decode(
                    "utf-16-le", errors="replace"
                )
            elif av_id == 7:  # MsvAvTimestamp
                if len(av_value) == 8:
                    result["timestamp"] = struct.unpack("<Q", av_value)[0]

        return result
