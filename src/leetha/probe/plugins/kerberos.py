"""Kerberos probe plugin — sends AS-REQ for a dummy principal."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class KerberosProbePlugin(ServiceProbe):
    name = "kerberos"
    protocol = "tcp"
    default_ports = [88]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a minimal Kerberos AS-REQ
            as_req = self._build_as_req("LEETHA.LOCAL", "leetha-probe")

            # Kerberos over TCP uses a 4-byte big-endian length prefix
            length_prefix = struct.pack(">I", len(as_req))
            conn.write(length_prefix + as_req)

            # Read 4-byte length prefix
            length_data = self._recv_exact(conn.raw_socket, 4)
            if not length_data:
                return None

            resp_length = struct.unpack(">I", length_data)[0]
            if resp_length > 65535 or resp_length < 2:
                return None

            data = self._recv_exact(conn.raw_socket, resp_length)
            if not data or len(data) < 2:
                return None

            # Parse ASN.1 tag
            tag = data[0]
            metadata: dict = {}

            # APPLICATION[30] = KRB-ERROR (0x7E)
            if tag == 0x7E:
                metadata["response_type"] = "KRB-ERROR"
                # Try to parse error code from the KRB-ERROR
                error_code = self._extract_error_code(data)
                if error_code is not None:
                    metadata["error_code"] = error_code
                    # Common Kerberos error codes
                    error_names = {
                        6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
                        7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
                        14: "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED",
                        24: "KDC_ERR_PREAUTH_FAILED",
                        25: "KDC_ERR_PREAUTH_REQUIRED",
                        68: "KDC_ERR_WRONG_REALM",
                    }
                    if error_code in error_names:
                        metadata["error_name"] = error_names[error_code]

                return ServiceIdentity(
                    service="kerberos",
                    certainty=85,
                    metadata=metadata,
                )

            # APPLICATION[11] = AS-REP (0x6B)
            if tag == 0x6B:
                metadata["response_type"] = "AS-REP"
                return ServiceIdentity(
                    service="kerberos",
                    certainty=85,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError, struct.error):
            return None

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
        """Receive exactly n bytes."""
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    @staticmethod
    def _build_as_req(realm: str, principal: str) -> bytes:
        """Build a minimal ASN.1-encoded Kerberos AS-REQ."""
        # Helper to encode ASN.1 length
        def _asn1_len(length: int) -> bytes:
            if length < 0x80:
                return bytes([length])
            elif length < 0x100:
                return bytes([0x81, length])
            else:
                return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])

        # Helper to encode ASN.1 tagged value
        def _asn1_tag(tag_class: int, tag_num: int, content: bytes, constructed: bool = True) -> bytes:
            if tag_class == 0 and not constructed:
                # Universal primitive
                tag_byte = tag_num
            elif tag_class == 0 and constructed:
                # Universal constructed
                tag_byte = 0x20 | tag_num
            elif tag_class == 2:  # Context-specific
                tag_byte = 0xA0 | tag_num
                if constructed:
                    tag_byte = 0xA0 | tag_num
                else:
                    tag_byte = 0x80 | tag_num
            elif tag_class == 1:  # Application
                if tag_num < 31:
                    tag_byte = 0x60 | tag_num
                else:
                    return bytes([0x7F, tag_num]) + _asn1_len(len(content)) + content
            else:
                tag_byte = tag_num
            return bytes([tag_byte]) + _asn1_len(len(content)) + content

        def _asn1_integer(value: int) -> bytes:
            if value < 0x80:
                return bytes([0x02, 0x01, value])
            elif value < 0x8000:
                return bytes([0x02, 0x02, (value >> 8) & 0xFF, value & 0xFF])
            else:
                return bytes([0x02, 0x04,
                              (value >> 24) & 0xFF, (value >> 16) & 0xFF,
                              (value >> 8) & 0xFF, value & 0xFF])

        def _asn1_string(s: str) -> bytes:
            encoded = s.encode("utf-8")
            return bytes([0x1B]) + _asn1_len(len(encoded)) + encoded  # GeneralString

        # kdc-options: forwardable, renewable, canonicalize
        kdc_options = bytes([0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10])

        # cname: PrincipalName (type 1 = NT-PRINCIPAL)
        name_string = _asn1_tag(0, 0x10, _asn1_string(principal), constructed=True)  # SEQUENCE OF
        cname_inner = (
            _asn1_tag(2, 0, _asn1_integer(1))  # name-type [0]
            + _asn1_tag(2, 1, name_string)  # name-string [1]
        )
        cname = _asn1_tag(0, 0x10, cname_inner, constructed=True)  # SEQUENCE

        # realm
        realm_encoded = _asn1_string(realm)

        # sname: PrincipalName (type 2 = NT-SRV-INST for krbtgt)
        sname_strings = _asn1_tag(0, 0x10,
                                   _asn1_string("krbtgt") + _asn1_string(realm),
                                   constructed=True)
        sname_inner = (
            _asn1_tag(2, 0, _asn1_integer(2))
            + _asn1_tag(2, 1, sname_strings)
        )
        sname = _asn1_tag(0, 0x10, sname_inner, constructed=True)

        # etype: supported encryption types
        # 17 = AES128-CTS-HMAC-SHA1-96, 18 = AES256-CTS-HMAC-SHA1-96, 23 = RC4-HMAC
        etype_list = _asn1_integer(18) + _asn1_integer(17) + _asn1_integer(23)
        etype_seq = _asn1_tag(0, 0x10, etype_list, constructed=True)

        # KDC-REQ-BODY
        req_body_inner = (
            _asn1_tag(2, 0, kdc_options)       # kdc-options [0]
            + _asn1_tag(2, 1, cname)           # cname [1]
            + _asn1_tag(2, 2, realm_encoded)   # realm [2]
            + _asn1_tag(2, 3, sname)           # sname [3]
            + _asn1_tag(2, 7, b"\x30\x02\x13\x00")  # etype [7] (simplified)
            + _asn1_tag(2, 8, etype_seq)       # etype [8]
        )
        req_body = _asn1_tag(0, 0x10, req_body_inner, constructed=True)

        # KDC-REQ (AS-REQ)
        kdc_req_inner = (
            _asn1_tag(2, 1, _asn1_integer(5))  # pvno [1] = 5
            + _asn1_tag(2, 2, _asn1_integer(10))  # msg-type [2] = 10 (AS-REQ)
            + _asn1_tag(2, 4, req_body)         # req-body [4]
        )
        kdc_req = _asn1_tag(0, 0x10, kdc_req_inner, constructed=True)

        # Wrap in APPLICATION[10] for AS-REQ
        as_req = _asn1_tag(1, 10, kdc_req)

        return as_req

    @staticmethod
    def _extract_error_code(data: bytes) -> int | None:
        """Try to extract error code from KRB-ERROR ASN.1 data."""
        # Simple heuristic: search for context tag [6] (error-code)
        # which is followed by an INTEGER
        for i in range(len(data) - 4):
            if data[i] == 0xA6:  # Context [6] constructed
                # Next bytes should be length, then INTEGER tag (0x02)
                offset = i + 1
                if offset >= len(data):
                    continue
                inner_len = data[offset]
                offset += 1
                if inner_len == 0x81:
                    offset += 1
                if offset >= len(data) or data[offset] != 0x02:
                    continue
                offset += 1
                if offset >= len(data):
                    continue
                int_len = data[offset]
                offset += 1
                if offset + int_len > len(data):
                    continue
                value = 0
                for b in data[offset:offset + int_len]:
                    value = (value << 8) | b
                return value
        return None
