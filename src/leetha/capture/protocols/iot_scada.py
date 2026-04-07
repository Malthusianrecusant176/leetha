"""IoT/SCADA protocol parsers -- Modbus TCP, BACnet/IP, CoAP, MQTT, EtherNet/IP.

Each parser extracts fields from raw payloads and returns a CapturedPacket
whose protocol name matches the processor registration in
``leetha.processors.iot_scada``.
"""
from __future__ import annotations

import struct

from leetha.capture.packets import CapturedPacket


# ---------------------------------------------------------------------------
# UMAS — Schneider Electric (port 502, Modbus FC 0x5A)
# ---------------------------------------------------------------------------

def parse_umas(packet) -> CapturedPacket | None:
    """Parse Schneider Electric UMAS protocol on port 502.

    UMAS uses Modbus function code 0x5A (90) with proprietary sub-functions.
    Must be checked BEFORE Modbus to intercept UMAS-specific traffic.
    """
    from scapy.all import IP, TCP, Raw

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    tcp = packet[TCP]
    if tcp.sport != 502 and tcp.dport != 502:
        return None

    try:
        payload = bytes(packet[TCP].payload)
    except Exception:
        return None

    # MBAP header (7 bytes) + function code
    if len(payload) < 8:
        return None

    # Must be Modbus protocol ID (0x0000)
    proto_id = struct.unpack("!H", payload[2:4])[0]
    if proto_id != 0x0000:
        return None

    # UMAS uses function code 0x5A (90)
    function_code = payload[7]
    if function_code != 0x5A:
        return None

    # UMAS sub-function code at byte 8
    umas_subcode = payload[8] if len(payload) > 8 else 0

    umas_functions = {
        0x01: "init_comm",
        0x02: "read_id",
        0x03: "read_project_info",
        0x04: "read_plc_info",
        0x06: "read_memory",
        0x0A: "start_plc",
        0x10: "read_coils",
        0x20: "write_coils",
        0x22: "read_io_object",
        0x23: "write_io_object",
        0x30: "monitor",
        0x31: "read_data",
        0x32: "take_plc_reservation",
        0x33: "release_plc_reservation",
        0x36: "read_plc_status",
        0x39: "read_application_name",
        0x40: "begin_download",
        0x41: "download_block",
        0x42: "end_download",
        0x50: "begin_upload",
        0x51: "upload_block",
        0x52: "end_upload",
        0x58: "keep_alive",
    }

    fields = {
        "umas_subcode": umas_subcode,
        "umas_function": umas_functions.get(umas_subcode, f"func_{umas_subcode:#04x}"),
        "unit_id": payload[6],
        "is_server": tcp.sport == 502,
    }

    # Try to extract project name or PLC info from response
    if umas_subcode in (0x03, 0x04, 0x39) and len(payload) > 12:
        # Response data after MBAP+FC+subcode
        data_start = 9
        raw_data = payload[data_start:]
        # Look for ASCII strings in response
        ascii_parts = []
        current = []
        for b in raw_data:
            if 0x20 <= b < 0x7F:
                current.append(chr(b))
            else:
                if len(current) >= 3:
                    ascii_parts.append(''.join(current))
                current = []
        if len(current) >= 3:
            ascii_parts.append(''.join(current))
        if ascii_parts:
            fields["extracted_strings"] = ascii_parts[:5]
            # First meaningful string is often the project/app name
            fields["project_name"] = ascii_parts[0] if ascii_parts else None

    is_server = tcp.sport == 502

    return CapturedPacket(
        protocol="umas",
        hw_addr=packet.src,
        ip_addr=packet[IP].src if not is_server else packet[IP].dst,
        target_ip=packet[IP].dst if not is_server else packet[IP].src,
        fields=fields,
    )


# ---------------------------------------------------------------------------
# Modbus TCP (port 502)
# ---------------------------------------------------------------------------

def parse_modbus(packet) -> CapturedPacket | None:
    """Parse Modbus TCP packets on port 502.

    MBAP header (7 bytes):
      0-1  Transaction ID
      2-3  Protocol ID (must be 0x0000 for Modbus)
      4-5  Length
      6    Unit ID
    PDU byte 0 = function code.
    """
    from scapy.all import IP, TCP, UDP, Raw

    if not packet.haslayer(IP):
        return None

    sport = dport = None
    if packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        sport, dport = packet[UDP].sport, packet[UDP].dport
    else:
        return None

    if sport != 502 and dport != 502:
        return None

    try:
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
        else:
            payload = bytes(packet[UDP].payload)
    except Exception:
        return None

    # MBAP header (7 bytes) + at least 1 byte function code
    if len(payload) < 8:
        return None

    # Protocol ID must be 0x0000
    proto_id = struct.unpack("!H", payload[2:4])[0]
    if proto_id != 0x0000:
        return None

    unit_id = payload[6]
    function_code = payload[7]

    return CapturedPacket(
        protocol="modbus",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields={
            "unit_id": unit_id,
            "function_code": function_code,
        },
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


# ---------------------------------------------------------------------------
# BACnet/IP (UDP port 47808)
# ---------------------------------------------------------------------------

def parse_bacnet(packet) -> CapturedPacket | None:
    """Parse BACnet/IP packets on UDP port 47808 (0xBAC0).

    BVLC header:
      Byte 0: Type (0x81 = BACnet/IP)
      Byte 1: Function
      Byte 2-3: Length
    """
    from scapy.all import IP, UDP

    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None

    udp = packet[UDP]
    if udp.dport != 47808 and udp.sport != 47808:
        return None

    try:
        payload = bytes(udp.payload)
    except Exception:
        return None

    if len(payload) < 4:
        return None

    # BVLC type must be 0x81
    if payload[0] != 0x81:
        return None

    bvlc_function = payload[1]

    fields: dict = {
        "bvlc_function": bvlc_function,
    }

    # Attempt to extract vendor_id, object_name, model_name from deeper
    # APDU layers if present.  BACnet APDU parsing is complex; we do
    # best-effort extraction of common tagged values.
    _extract_bacnet_fields(payload[4:], fields)

    return CapturedPacket(
        protocol="bacnet",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields=fields,
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


def _extract_bacnet_fields(data: bytes, fields: dict) -> None:
    """Best-effort extraction of BACnet APDU fields.

    Scans for common context-tagged values.  This is intentionally
    shallow -- full BACnet decoding is out of scope for passive
    fingerprinting.
    """
    # Look for vendor_id pattern (context tag 2, unsigned)
    # and character-string values that might be object_name / model_name.
    # For now we just note their absence; deeper parsing can be added later.
    fields.setdefault("vendor_id", None)
    fields.setdefault("object_name", None)
    fields.setdefault("model_name", None)


# ---------------------------------------------------------------------------
# CoAP (UDP port 5683)
# ---------------------------------------------------------------------------

def parse_coap(packet) -> CapturedPacket | None:
    """Parse CoAP packets on UDP port 5683.

    Header (4 bytes minimum):
      Byte 0: Ver (2 bits) | Type (2 bits) | Token Length (4 bits)
      Byte 1: Code (3-bit class . 5-bit detail)
      Byte 2-3: Message ID
    Options follow the header.
    """
    from scapy.all import IP, UDP

    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None

    udp = packet[UDP]
    if udp.dport != 5683 and udp.sport != 5683:
        return None

    try:
        payload = bytes(udp.payload)
    except Exception:
        return None

    if len(payload) < 4:
        return None

    # Version must be 1 (bits 7-6)
    version = (payload[0] >> 6) & 0x03
    if version != 1:
        return None

    msg_type = (payload[0] >> 4) & 0x03
    token_len = payload[0] & 0x0F
    code_class = (payload[1] >> 5) & 0x07
    code_detail = payload[1] & 0x1F

    fields: dict = {
        "message_type": msg_type,
        "code": f"{code_class}.{code_detail:02d}",
        "uri_path": None,
        "content_format": None,
    }

    # Parse options starting after the token
    opt_offset = 4 + token_len
    _parse_coap_options(payload, opt_offset, fields)

    return CapturedPacket(
        protocol="coap",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields=fields,
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


def _parse_coap_options(payload: bytes, offset: int, fields: dict) -> None:
    """Walk CoAP options and extract Uri-Path (11) and Content-Format (12)."""
    opt_number = 0
    uri_parts: list[str] = []

    while offset < len(payload):
        byte = payload[offset]
        if byte == 0xFF:  # payload marker
            break

        delta = (byte >> 4) & 0x0F
        length = byte & 0x0F
        offset += 1

        if delta == 13:
            if offset >= len(payload):
                break
            delta = payload[offset] + 13
            offset += 1
        elif delta == 14:
            if offset + 1 >= len(payload):
                break
            delta = struct.unpack("!H", payload[offset : offset + 2])[0] + 269
            offset += 2
        elif delta == 15:
            break

        if length == 13:
            if offset >= len(payload):
                break
            length = payload[offset] + 13
            offset += 1
        elif length == 14:
            if offset + 1 >= len(payload):
                break
            length = struct.unpack("!H", payload[offset : offset + 2])[0] + 269
            offset += 2
        elif length == 15:
            break

        opt_number += delta
        opt_value = payload[offset : offset + length]
        offset += length

        if opt_number == 11:  # Uri-Path
            uri_parts.append(opt_value.decode("utf-8", errors="replace"))
        elif opt_number == 12:  # Content-Format
            if len(opt_value) == 1:
                fields["content_format"] = opt_value[0]
            elif len(opt_value) == 2:
                fields["content_format"] = struct.unpack("!H", opt_value)[0]

    if uri_parts:
        fields["uri_path"] = "/" + "/".join(uri_parts)


# ---------------------------------------------------------------------------
# MQTT (TCP port 1883 / 8883)
# ---------------------------------------------------------------------------

def parse_mqtt(packet) -> CapturedPacket | None:
    """Parse MQTT CONNECT and PUBLISH packets on TCP ports 1883/8883.

    Fixed header byte 0:
      Bits 7-4: Packet type (1=CONNECT, 3=PUBLISH)
      Bits 3-0: Flags
    """
    from scapy.all import IP, TCP

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    if tcp.dport not in (1883, 8883) and tcp.sport not in (1883, 8883):
        return None

    try:
        payload = bytes(tcp.payload)
    except Exception:
        return None

    if len(payload) < 2:
        return None

    pkt_type = (payload[0] >> 4) & 0x0F

    # Only handle CONNECT (1) and PUBLISH (3)
    if pkt_type not in (1, 3):
        return None

    # Decode remaining length (variable-length encoding)
    remaining_length, rl_bytes = _mqtt_decode_remaining_length(payload, 1)
    if remaining_length is None:
        return None

    body_start = 1 + rl_bytes
    body = payload[body_start:]

    fields: dict = {
        "message_type": "CONNECT" if pkt_type == 1 else "PUBLISH",
        "client_id": None,
        "topic": None,
    }

    if pkt_type == 1:
        _parse_mqtt_connect(body, fields)
    elif pkt_type == 3:
        _parse_mqtt_publish(body, fields)

    return CapturedPacket(
        protocol="mqtt",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields=fields,
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


def _mqtt_decode_remaining_length(
    data: bytes, offset: int
) -> tuple[int | None, int]:
    """Decode MQTT variable-length integer. Returns (value, bytes_consumed)."""
    multiplier = 1
    value = 0
    consumed = 0
    while offset < len(data):
        encoded_byte = data[offset]
        offset += 1
        consumed += 1
        value += (encoded_byte & 0x7F) * multiplier
        if (encoded_byte & 0x80) == 0:
            return value, consumed
        multiplier *= 128
        if consumed > 4:
            break
    return None, consumed


def _parse_mqtt_connect(body: bytes, fields: dict) -> None:
    """Extract client_id from an MQTT CONNECT variable header + payload."""
    # Variable header: Protocol Name (length-prefixed string) + Protocol Level
    # + Connect Flags + Keep Alive
    if len(body) < 10:
        return

    proto_name_len = struct.unpack("!H", body[0:2])[0]
    offset = 2 + proto_name_len  # skip protocol name
    if offset + 4 > len(body):
        return
    # Skip protocol level (1 byte), connect flags (1 byte), keep alive (2 bytes)
    offset += 4

    # Payload starts with Client ID (length-prefixed UTF-8 string)
    if offset + 2 > len(body):
        return
    client_id_len = struct.unpack("!H", body[offset : offset + 2])[0]
    offset += 2
    if offset + client_id_len > len(body):
        return
    fields["client_id"] = body[offset : offset + client_id_len].decode(
        "utf-8", errors="replace"
    )


def _parse_mqtt_publish(body: bytes, fields: dict) -> None:
    """Extract topic from an MQTT PUBLISH variable header."""
    if len(body) < 2:
        return
    topic_len = struct.unpack("!H", body[0:2])[0]
    if 2 + topic_len > len(body):
        return
    fields["topic"] = body[2 : 2 + topic_len].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# EtherNet/IP (TCP/UDP port 44818)
# ---------------------------------------------------------------------------

_ENIP_COMMANDS = {
    0x0004: "ListServices",
    0x0063: "ListIdentity",
    0x0065: "RegisterSession",
    0x0066: "UnRegisterSession",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
}


def parse_enip(packet) -> CapturedPacket | None:
    """Parse EtherNet/IP encapsulation header on port 44818.

    Header (24 bytes):
      0-1   Command
      2-3   Length of data portion
      4-7   Session Handle
      8-11  Status
      12-19 Sender Context
      20-23 Options
    """
    from scapy.all import IP, TCP, UDP

    if not packet.haslayer(IP):
        return None

    sport = dport = None
    if packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        sport, dport = packet[UDP].sport, packet[UDP].dport
    else:
        return None

    if sport != 44818 and dport != 44818:
        return None

    try:
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
        else:
            payload = bytes(packet[UDP].payload)
    except Exception:
        return None

    # Encapsulation header is 24 bytes minimum
    if len(payload) < 24:
        return None

    command = struct.unpack("<H", payload[0:2])[0]
    data_length = struct.unpack("<H", payload[2:4])[0]

    command_name = _ENIP_COMMANDS.get(command)
    if command_name is None:
        return None

    fields: dict = {
        "command": command_name,
        "product_name": None,
        "vendor_id": None,
        "device_type": None,
    }

    # For ListIdentity responses, try to extract identity info
    if command == 0x0063 and len(payload) > 24:
        _parse_enip_list_identity(payload[24:], fields)

    return CapturedPacket(
        protocol="enip",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields=fields,
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )


def _parse_enip_list_identity(data: bytes, fields: dict) -> None:
    """Extract identity fields from a ListIdentity response CPF.

    The response contains a count of items, each item having:
      Type ID (2), Length (2), then identity data.
    Identity data layout (after encapsulation version + socket addr):
      Vendor ID (2), Device Type (2), Product Code (2),
      Revision (2), Status (2), Serial (4),
      Product Name Length (1), Product Name (variable).
    """
    if len(data) < 2:
        return

    item_count = struct.unpack("<H", data[0:2])[0]
    if item_count < 1:
        return

    offset = 2
    if offset + 4 > len(data):
        return

    # type_id = struct.unpack("<H", data[offset : offset + 2])[0]
    item_length = struct.unpack("<H", data[offset + 2 : offset + 4])[0]
    offset += 4

    item_data = data[offset : offset + item_length]

    # Skip encapsulation protocol version (2) + socket address (16)
    id_offset = 18
    if id_offset + 14 > len(item_data):
        return

    fields["vendor_id"] = struct.unpack("<H", item_data[id_offset : id_offset + 2])[0]
    fields["device_type"] = struct.unpack(
        "<H", item_data[id_offset + 2 : id_offset + 4]
    )[0]

    # Skip product code (2), revision (2), status (2), serial (4)
    name_len_offset = id_offset + 14
    if name_len_offset >= len(item_data):
        return

    name_len = item_data[name_len_offset]
    name_start = name_len_offset + 1
    if name_start + name_len > len(item_data):
        return

    fields["product_name"] = item_data[name_start : name_start + name_len].decode(
        "utf-8", errors="replace"
    )


# ---------------------------------------------------------------------------
# DNP3 (TCP port 20000)
# ---------------------------------------------------------------------------

def parse_dnp3(packet) -> CapturedPacket | None:
    """Parse DNP3 packets on port 20000."""
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
    except ImportError:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    if tcp.dport != 20000 and tcp.sport != 20000:
        return None

    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw])
    if len(payload) < 10:
        return None

    # DNP3 Data Link Layer: start bytes 0x0564
    if payload[0:2] != b'\x05\x64':
        return None

    dl_length = payload[2]
    control = payload[3]
    dst_addr = struct.unpack('<H', payload[4:6])[0]
    src_addr = struct.unpack('<H', payload[6:8])[0]

    # Direction and Primary bits
    direction = bool(control & 0x80)  # DIR: 1=master->outstation, 0=outstation->master
    primary = bool(control & 0x40)    # PRM: 1=from primary station
    func_code = control & 0x0F

    func_names = {
        0: "confirm", 1: "read", 2: "write", 3: "select",
        4: "operate", 7: "immediate_freeze", 9: "cold_restart",
        13: "warm_restart", 14: "open_file", 15: "close_file",
        129: "response", 130: "unsolicited_response",
    }

    # Transport layer function code (if present after DL header)
    transport_fc = None
    if len(payload) > 10:
        # After 10-byte DL header (including 2 CRC bytes at 8-9)
        transport_byte = payload[10] if len(payload) > 10 else None
        if transport_byte is not None:
            transport_fc = transport_byte & 0x3F

    is_server = tcp.sport == 20000

    return CapturedPacket(
        protocol="dnp3",
        hw_addr=packet.src,
        ip_addr=packet[IP].src if not is_server else packet[IP].dst,
        target_ip=packet[IP].dst if not is_server else packet[IP].src,
        fields={
            "dl_length": dl_length,
            "control": control,
            "direction": "master_to_outstation" if direction else "outstation_to_master",
            "primary": primary,
            "func_code": func_code,
            "func_name": func_names.get(func_code, f"fc_{func_code}"),
            "dst_addr": dst_addr,
            "src_addr": src_addr,
            "is_server": is_server,
        },
    )


# ---------------------------------------------------------------------------
# S7comm (TCP port 102)
# ---------------------------------------------------------------------------

def parse_s7comm(packet) -> CapturedPacket | None:
    """Parse Siemens S7comm packets on port 102 (TPKT/COTP transport)."""
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
    except ImportError:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    if tcp.dport != 102 and tcp.sport != 102:
        return None

    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw])
    if len(payload) < 7:
        return None

    # TPKT header: version=3, reserved=0, 2-byte length
    if payload[0] != 3 or payload[1] != 0:
        return None

    tpkt_length = struct.unpack('>H', payload[2:4])[0]

    # COTP header: length, PDU type
    cotp_length = payload[4]
    cotp_pdu_type = payload[5] >> 4  # Upper 4 bits

    cotp_type_names = {
        0x0E: "connect_request",
        0x0D: "connect_confirm",
        0x08: "disconnect_request",
        0x0C: "disconnect_confirm",
        0x0F: "data_transfer",
        0x05: "expedited_data",
        0x07: "ack",
    }

    fields = {
        "tpkt_length": tpkt_length,
        "cotp_pdu_type": cotp_pdu_type,
        "cotp_type_name": cotp_type_names.get(cotp_pdu_type, f"type_{cotp_pdu_type:#x}"),
        "is_server": tcp.sport == 102,
    }

    # S7comm header starts after COTP data header
    # For data transfer (0x0F), COTP header is 3 bytes (len, type, flags)
    s7_offset = 4 + 1 + cotp_length + 1  # TPKT(4) + COTP header
    if cotp_pdu_type == 0x0F and len(payload) > s7_offset + 2:
        s7_header = payload[s7_offset:]
        if s7_header[0] == 0x32:  # S7 protocol magic
            fields["s7_protocol"] = True
            fields["s7_pdu_type"] = s7_header[1] if len(s7_header) > 1 else None
            s7_pdu_names = {
                0x01: "job_request",
                0x02: "ack",
                0x03: "ack_data",
                0x07: "userdata",
            }
            fields["s7_pdu_name"] = s7_pdu_names.get(fields["s7_pdu_type"], "unknown")

            # Extract function code from parameter section
            if len(s7_header) > 12:
                param_offset = 12  # Fixed header is 12 bytes for job/ack_data
                if len(s7_header) > param_offset:
                    fields["s7_function"] = s7_header[param_offset]
                    s7_func_names = {
                        0x00: "cpu_services", 0x04: "read_variable",
                        0x05: "write_variable", 0xF0: "setup_communication",
                        0x28: "plc_control", 0x29: "plc_stop",
                    }
                    fields["s7_function_name"] = s7_func_names.get(
                        fields["s7_function"], f"fc_{fields['s7_function']:#x}")

    is_server = tcp.sport == 102

    return CapturedPacket(
        protocol="s7comm",
        hw_addr=packet.src,
        ip_addr=packet[IP].src if not is_server else packet[IP].dst,
        target_ip=packet[IP].dst if not is_server else packet[IP].src,
        fields=fields,
    )


# ---------------------------------------------------------------------------
# OPC UA (TCP port 4840/4843)
# ---------------------------------------------------------------------------

def parse_opcua(packet) -> CapturedPacket | None:
    """Parse OPC UA Binary protocol on port 4840/4843."""
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
    except ImportError:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    opcua_ports = {4840, 4843}
    if tcp.dport not in opcua_ports and tcp.sport not in opcua_ports:
        return None

    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw])
    if len(payload) < 8:
        return None

    # OPC UA message header: 3-byte type + chunk type + 4-byte length
    try:
        msg_type = payload[0:3].decode('ascii')
    except (UnicodeDecodeError, ValueError):
        return None

    valid_types = {"HEL", "ACK", "OPN", "CLO", "MSG", "ERR"}
    if msg_type not in valid_types:
        return None

    chunk_type = chr(payload[3]) if payload[3] in (ord('F'), ord('C'), ord('A')) else '?'
    msg_length = struct.unpack('<I', payload[4:8])[0]

    fields = {
        "msg_type": msg_type,
        "chunk_type": chunk_type,
        "msg_length": msg_length,
        "is_server": tcp.sport in opcua_ports,
    }

    type_descriptions = {
        "HEL": "hello",
        "ACK": "acknowledge",
        "OPN": "open_secure_channel",
        "CLO": "close_secure_channel",
        "MSG": "message",
        "ERR": "error",
    }
    fields["type_name"] = type_descriptions.get(msg_type, msg_type)

    # Extract endpoint URL from HEL message
    if msg_type == "HEL" and len(payload) > 32:
        try:
            # HEL: after 8-byte header + 4x4-byte protocol fields (versions/sizes) = offset 28
            url_len = struct.unpack('<I', payload[28:32])[0]
            if 0 < url_len < 256 and len(payload) >= 32 + url_len:
                endpoint_url = payload[32:32+url_len].decode('utf-8', errors='replace')
                fields["endpoint_url"] = endpoint_url
        except (struct.error, ValueError):
            pass

    is_server = tcp.sport in opcua_ports

    return CapturedPacket(
        protocol="opcua",
        hw_addr=packet.src,
        ip_addr=packet[IP].src if not is_server else packet[IP].dst,
        target_ip=packet[IP].dst if not is_server else packet[IP].src,
        fields=fields,
    )


# ---------------------------------------------------------------------------
# IEC 61850 GOOSE (EtherType 0x88B8)
# ---------------------------------------------------------------------------

def _ber_length(data: bytes, offset: int) -> tuple[int, int]:
    """Parse BER-encoded length field. Returns (length, new_offset)."""
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + num_bytes > len(data):
        return 0, offset
    length = int.from_bytes(data[offset:offset+num_bytes], 'big')
    return length, offset + num_bytes


def parse_goose(packet) -> CapturedPacket | None:
    """Parse IEC 61850 GOOSE frames (EtherType 0x88B8)."""
    try:
        from scapy.layers.l2 import Ether
    except ImportError:
        return None

    if not packet.haslayer(Ether):
        return None

    eth = packet[Ether]
    if eth.type != 0x88B8:
        return None

    payload = bytes(eth.payload) if eth.payload else b''
    if len(payload) < 8:
        return None

    fields = {
        "ethertype": "0x88B8",
    }

    # GOOSE APDU parsing (ASN.1 BER encoded)
    # First 2 bytes: APPID, then 2 bytes: length, then 4 bytes: reserved
    if len(payload) >= 8:
        appid = struct.unpack('>H', payload[0:2])[0]
        goose_length = struct.unpack('>H', payload[2:4])[0]
        fields["appid"] = appid
        fields["goose_length"] = goose_length

        # Parse GOOSE PDU (tag 0x61 = goosePdu)
        offset = 8  # After APPID(2) + Length(2) + Reserved(4)
        if offset < len(payload) and payload[offset] == 0x61:
            offset += 1
            # BER length
            pdu_len, offset = _ber_length(payload, offset)

            # Parse GOOSE fields (tag-length-value sequences)
            while offset < len(payload) - 2:
                tag = payload[offset]
                offset += 1
                field_len, offset = _ber_length(payload, offset)
                if field_len <= 0 or offset + field_len > len(payload):
                    break
                value = payload[offset:offset+field_len]
                offset += field_len

                if tag == 0x80:  # gocbRef
                    fields["gocb_ref"] = value.decode('utf-8', errors='replace')
                elif tag == 0x81:  # timeAllowedtoLive
                    pass
                elif tag == 0x82:  # datSet
                    fields["dat_set"] = value.decode('utf-8', errors='replace')
                elif tag == 0x83:  # goID
                    fields["go_id"] = value.decode('utf-8', errors='replace')
                elif tag == 0x86:  # stNum
                    fields["st_num"] = int.from_bytes(value, 'big')
                elif tag == 0x87:  # sqNum
                    fields["sq_num"] = int.from_bytes(value, 'big')

    return CapturedPacket(
        protocol="goose",
        hw_addr=packet.src,
        ip_addr="0.0.0.0",  # L2 protocol, no IP
        fields=fields,
    )


# ---------------------------------------------------------------------------
# PROFINET (EtherType 0x8892)
# ---------------------------------------------------------------------------

def parse_profinet(packet) -> CapturedPacket | None:
    """Parse PROFINET frames (EtherType 0x8892)."""
    try:
        from scapy.layers.l2 import Ether
    except ImportError:
        return None

    if not packet.haslayer(Ether):
        return None

    eth = packet[Ether]
    if eth.type != 0x8892:
        return None

    payload = bytes(eth.payload) if eth.payload else b''
    if len(payload) < 4:
        return None

    # PROFINET frame: FrameID (2 bytes) + data
    frame_id = struct.unpack('>H', payload[0:2])[0]

    fields = {
        "ethertype": "0x8892",
        "frame_id": frame_id,
    }

    # Classify by frame ID ranges
    if 0x0100 <= frame_id <= 0x7FFF:
        fields["frame_type"] = "rt_class1"  # Real-time cyclic
    elif 0x8000 <= frame_id <= 0xBFFF:
        fields["frame_type"] = "rt_class2"  # Real-time cyclic high priority
    elif 0xC000 <= frame_id <= 0xFBFF:
        fields["frame_type"] = "rt_class3"  # Isochronous real-time
    elif frame_id == 0xFEFE:
        fields["frame_type"] = "dcp_identify_request"
    elif frame_id == 0xFEFF:
        fields["frame_type"] = "dcp_identify_response"
    elif frame_id == 0xFEFD:
        fields["frame_type"] = "dcp_get_set"
    elif 0xFC00 <= frame_id <= 0xFCFF:
        fields["frame_type"] = "alarm"
    else:
        fields["frame_type"] = f"frame_{frame_id:#06x}"

    # Parse DCP Identify Response for device info
    if frame_id == 0xFEFF and len(payload) > 12:
        # DCP response: ServiceID(1) + ServiceType(1) + Xid(4) + ResponseDelay(2) + DataLength(2) + blocks
        offset = 12  # Skip DCP header
        while offset + 4 < len(payload):
            opt = payload[offset]
            sub = payload[offset+1]
            block_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
            offset += 4
            if block_len <= 0 or offset + block_len > len(payload):
                break
            block_data = payload[offset:offset+block_len]
            offset += block_len
            # Pad to even
            if block_len % 2:
                offset += 1

            if opt == 0x02:  # Device properties
                if sub == 0x01:  # Vendor (NameOfVendor)
                    fields["vendor_name"] = block_data[2:].decode('utf-8', errors='replace').rstrip('\x00')
                elif sub == 0x02:  # Station name
                    fields["station_name"] = block_data[2:].decode('utf-8', errors='replace').rstrip('\x00')
                elif sub == 0x03:  # Device ID
                    if len(block_data) >= 6:
                        fields["vendor_id"] = struct.unpack('>H', block_data[2:4])[0]
                        fields["device_id"] = struct.unpack('>H', block_data[4:6])[0]
                elif sub == 0x05:  # Device role
                    if len(block_data) >= 4:
                        role = struct.unpack('>H', block_data[2:4])[0]
                        roles = []
                        if role & 0x01: roles.append("io_device")
                        if role & 0x02: roles.append("io_controller")
                        if role & 0x04: roles.append("io_multidevice")
                        if role & 0x08: roles.append("io_supervisor")
                        fields["device_role"] = roles or ["unknown"]

    return CapturedPacket(
        protocol="profinet",
        hw_addr=packet.src,
        ip_addr="0.0.0.0",  # L2 protocol, no IP
        fields=fields,
    )
