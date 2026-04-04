"""Protocol-specific banner matchers for passive TCP service identification.

Each matcher receives raw TCP payload bytes (up to 2048) and returns a dict
with identification fields, or ``None`` if the payload does not match.

The public entry point is :func:`match_banner`.
"""

from __future__ import annotations

import re
import struct
from typing import Callable

# ---------------------------------------------------------------------------
# Individual matchers
# ---------------------------------------------------------------------------

def _match_ssh(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    m = re.match(r"SSH-(\S+)-(\S+)", text)
    if m is None:
        return None
    proto_version = m.group(1)
    software_raw = m.group(2)
    # Try to split software_version, e.g. "OpenSSH_9.2p1" -> ("OpenSSH", "9.2p1")
    version: str | None = None
    sw_match = re.match(r"(.+?)[-_](\d\S*)", software_raw)
    if sw_match:
        software = sw_match.group(1)
        version = sw_match.group(2)
    else:
        software = software_raw
    result: dict = {
        "service": "ssh",
        "software": software,
        "proto_version": proto_version,
        "raw_banner": text.strip(),
    }
    if version is not None:
        result["version"] = version
    return result


def _match_ftp(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not (text.startswith("220 ") or text.startswith("220-")):
        return None
    result: dict = {"service": "ftp", "raw_banner": text.strip()}
    # Try to find software name/version
    # Common patterns: "220 ProFTPD 1.3.8 ..." or "220 (vsFTPd 3.0.5)"
    m = re.search(r"220[ -]\(?(\w\S+?)[\s_]+([\d][\d.]*\S*)", text)
    if m:
        sw = m.group(1)
        if sw not in ("Welcome", "Service"):
            result["software"] = sw
            result["version"] = m.group(2)
    else:
        # Try software-only pattern
        m = re.search(r"220[ -]\(?(\w{2,}\S*)", text)
        if m and m.group(1) not in ("Welcome", "Service"):
            result["software"] = m.group(1)
    return result


def _match_smtp(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not text.startswith("220"):
        return None
    if "SMTP" not in text.upper() and "ESMTP" not in text.upper():
        return None
    result: dict = {"service": "smtp", "raw_banner": text.strip()}
    # Try to get the software name after ESMTP/SMTP
    m = re.search(r"(?:ESMTP|SMTP)\s+(\S+)", text)
    if m:
        result["software"] = m.group(1)
    return result


def _match_imap(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not text.startswith("* OK"):
        return None
    result: dict = {"service": "imap", "raw_banner": text.strip()}
    # Try to extract software, e.g. "Dovecot", "Cyrus"
    m = re.search(r"\]\s+(\S+)", text)
    if m:
        result["software"] = m.group(1)
    return result


def _match_pop3(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not text.startswith("+OK"):
        return None
    result: dict = {"service": "pop3", "raw_banner": text.strip()}
    m = re.search(r"\+OK\s+(\S+)", text)
    if m:
        result["software"] = m.group(1)
    return result


def _match_telnet(payload: bytes) -> dict | None:
    if payload[:2] in (b"\xff\xfb", b"\xff\xfd"):
        return {"service": "telnet", "raw_banner": payload.hex()}
    text = payload.decode("ascii", errors="replace").lower()
    if "login:" in text:
        return {"service": "telnet", "raw_banner": text.strip()}
    return None


def _match_vnc(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    m = re.match(r"RFB\s+(\d{3}\.\d{3})", text)
    if m is None:
        return None
    return {
        "service": "vnc",
        "version": m.group(1),
        "raw_banner": text.strip(),
    }


def _match_irc(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if "NOTICE" in text or re.match(r":\S+\s+\d{3}", text):
        return {"service": "irc", "raw_banner": text.strip()}
    return None


def _match_mysql(payload: bytes) -> dict | None:
    if len(payload) < 6:
        return None
    # MySQL greeting packet: 3 bytes length (LE) + 1 byte seq + 1 byte proto_ver
    proto_ver = payload[4]
    if proto_ver != 0x0A:
        return None
    # Version string starts at byte 5, null-terminated
    null_idx = payload.find(b"\x00", 5)
    if null_idx == -1:
        return None
    version_str = payload[5:null_idx].decode("ascii", errors="replace")
    software = "MariaDB" if "MariaDB" in version_str else "MySQL"
    # Clean version: for MariaDB like "5.5.5-10.11.4-MariaDB" extract real version
    version = version_str
    if software == "MariaDB":
        m = re.search(r"(\d+\.\d+\.\d+)-MariaDB", version_str)
        if m:
            version = m.group(1)
    return {
        "service": "mysql",
        "software": software,
        "version": version,
        "raw_banner": version_str,
    }


def _match_postgresql(payload: bytes) -> dict | None:
    if len(payload) < 1:
        return None
    tag = chr(payload[0])
    if tag not in ("R", "S", "E"):
        return None
    result: dict = {"service": "postgresql", "software": "PostgreSQL", "raw_banner": payload.hex()}
    # Try to find server_version in ParameterStatus messages (tag 'S')
    # Format: 'S' + int32 length + param_name\x00 + param_value\x00
    idx = 0
    while idx < len(payload):
        if payload[idx:idx + 1] == b"S" and idx + 4 < len(payload):
            msg_len = struct.unpack("!I", payload[idx + 1:idx + 5])[0]
            msg_body = payload[idx + 5:idx + 1 + msg_len]
            parts = msg_body.split(b"\x00")
            if len(parts) >= 2 and parts[0] == b"server_version":
                result["version"] = parts[1].decode("ascii", errors="replace")
                break
            idx += 1 + msg_len
        else:
            idx += 1
    return result


def _match_mssql(payload: bytes) -> dict | None:
    if len(payload) < 1:
        return None
    if payload[0] != 0x04:
        return None
    return {
        "service": "mssql",
        "software": "MSSQL",
        "raw_banner": payload.hex(),
    }


def _match_mongodb(payload: bytes) -> dict | None:
    if len(payload) < 16:
        return None
    # Bytes 12-15 are the opcode (little-endian)
    opcode = struct.unpack("<I", payload[12:16])[0]
    if opcode not in (1, 2013):
        return None
    result: dict = {"service": "mongodb", "software": "MongoDB", "raw_banner": payload.hex()}
    # Try to extract version from BSON body if present
    text = payload.decode("ascii", errors="replace")
    m = re.search(r'"version"\s*:\s*"([\d.]+)"', text)
    if m:
        result["version"] = m.group(1)
    return result


def _match_redis(payload: bytes) -> dict | None:
    if len(payload) < 1:
        return None
    if chr(payload[0]) not in ("+", "-", "$", "*", ":"):
        return None
    text = payload.decode("ascii", errors="replace")
    result: dict = {"service": "redis", "raw_banner": text.strip()}
    # Try to extract version from INFO response
    m = re.search(r"redis_version:([\d.]+)", text)
    if m:
        result["version"] = m.group(1)
    return result


def _match_smb(payload: bytes) -> dict | None:
    # NetBIOS session header is 4 bytes, then SMB magic
    if len(payload) < 8:
        return None
    magic = payload[4:8]
    if magic == b"\xfeSMB":
        smb_ver = "2"
    elif magic == b"\xffSMB":
        smb_ver = "1"
    else:
        return None
    return {
        "service": "smb",
        "smb_version": smb_ver,
        "raw_banner": payload[:32].hex(),
    }


def _match_rdp(payload: bytes) -> dict | None:
    if len(payload) < 6:
        return None
    if payload[0] != 0x03:
        return None
    if payload[5] != 0xD0:
        return None
    return {"service": "rdp", "raw_banner": payload.hex()}


def _match_ipp(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if "application/ipp" not in text.lower():
        return None
    result: dict = {"service": "ipp", "raw_banner": text.strip()}
    m = re.search(r"Server:\s*(.+?)(?:\r?\n)", text)
    if m:
        result["software"] = m.group(1).strip()
    return result


def _match_jetdirect(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not text.startswith("@PJL"):
        return None
    return {"service": "jetdirect", "raw_banner": text.strip()}


def _match_lpd(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace").lower()
    if any(kw in text for kw in ("printer", "queue", "lpd")):
        return {"service": "lpd", "raw_banner": text.strip()}
    return None


def _match_mqtt(payload: bytes) -> dict | None:
    if len(payload) < 4:
        return None
    if payload[0] != 0x20:
        return None
    result: dict = {"service": "mqtt", "raw_banner": payload[:4].hex()}
    result["connect_return_code"] = payload[3]
    return result


def _match_sip(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not (text.startswith("SIP/") or "SIP/2.0" in text):
        return None
    result: dict = {"service": "sip", "raw_banner": text.strip()}
    m = re.search(r"Server:\s*(.+?)(?:\r?\n)", text)
    if m:
        result["software"] = m.group(1).strip()
    return result


def _match_rtsp(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not text.startswith("RTSP/"):
        return None
    result: dict = {"service": "rtsp", "raw_banner": text.strip()}
    m = re.search(r"Server:\s*(.+?)(?:\r?\n)", text)
    if m:
        result["software"] = m.group(1).strip()
    return result


def _match_ldap(payload: bytes) -> dict | None:
    if len(payload) < 6:
        return None
    if payload[0] != 0x30:
        return None
    # Look for BindResponse (0x61) or SearchResultDone (0x65) application tag
    found = False
    for i in range(2, min(len(payload), 16)):
        if payload[i] in (0x61, 0x65):
            found = True
            break
    if not found:
        return None
    return {"service": "ldap", "raw_banner": payload[:16].hex()}


def _match_cassandra(payload: bytes) -> dict | None:
    if len(payload) < 4:
        return None
    # Response: high nibble of byte 0 has bit 7 set (0x80+)
    if payload[0] & 0x80 == 0:
        return None
    opcode = payload[3]
    if opcode not in (0x02, 0x06):
        return None
    return {"service": "cassandra", "raw_banner": payload[:8].hex()}


def _match_elasticsearch(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not text.startswith("HTTP/"):
        return None
    if '"cluster_name"' not in text:
        return None
    result: dict = {
        "service": "elasticsearch",
        "software": "Elasticsearch",
        "raw_banner": text.strip(),
    }
    m = re.search(r'"number"\s*:\s*"([\d.]+)"', text)
    if m:
        result["version"] = m.group(1)
    return result


def _match_amqp(payload: bytes) -> dict | None:
    if len(payload) < 4:
        return None
    if payload[:4] == b"AMQP":
        # Protocol header, e.g. AMQP\x00\x00\x09\x01
        result: dict = {"service": "amqp", "raw_banner": payload[:8].hex()}
        if len(payload) >= 8:
            result["proto_version"] = f"{payload[5]}.{payload[6]}.{payload[7]}"
        return result
    if payload[0] == 0x01:
        # AMQP method frame
        return {"service": "amqp", "raw_banner": payload[:16].hex()}
    return None


def _match_docker_api(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not text.startswith("HTTP/"):
        return None
    if '"ApiVersion"' not in text:
        return None
    result: dict = {
        "service": "docker_api",
        "software": "Docker",
        "raw_banner": text.strip(),
    }
    m = re.search(r'"ApiVersion"\s*:\s*"([^"]+)"', text)
    if m:
        result["version"] = m.group(1)
    return result


def _match_kubernetes_api(payload: bytes) -> dict | None:
    text = payload.decode("ascii", errors="replace")
    if not text.startswith("HTTP/"):
        return None
    has_version = '"major"' in text and '"minor"' in text
    has_status = '"kind":"Status"' in text or '"kind": "Status"' in text
    if not (has_version or has_status):
        return None
    result: dict = {
        "service": "kubernetes_api",
        "software": "Kubernetes",
        "raw_banner": text.strip(),
    }
    m = re.search(r'"gitVersion"\s*:\s*"([^"]+)"', text)
    if m:
        result["version"] = m.group(1)
    return result


def _match_socks(payload: bytes) -> dict | None:
    if len(payload) < 2:
        return None
    # SOCKS5: byte 0 = 0x05
    if payload[0] == 0x05:
        return {"service": "socks", "version": "5", "raw_banner": payload[:2].hex()}
    # SOCKS4: byte 0 = 0x00, byte 1 = 0x5A (request granted)
    if payload[0] == 0x00 and payload[1] == 0x5A:
        return {"service": "socks", "version": "4", "raw_banner": payload[:8].hex()}
    return None


def _match_bgp(payload: bytes) -> dict | None:
    if len(payload) < 21:
        return None
    # 16 bytes of 0xFF marker
    if payload[:16] != b"\xff" * 16:
        return None
    # Type field at byte 18 must be 1 (OPEN)
    msg_type = payload[18]
    if msg_type != 1:
        return None
    result: dict = {"service": "bgp", "raw_banner": payload[:21].hex()}
    # BGP version at byte 19
    result["version"] = str(payload[19])
    # AS number at bytes 20-21
    if len(payload) >= 22:
        result["as_number"] = struct.unpack("!H", payload[20:22])[0]
    return result


def _match_pptp(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    # Bytes 8-9 = 0x0001 (control message)
    # Bytes 10-11 = 0x0002 (Start-Control-Connection-Reply)
    if payload[8:10] != b"\x00\x01":
        return None
    if payload[10:12] != b"\x00\x02":
        return None
    return {"service": "pptp", "raw_banner": payload[:32].hex()}


def _match_unifiprotect(payload: bytes) -> dict | None:
    """UniFi Protect HTTPS — TLS or HTTP response from Protect controller/camera."""
    # TLS ServerHello starts with 0x16 (handshake) then version
    if payload[0] == 0x16 and len(payload) >= 5:
        return {
            "service": "unifiprotect",
            "software": "UniFi Protect",
            "raw_banner": payload[:8].hex(),
        }
    # HTTP response
    text = payload.decode("ascii", errors="replace")
    if text.startswith("HTTP/"):
        result: dict = {
            "service": "unifiprotect",
            "software": "UniFi Protect",
            "raw_banner": text[:256].strip(),
        }
        m = re.search(r"Server:\s*(.+?)(?:\r?\n)", text)
        if m:
            result["software"] = m.group(1).strip()
        return result
    return None


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_MATCHERS: dict[str, Callable[[bytes], dict | None]] = {
    "ssh": _match_ssh,
    "ftp": _match_ftp,
    "smtp": _match_smtp,
    "imap": _match_imap,
    "pop3": _match_pop3,
    "telnet": _match_telnet,
    "vnc": _match_vnc,
    "irc": _match_irc,
    "mysql": _match_mysql,
    "postgresql": _match_postgresql,
    "mssql": _match_mssql,
    "mongodb": _match_mongodb,
    "redis": _match_redis,
    "smb": _match_smb,
    "rdp": _match_rdp,
    "ipp": _match_ipp,
    "jetdirect": _match_jetdirect,
    "lpd": _match_lpd,
    "mqtt": _match_mqtt,
    "sip": _match_sip,
    "rtsp": _match_rtsp,
    "ldap": _match_ldap,
    "cassandra": _match_cassandra,
    "elasticsearch": _match_elasticsearch,
    "amqp": _match_amqp,
    "docker_api": _match_docker_api,
    "kubernetes_api": _match_kubernetes_api,
    "socks": _match_socks,
    "bgp": _match_bgp,
    "pptp": _match_pptp,
    "unifiprotect": _match_unifiprotect,
}


def match_banner(service: str, payload: bytes) -> dict | None:
    """Identify a service from raw TCP payload bytes.

    Parameters
    ----------
    service:
        The service name hint (lowercase), typically derived from the
        destination port via :func:`~leetha.capture.banner.ports.service_for_port`.
    payload:
        Raw TCP payload bytes (up to 2048).

    Returns
    -------
    dict | None
        A dict with at least ``service`` and ``raw_banner`` keys on a
        successful match, or ``None`` if the payload is empty or the
        service is unknown.
    """
    if not payload:
        return None
    matcher = _MATCHERS.get(service.lower())
    if matcher is None:
        return None
    return matcher(payload)
