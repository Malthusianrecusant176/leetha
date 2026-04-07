"""Banner processor — converts passive service banners into Evidence."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


_SERVICE_CATEGORIES: dict[str, str] = {
    "ssh": "server", "ftp": "server", "smtp": "server",
    "imap": "server", "pop3": "server",
    "mysql": "server", "postgresql": "server", "mssql": "server",
    "mongodb": "server", "redis": "server", "irc": "server",
    "ipp": "printer", "jetdirect": "printer", "lpd": "printer",
    "mqtt": "server", "amqp": "server",
    "sip": "server",
    "rtsp": "ip_camera",
    "unifiprotect": "ip_camera",
    "ldap": "server",
    "cassandra": "server", "elasticsearch": "server",
    "docker_api": "server", "kubernetes_api": "server",
    "socks": "server",
    "bgp": "router",
    "pptp": "server",
}

_SERVICE_PLATFORMS: dict[str, str] = {
    "rdp": "Windows",
    "mssql": "Windows",
}

_SOFTWARE_VENDORS: dict[str, str] = {
    "openssh": "OpenSSH",
    "dropbear": "Dropbear",
    "proftpd": "ProFTPD",
    "vsftpd": "vsFTPd",
    "postfix": "Postfix",
    "exim": "Exim",
    "dovecot": "Dovecot",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "microsoft sql server": "Microsoft",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "elasticsearch": "Elastic",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "rabbitmq": "RabbitMQ",
    "unifi protect": "Ubiquiti",
    "ubiquiti": "Ubiquiti",
}

_SSH_OS_HINTS: dict[str, str] = {
    "ubuntu": "Linux",
    "debian": "Linux",
    "freebsd": "FreeBSD",
}


@register_processor("service_banner")
class BannerProcessor(Processor):
    """Converts passive service banner captures into fingerprint evidence."""

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        service = packet.get("service")
        if not service:
            return []

        software = packet.get("software", "")
        version = packet.get("version")
        server_port = packet.get("server_port")

        category = _SERVICE_CATEGORIES.get(service)
        platform = _SERVICE_PLATFORMS.get(service)
        vendor = self._resolve_vendor(software)
        platform_version = version

        # SSH OS hints from the software string
        if service == "ssh" and software:
            sw_lower = software.lower()
            for hint, os_name in _SSH_OS_HINTS.items():
                if hint in sw_lower:
                    platform = os_name
                    break

        evidence = [Evidence(
            source="passive_banner",
            method="pattern",
            certainty=0.85,
            category=category,
            vendor=vendor,
            platform=platform,
            platform_version=platform_version,
            raw={
                "service": service,
                "software": software,
                "version": version,
                "server_port": server_port,
            },
        )]

        # OT device identity extraction from banner content
        banner_text = packet.get("banner", "") or ""
        if banner_text:
            ot_evidence = self._extract_ot_identity(banner_text)
            if ot_evidence:
                evidence.extend(ot_evidence)

        return evidence

    def _extract_ot_identity(self, banner: str) -> list[Evidence]:
        """Extract OT device identity from service banner content."""
        import re
        results = []

        # SEL relay banners (Telnet/SSH): "SEL-351-7 FID=SEL-351-7-R107-V0-Z002002-D20130514"
        sel_match = re.search(r'(SEL-\d{3,4}[A-Z]?)', banner, re.IGNORECASE)
        if sel_match:
            model = sel_match.group(1).upper()
            fid_match = re.search(r'FID=([\w-]+)', banner)
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.90,
                vendor="SEL", model=model, category="ics_device",
                raw={"banner": banner[:200], "fid": fid_match.group(1) if fid_match else None},
            ))

        # GE Multilin banners: "GE Multilin T60" or "UR-series"
        ge_match = re.search(r'(?:GE\s+)?Multilin\s+([A-Z]\d{2,3})', banner, re.IGNORECASE)
        if ge_match:
            model = f"GE Multilin {ge_match.group(1).upper()}"
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.90,
                vendor="GE", model=model, category="ics_device",
                raw={"banner": banner[:200]},
            ))

        # Schneider Modicon: "BMX P34 2020" or "Modicon M340"
        schneider_match = re.search(r'(?:BMX\s*[A-Z]\d{2}\s*\d{4}|Modicon\s+[A-Z]\d{3,4})', banner, re.IGNORECASE)
        if schneider_match:
            model = schneider_match.group(0)
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Schneider Electric", model=model, category="plc",
                raw={"banner": banner[:200]},
            ))

        # Siemens PLC: "S7-300" or "SIMATIC S7-1200" or "6ES7"
        siemens_match = re.search(r'(?:SIMATIC\s+)?S7-(\d{3,4})', banner, re.IGNORECASE)
        if not siemens_match:
            siemens_match = re.search(r'6ES7\s*\d{3}', banner)
        if siemens_match:
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Siemens", model=siemens_match.group(0), category="plc",
                raw={"banner": banner[:200]},
            ))

        # Woodward controller: "easYgen" or "2301" or "MicroNet"
        woodward_match = re.search(r'(?:easYgen|MicroNet|Woodward.*(?:2301|DECS|ProTech))', banner, re.IGNORECASE)
        if woodward_match:
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Woodward", model=woodward_match.group(0), category="ics_device",
                raw={"banner": banner[:200]},
            ))

        # Firmware version extraction: "FW:" or "Firmware:" or "Version:" followed by digits
        fw_match = re.search(r'(?:FW|Firmware|Version|Rev)[:\s]+([0-9]+(?:\.[0-9]+)+)', banner, re.IGNORECASE)
        if fw_match and results:
            results[0].platform_version = fw_match.group(1)

        return results

    @staticmethod
    def _resolve_vendor(software: str | None) -> str | None:
        if not software:
            return None
        sw_lower = software.lower()
        for key, vendor_name in _SOFTWARE_VENDORS.items():
            if key in sw_lower:
                return vendor_name
        return software
