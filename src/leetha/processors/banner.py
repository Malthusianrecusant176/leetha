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

        return [Evidence(
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

    @staticmethod
    def _resolve_vendor(software: str | None) -> str | None:
        if not software:
            return None
        sw_lower = software.lower()
        for key, vendor_name in _SOFTWARE_VENDORS.items():
            if key in sw_lower:
                return vendor_name
        return software
