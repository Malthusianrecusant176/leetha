"""Hadoop HDFS NameNode probe plugin — HTTP GET /jmx, detects Hadoop JMX beans."""
from __future__ import annotations

import json
import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HadoopNameNodeProbePlugin(ServiceProbe):
    name = "hadoop_namenode"
    protocol = "tcp"
    default_ports = [9870, 50070]

    _HADOOP_BEAN_RE = re.compile(r"Hadoop:service=NameNode", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                f"GET /jmx HTTP/1.0\r\n"
                f"Host: {conn.host}:{conn.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            conn.write(request.encode())
            data = conn.read(16384)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            body_start = response.find("\r\n\r\n")
            if body_start < 0:
                return None
            body = response[body_start + 4:].strip()
            if not body:
                return None

            try:
                info = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(info, dict) or "beans" not in info:
                return None

            beans = info["beans"]
            if not isinstance(beans, list):
                return None

            # Look for Hadoop-specific JMX bean names
            hadoop_found = False
            metadata: dict = {}
            version = None

            for bean in beans:
                if not isinstance(bean, dict):
                    continue
                name = bean.get("name", "")
                if self._HADOOP_BEAN_RE.search(name):
                    hadoop_found = True
                if "tag.Version" in bean:
                    version = bean["tag.Version"]
                elif "Version" in bean and "Hadoop" in str(bean.get("name", "")):
                    version = bean["Version"]
                if "ClusterId" in bean:
                    metadata["cluster_id"] = bean["ClusterId"]
                if "BlockPoolId" in bean:
                    metadata["block_pool_id"] = bean["BlockPoolId"]

            if not hadoop_found:
                return None

            metadata["bean_count"] = len(beans)

            return ServiceIdentity(
                service="hadoop_namenode",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
