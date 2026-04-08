"""Prometheus metrics for Leetha."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, CollectorRegistry, generate_latest

# Custom registry avoids default Python process metrics.
REGISTRY = CollectorRegistry()

DEVICES_TOTAL = Gauge(
    "leetha_devices_total",
    "Total discovered devices",
    registry=REGISTRY,
)
DEVICES_ONLINE = Gauge(
    "leetha_devices_online",
    "Devices seen in last 5 minutes",
    registry=REGISTRY,
)
ALERTS_ACTIVE = Gauge(
    "leetha_alerts_active",
    "Unresolved findings count",
    registry=REGISTRY,
)
ALERTS_TOTAL = Counter(
    "leetha_alerts_total",
    "Findings by rule and severity",
    ["rule", "severity"],
    registry=REGISTRY,
)
PACKETS_TOTAL = Gauge(
    "leetha_packets_total",
    "Packets processed",
    registry=REGISTRY,
)
CAPTURE_INTERFACES = Gauge(
    "leetha_capture_interfaces",
    "Active capture interfaces",
    registry=REGISTRY,
)


async def update_metrics(
    device_count: int,
    online_count: int,
    alert_count: int,
    capture_count: int,
    packet_count: int,
) -> None:
    """Update all gauge values from current app state."""
    DEVICES_TOTAL.set(device_count)
    DEVICES_ONLINE.set(online_count)
    ALERTS_ACTIVE.set(alert_count)
    CAPTURE_INTERFACES.set(capture_count)
    PACKETS_TOTAL.set(packet_count)


def render_metrics() -> bytes:
    """Return Prometheus text exposition format."""
    return generate_latest(REGISTRY)


def record_finding(rule: str, severity: str) -> None:
    """Increment the finding counter for a specific rule and severity."""
    ALERTS_TOTAL.labels(rule=rule, severity=severity).inc()
