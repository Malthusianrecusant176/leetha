"""Tests for Prometheus metrics."""


async def test_metrics_update():
    """update_metrics populates gauges without error."""
    from leetha.metrics import update_metrics, DEVICES_TOTAL, DEVICES_ONLINE
    await update_metrics(device_count=5, online_count=3, alert_count=1,
                         capture_count=2, packet_count=100)
    assert DEVICES_TOTAL._value.get() == 5
    assert DEVICES_ONLINE._value.get() == 3


def test_metrics_render():
    """render_metrics produces Prometheus text format."""
    from leetha.metrics import render_metrics
    output = render_metrics().decode("utf-8")
    assert "leetha_devices_total" in output


def test_record_finding():
    """record_finding increments counter."""
    from leetha.metrics import record_finding, ALERTS_TOTAL
    record_finding("new_host", "warning")
    # Should not raise; counter incremented
    val = ALERTS_TOTAL.labels(rule="new_host", severity="warning")._value.get()
    assert val >= 1
