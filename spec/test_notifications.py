"""Tests for notification dispatcher."""
import types
import pytest
from leetha.store.models import Finding, FindingRule, AlertSeverity


@pytest.fixture
def finding():
    return Finding(
        hw_addr="aa:bb:cc:dd:ee:ff",
        rule=FindingRule.NEW_HOST,
        severity=AlertSeverity.WARNING,
        message="New device detected on network",
    )


def _make_fake_apprise():
    """Create a tracker that records async_notify calls."""
    calls = []
    async def fake_notify(**kwargs):
        calls.append(kwargs)
    fake = types.SimpleNamespace(async_notify=fake_notify)
    return fake, calls


async def test_notify_skips_below_min_severity(finding):
    """Notifications below min severity are silently skipped."""
    from leetha.notifications import NotificationDispatcher
    d = NotificationDispatcher(urls=["json://localhost"], min_severity="high")
    fake, calls = _make_fake_apprise()
    d._apprise = fake
    await d.send(finding)
    assert len(calls) == 0


async def test_notify_sends_above_min_severity(finding):
    """Findings at or above min severity trigger notification."""
    from leetha.notifications import NotificationDispatcher
    d = NotificationDispatcher(urls=["json://localhost"], min_severity="warning")
    fake, calls = _make_fake_apprise()
    d._apprise = fake
    await d.send(finding)
    assert len(calls) == 1


async def test_notify_skips_when_no_urls():
    """No URLs configured = no notification, no error."""
    from leetha.notifications import NotificationDispatcher
    d = NotificationDispatcher(urls=[], min_severity="info")
    finding = Finding(
        hw_addr="aa:bb:cc:dd:ee:ff",
        rule=FindingRule.NEW_HOST,
        severity=AlertSeverity.CRITICAL,
        message="test",
    )
    await d.send(finding)


async def test_notify_rate_limits(finding):
    """Same rule+MAC within cooldown window is suppressed."""
    from leetha.notifications import NotificationDispatcher
    d = NotificationDispatcher(urls=["json://localhost"], min_severity="info")
    fake, calls = _make_fake_apprise()
    d._apprise = fake
    await d.send(finding)
    await d.send(finding)  # duplicate within cooldown
    assert len(calls) == 1


async def test_format_message(finding):
    """Message includes severity, rule, MAC, and message."""
    from leetha.notifications import NotificationDispatcher
    d = NotificationDispatcher(urls=[], min_severity="info")
    title, body = d.format(finding)
    assert "WARNING" in title
    assert "aa:bb:cc:dd:ee:ff" in body
    assert "new_host" in body
