"""Test that DHCP anomaly callback uses the correct event loop."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from concurrent.futures import Future

from leetha.app import LeethaApp


def test_handle_dhcp_anomalies_uses_provided_loop():
    """_handle_dhcp_anomalies must use the loop passed to it, not get_event_loop()."""
    app = object.__new__(LeethaApp)
    app.store = MagicMock()
    app.store.findings = MagicMock()
    app.store.findings.add = AsyncMock()

    mock_loop = MagicMock()
    future = Future()
    future.set_result([{"src_mac": "aa:bb:cc:dd:ee:ff", "option": "53", "reason": "test"}])

    with patch("leetha.app.asyncio") as mock_asyncio:
        app._handle_dhcp_anomalies(future, mock_loop)
        mock_asyncio.run_coroutine_threadsafe.assert_called_once()
        args = mock_asyncio.run_coroutine_threadsafe.call_args[0]
        assert args[1] is mock_loop
        mock_asyncio.get_event_loop.assert_not_called()


def test_on_dhcp_packet_captures_running_loop():
    """_on_dhcp_packet must capture the running loop and pass it to the callback."""
    app = object.__new__(LeethaApp)
    app.config = MagicMock()
    app.config.data_dir = "/tmp"
    app._analysis_executor = MagicMock()

    mock_future = MagicMock()
    app._analysis_executor.submit.return_value = mock_future

    fake_packet = MagicMock()
    fake_packet.fields = {"raw_options": {"53": b"\x01"}}
    fake_packet.hw_addr = "aa:bb:cc:dd:ee:ff"
    fake_packet.ip_addr = "192.168.1.100"

    mock_loop = MagicMock()
    with patch("leetha.app.asyncio") as mock_asyncio:
        mock_asyncio.get_running_loop.return_value = mock_loop
        app._on_dhcp_packet(fake_packet)
        mock_asyncio.get_running_loop.assert_called_once()
        mock_future.add_done_callback.assert_called_once()
