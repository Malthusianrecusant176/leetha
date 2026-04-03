"""Tests for the lightweight TCP connection table."""

import time

from leetha.capture.banner.connections import ConnectionTable, ConnState


def test_register_syn_creates_syn_seen_entry():
    table = ConnectionTable()
    entry = table.register_syn("10.0.0.1", 12345, "10.0.0.2", 80)
    assert entry.state is ConnState.SYN_SEEN
    assert entry.server_port == 80


def test_mark_captured_changes_state():
    table = ConnectionTable()
    table.register_syn("10.0.0.1", 12345, "10.0.0.2", 80)
    table.mark_captured("10.0.0.1", 12345, "10.0.0.2", 80)
    entry = table.lookup("10.0.0.1", 12345, "10.0.0.2", 80)
    assert entry is not None
    assert entry.state is ConnState.BANNER_CAPTURED


def test_is_captured_true_after_mark():
    table = ConnectionTable()
    table.register_syn("10.0.0.1", 12345, "10.0.0.2", 80)
    table.mark_captured("10.0.0.1", 12345, "10.0.0.2", 80)
    assert table.is_captured("10.0.0.1", 12345, "10.0.0.2", 80) is True


def test_is_captured_false_before_mark():
    table = ConnectionTable()
    table.register_syn("10.0.0.1", 12345, "10.0.0.2", 80)
    assert table.is_captured("10.0.0.1", 12345, "10.0.0.2", 80) is False


def test_is_captured_false_for_unknown():
    table = ConnectionTable()
    assert table.is_captured("10.0.0.1", 12345, "10.0.0.2", 80) is False


def test_mark_closed_changes_state():
    table = ConnectionTable()
    table.register_syn("10.0.0.1", 12345, "10.0.0.2", 22)
    table.mark_closed("10.0.0.1", 12345, "10.0.0.2", 22)
    entry = table.lookup("10.0.0.1", 12345, "10.0.0.2", 22)
    assert entry is not None
    assert entry.state is ConnState.CLOSED


def test_sweep_removes_expired_entries():
    table = ConnectionTable(ttl_seconds=0.01)
    table.register_syn("10.0.0.1", 12345, "10.0.0.2", 80)
    time.sleep(0.02)
    removed = table.sweep()
    assert removed == 1
    assert len(table) == 0


def test_sweep_removes_closed_entries():
    table = ConnectionTable()
    table.register_syn("10.0.0.1", 12345, "10.0.0.2", 80)
    table.mark_closed("10.0.0.1", 12345, "10.0.0.2", 80)
    removed = table.sweep()
    assert removed == 1
    assert len(table) == 0


def test_fifo_eviction_when_full():
    table = ConnectionTable(max_entries=3)
    table.register_syn("10.0.0.1", 1, "10.0.0.2", 80)
    table.register_syn("10.0.0.1", 2, "10.0.0.2", 80)
    table.register_syn("10.0.0.1", 3, "10.0.0.2", 80)
    # Adding a 4th should evict the oldest (port 1).
    table.register_syn("10.0.0.1", 4, "10.0.0.2", 80)
    assert len(table) == 3
    assert table.lookup("10.0.0.1", 1, "10.0.0.2", 80) is None
    assert table.lookup("10.0.0.1", 4, "10.0.0.2", 80) is not None


def test_record_client_data_increments_bytes():
    table = ConnectionTable()
    table.register_syn("10.0.0.1", 12345, "10.0.0.2", 80)
    table.record_client_data("10.0.0.1", 12345, "10.0.0.2", 80, 100)
    table.record_client_data("10.0.0.1", 12345, "10.0.0.2", 80, 50)
    entry = table.lookup("10.0.0.1", 12345, "10.0.0.2", 80)
    assert entry is not None
    assert entry.client_bytes == 150


def test_len_tracks_entries():
    table = ConnectionTable()
    assert len(table) == 0
    table.register_syn("10.0.0.1", 1, "10.0.0.2", 80)
    assert len(table) == 1
    table.register_syn("10.0.0.1", 2, "10.0.0.2", 80)
    assert len(table) == 2
