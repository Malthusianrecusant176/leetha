from leetha.capture.banner.connections import ConnectionTable, ConnState


class TestBannerDedup:
    def test_first_banner_not_suppressed(self):
        table = ConnectionTable()
        table.register_syn("10.0.0.2", 54321, "10.0.0.1", 22)
        assert not table.is_captured("10.0.0.2", 54321, "10.0.0.1", 22)

    def test_second_banner_suppressed_after_mark(self):
        table = ConnectionTable()
        table.register_syn("10.0.0.2", 54321, "10.0.0.1", 22)
        table.mark_captured("10.0.0.2", 54321, "10.0.0.1", 22)
        assert table.is_captured("10.0.0.2", 54321, "10.0.0.1", 22)

    def test_different_connections_independent(self):
        table = ConnectionTable()
        table.register_syn("10.0.0.2", 54321, "10.0.0.1", 22)
        table.mark_captured("10.0.0.2", 54321, "10.0.0.1", 22)
        # Different connection to same server
        table.register_syn("10.0.0.3", 54322, "10.0.0.1", 22)
        assert not table.is_captured("10.0.0.3", 54322, "10.0.0.1", 22)

    def test_sweep_clears_closed(self):
        table = ConnectionTable()
        table.register_syn("10.0.0.2", 54321, "10.0.0.1", 22)
        table.mark_closed("10.0.0.2", 54321, "10.0.0.1", 22)
        removed = table.sweep()
        assert removed == 1


class TestBannerSeenDedup:
    def test_set_dedup_pattern(self):
        """Simulate the _banner_seen dedup pattern from engine._ingest."""
        seen = set()
        # First banner from server aa:bb on port 22
        key1 = ("aa:bb:cc:dd:ee:ff", 22)
        assert key1 not in seen
        seen.add(key1)
        # Second banner from same server+port should be suppressed
        assert key1 in seen
        # Different port on same server is independent
        key2 = ("aa:bb:cc:dd:ee:ff", 3306)
        assert key2 not in seen
