from datetime import datetime, timedelta
from leetha.evidence.engine import cap_evidence
from leetha.evidence.models import Evidence


class TestEvidenceCap:
    def test_keeps_highest_certainty_per_source(self):
        old = datetime.now() - timedelta(hours=2)
        new = datetime.now()
        evidence = [
            Evidence(source="dhcpv4", method="exact", certainty=0.6, vendor="Low", observed_at=new),
            Evidence(source="dhcpv4", method="exact", certainty=0.9, vendor="High", observed_at=old),
            Evidence(source="arp", method="heuristic", certainty=0.3, observed_at=new),
        ]
        capped = cap_evidence(evidence, max_per_source=1)
        assert len(capped) == 2
        dhcp_ev = [e for e in capped if e.source == "dhcpv4"]
        assert len(dhcp_ev) == 1
        assert dhcp_ev[0].vendor == "High"

    def test_small_list_unchanged(self):
        evidence = [
            Evidence(source="dhcpv4", method="exact", certainty=0.8),
            Evidence(source="arp", method="heuristic", certainty=0.3),
        ]
        capped = cap_evidence(evidence, max_per_source=10)
        assert len(capped) == 2

    def test_empty_returns_empty(self):
        assert cap_evidence([]) == []

    def test_respects_max_total(self):
        evidence = [
            Evidence(source=f"src_{i}", method="exact", certainty=0.5)
            for i in range(300)
        ]
        capped = cap_evidence(evidence, max_per_source=5, max_total=200)
        assert len(capped) <= 200

    def test_compute_caps_evidence_chain(self):
        from leetha.evidence.engine import VerdictEngine
        engine = VerdictEngine()
        evidence = [
            Evidence(source="dhcpv4", method="exact", certainty=0.85, vendor=f"v{i}",
                     observed_at=datetime.now() - timedelta(minutes=i))
            for i in range(50)
        ]
        verdict = engine.compute("aa:bb:cc:dd:ee:ff", evidence)
        assert len(verdict.evidence_chain) <= 200
