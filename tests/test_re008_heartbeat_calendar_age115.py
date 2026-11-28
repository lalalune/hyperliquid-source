import importlib.util
import json
from pathlib import Path
import unittest

PACKET = Path(__file__).resolve().parents[1] / "research/work-items/RE-008-node115-heartbeat-calendar-age"
spec = importlib.util.spec_from_file_location("heartbeat_calendar_age115", PACKET / "verify.py")
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class HeartbeatCalendarEvidenceTests(unittest.TestCase):
    def test_calendar_caller_and_known_source(self):
        if not subject.prior.TARGET.exists() or subject.prior.TARGET.stat().st_size != subject.prior.TARGET_SIZE:
            self.skipTest("materialized node115 required")
        saved = json.loads((PACKET / "results.json").read_text())
        self.assertEqual(subject.static_evidence(), saved["static"])

    def test_directed_leap_witnesses_are_exercised(self):
        day = subject.jan1(1970)
        rows = subject.cases()
        self.assertIn((day, 240, 0, day, 59, 1_500_000_000, 0), rows)
        self.assertIn((day, 59, 1_500_000_000, day - 1, 82_859, 1_000_000_017, 0), rows)
        self.assertIn((day, 239, 1, day, 59, 0, 0), rows)
