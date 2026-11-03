#!/usr/bin/env python3
"""Exercise the committed node #115 .eh_frame CIE census checker.

The checker at tools/foundation_ehframe_cie_census.py reads
artifacts/node/115/hl-node in place and compares its own derived CIE and FDE
census with research/work-items/RE-001-node115-ehframe-cie-census/evidence.json.
This test imports that actual checker and runs it; it does not reimplement the
parse and it never executes or copies the target.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / 'tools' / 'foundation_ehframe_cie_census.py'
EVIDENCE = (ROOT / 'research' / 'work-items'
            / 'RE-001-node115-ehframe-cie-census' / 'evidence.json')


def load_checker():
    spec = importlib.util.spec_from_file_location(
        'foundation_ehframe_cie_census_checker', CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError('cannot load checker %s' % CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CensusCheckerTest(unittest.TestCase):
    def setUp(self):
        self.module = load_checker()
        self.assertEqual(self.module.EVIDENCE, EVIDENCE)

    def test_saved_packet_matches_the_pinned_target(self):
        recorded = json.loads(EVIDENCE.read_text(encoding='utf-8'))
        self.assertEqual(recorded['target_sha256'], self.module.TARGET_SHA256)
        self.assertEqual(recorded['target_size'], self.module.TARGET_SIZE)
        self.assertEqual(self.module.main([]), 0)

    def test_tampered_recorded_extent_is_rejected(self):
        recorded = json.loads(EVIDENCE.read_text(encoding='utf-8'))
        recorded['fde_census']['extent_bytes_total'] += 1
        with tempfile.TemporaryDirectory() as directory:
            tampered = Path(directory) / 'evidence.json'
            tampered.write_text(json.dumps(recorded), encoding='utf-8')
            self.module.EVIDENCE = tampered
            try:
                with self.assertRaises(self.module.CheckError):
                    self.module.main([])
            finally:
                self.module.EVIDENCE = EVIDENCE

    def test_authentication_rejects_a_different_target_identity(self):
        with self.assertRaises(self.module.CheckError):
            self.module.authenticate(self.module.TARGET_SIZE, '0' * 64)
        with self.assertRaises(self.module.CheckError):
            self.module.authenticate(self.module.TARGET_SIZE + 1,
                                     self.module.TARGET_SHA256)


if __name__ == '__main__':
    unittest.main()
