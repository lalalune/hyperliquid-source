"""Missing call site must fail closed in evm_amount_scale.exponent_source().

exponent_source() locates its call site through a bare ``next()``, so a
listing without that site escapes the module's EvidenceError contract
(the same contract its own ``find()`` helper and its trailing
``raise EvidenceError('no esi source ...')`` enforce) as a bare
StopIteration. Route the lookup through ``next(..., None)`` plus an
EvidenceError, mirroring the find_tail anchor fixes.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import evm_amount_scale as eas

SITE = 0x110
RSI = 6


class ExponentSourceTests(unittest.TestCase):
    def test_missing_site_fails_closed(self):
        with self.assertRaises(eas.EvidenceError):
            eas.exponent_source([], SITE)

    def test_immediate_source_found(self):
        insns = [(0x100, 'mov', (('r', RSI, 4), ('i', 42)), SITE),
                 (SITE, 'call', (('t', 'helper'),), None)]
        self.assertEqual(eas.exponent_source(insns, SITE),
                         {'form': 'immediate', 'value': 42, 'set_at': 0x100})

    def test_present_site_without_source_still_fails_closed(self):
        insns = [(0x100, 'nop', (), SITE),
                 (SITE, 'call', (('t', 'helper'),), None)]
        with self.assertRaisesRegex(eas.EvidenceError, 'no esi source'):
            eas.exponent_source(insns, SITE)


if __name__ == '__main__':
    unittest.main()
