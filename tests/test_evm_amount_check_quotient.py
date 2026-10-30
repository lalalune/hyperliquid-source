"""Missing divide call must fail closed in evm_amount check_quotient_reads().

check_quotient_reads() locates the divide call through a bare ``next()``,
so a listing without CALL_DIV escapes the module's EvidenceError contract
(every other failure in the function goes through ``checked()``) as a
bare StopIteration. Route the lookup through ``next(..., None)`` plus an
EvidenceError, matching the exponent_source fix and ``find()``'s message.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import evm_amount_scale as eas


def listing_with_reads():
    rows = [(eas.CALL_DIV, 'call', (('t', 'div_helper'),), eas.CALL_DIV + 4)]
    for i, off in enumerate((0, 8, 16, 24)):
        va = eas.CALL_DIV + 4 + 4 * i
        rows.append((va, 'mov', (('r', 0, 8), ('m', 8, eas.RBX, None, 1, off)),
                     va + 4))
    return rows


class CheckQuotientReadsTests(unittest.TestCase):
    def test_missing_divide_call_fails_closed(self):
        with self.assertRaises(eas.EvidenceError):
            eas.check_quotient_reads([])

    def test_four_rbx_reads_accepted(self):
        rows = listing_with_reads()
        self.assertEqual(eas.check_quotient_reads(rows),
                         [r[0] for r in rows[1:]])

    def test_wrong_read_count_still_fails_closed(self):
        with self.assertRaisesRegex(eas.EvidenceError, 'unexpected reads'):
            eas.check_quotient_reads(listing_with_reads()[:4])


if __name__ == '__main__':
    unittest.main()
