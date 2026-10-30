"""find_tail() must fail closed with EvidenceError for missing anchors.

analyse() calls find_tail() on whatever listing a function range disassembles
to, with no prior anchor check, and main() catches EvidenceError (plus
Unmodelled) only — yet every anchor lookup in find_tail() was a bare next(),
so a listing without the cap-arithmetic pattern escaped as StopIteration
(or IndexError for a trailing error store with no join instruction).
Synthetic listings only — no captured binary is needed.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from wei_buffered_cap import EvidenceError, find_tail

LOAD = (0x1000, 'mov', (), 'mov    eax,DWORD PTR [rsp+0x14]')
CVT = (0x1004, 'cvtsi2sd', (), 'cvtsi2sd xmm0, eax')
MUL = (0x1008, 'mulsd', (('r', 0), ('a', 0)), 'mulsd xmm0, xmm1')
STAGE1 = (0x100c, 'mov', (), 'movq   xmm2,rcx')
STAGE2 = (0x1010, 'ucomisd', (), 'ucomisd xmm0, xmm1')
TAG = (0x1014, 'mov', (('r', 0), ('i', 0xb2)), 'mov eax, 0xb2')
OK = (0x1018, 'mov', (), 'mov    WORD PTR [rdi],0x186')
ERR = (0x101c, 'mov', (), 'mov    WORD PTR [rdi],0x13f')
JOIN = (0x1020, 'jmp', (('a', 0x2000),), 'jmp 0x2000')

FULL = [LOAD, CVT, MUL, STAGE1, STAGE2, TAG, OK, ERR, JOIN]


class FindTailAnchorTests(unittest.TestCase):
    def test_empty_listing_raises_evidence_error(self):
        with self.assertRaises(EvidenceError):
            find_tail([])

    def test_missing_ok_store_raises_evidence_error(self):
        with self.assertRaises(EvidenceError):
            find_tail([LOAD, CVT])

    def test_missing_mulsd_raises_evidence_error(self):
        with self.assertRaises(EvidenceError):
            find_tail([i for i in FULL if i is not MUL])

    def test_missing_tag_raises_evidence_error(self):
        with self.assertRaises(EvidenceError):
            find_tail([i for i in FULL if i is not TAG])

    def test_trailing_error_store_raises_evidence_error(self):
        with self.assertRaises(EvidenceError):
            find_tail(FULL[:-1])

    def test_full_listing_returns_anchors(self):
        self.assertEqual(find_tail(FULL), {
            'tail_start': 0x1000, 'cvt': 0x1004, 'join': 0x2000,
            'stage1_end': 0x100c, 'stage2': 0x1010, 'stage2_end': 0x1014,
            'ok_store': 0x1018, 'err_store': 0x101c, 'indices': (0, 7)})


if __name__ == '__main__':
    unittest.main()
