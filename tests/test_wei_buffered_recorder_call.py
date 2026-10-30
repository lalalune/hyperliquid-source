"""Controls for the wei_buffered_cap recorder-call lookup (RE-004).

analyse() previously located the recorder call through a bare next(), so a
listing whose tail pattern matched but which carried no recorder call after
the ok store escaped main()'s EvidenceError-only handler as StopIteration.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'wei_buffered_cap.py'

spec = importlib.util.spec_from_file_location('wei_buffered_cap', TOOL)
wbc = importlib.util.module_from_spec(spec)
sys.modules['wei_buffered_cap'] = wbc
spec.loader.exec_module(wbc)

OK_STORE = 0x1000
GOT_SLOT = 0x5000
OTHER_SLOT = 0x6000


def call(va, slot):
    return (va, 'call', (('a', 8, slot),), 'call QWORD PTR [rip+0x0]')


def listing():
    return [
        (0x900, 'mov', (('r', 0, 8, 'rax'),), 'mov rax,rcx'),
        (0x1000, 'mov', (), 'mov WORD PTR [rdi],0x186'),
        (0x1010, 'call', (('a', 8, OTHER_SLOT),), 'call QWORD PTR [rip+0x0]'),
        (0x1020, 'call', (('a', 8, GOT_SLOT),), 'call QWORD PTR [rip+0x0]'),
    ]


class RecorderCallTests(unittest.TestCase):
    def test_returns_recorder_call_after_ok_store(self):
        relocs = {GOT_SLOT: wbc.RECORDER_TARGET, OTHER_SLOT: 0x1111}
        found = wbc.find_recorder_call(listing(), OK_STORE, relocs)
        self.assertEqual(found[0], 0x1020)

    def test_missing_recorder_call_raises_evidence_error(self):
        relocs = {OTHER_SLOT: 0x1111}
        with self.assertRaises(wbc.EvidenceError):
            wbc.find_recorder_call(listing(), OK_STORE, relocs)

    def test_call_at_or_before_ok_store_is_ignored(self):
        insns = [call(0x1000, GOT_SLOT), call(0x900, GOT_SLOT)]
        relocs = {GOT_SLOT: wbc.RECORDER_TARGET}
        with self.assertRaises(wbc.EvidenceError):
            wbc.find_recorder_call(insns, OK_STORE, relocs)

    def test_empty_listing_raises_evidence_error(self):
        with self.assertRaises(wbc.EvidenceError):
            wbc.find_recorder_call([], OK_STORE, {})

    def test_non_call_and_wrong_operand_are_ignored(self):
        insns = [
            (0x1020, 'jmp', (('a', 8, GOT_SLOT),), 'jmp QWORD PTR [rip+0x0]'),
            (0x1030, 'call', (('t', 0x2000),), 'call 0x2000'),
        ]
        relocs = {GOT_SLOT: wbc.RECORDER_TARGET}
        with self.assertRaises(wbc.EvidenceError):
            wbc.find_recorder_call(insns, OK_STORE, relocs)


if __name__ == '__main__':
    unittest.main()
