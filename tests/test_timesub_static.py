"""Target-grounded controls for the static Time Sub helper packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import timesub_static as ts
from elf_index import sections


class TimeSubEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ts.TARGET.is_file() or ts.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = ts.inspect(ts.TARGET)
        cls.data = ts.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va < s['address'] + s['size']]
        self.assertEqual(len(matches), 1)
        s = matches[0]
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_retained_record_matches_authenticated_target(self):
        record = ts.ROOT / 'research/work-items/RE-001-timesub-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        helper = self.result['helper']
        self.assertEqual(helper['start_va'], '0x1447130')
        self.assertEqual(helper['end_va_exclusive'], '0x14472a0')
        self.assertEqual(helper['bytes'], 368)
        self.assertEqual(helper['sha256'],
                         '53e1c201b2220f438c5d55b5885a92b487df8f40c7ee4cf180f584de62d50cc8')

    def test_magic_division_identity(self):
        # The decoded sequence computes trunc(n / 1000) for signed 32-bit n:
        # q = ((n * 0x10624dd3) >>a 38) + (1 if n < 0 else 0).
        for n in list(range(-4004, 4005, 7)) + [-1, 1, -999, 999, -1000, 1000,
                                                -2**31, 2**31 - 1]:
            q = ((n * ts.MAGIC_DIVISOR) >> 38) + (1 if n < 0 else 0)
            expected = n // 1000 if n >= 0 else -((-n) // 1000)
            self.assertEqual(q, expected, msg=f'magic div mismatch for {n}')

    def test_borrow_adjust_and_overflow_model(self):
        # (rax, edx) -> f64 seconds, modelling the decoded instructions.
        def model(rax, edx):
            adjust = 1 if (rax < 0 and edx > 0) else 0
            secs = rax + adjust
            micros = secs * 1_000_000
            if not -(2**63) <= micros < 2**63:
                return 0.0
            term = edx - 1_000_000_000 if adjust else edx
            q = term // 1000 if term >= 0 else -((-term) // 1000)
            micros += q
            if not -(2**63) <= micros < 2**63:
                return 0.0
            return micros / 1e6
        self.assertEqual(model(0, 0), 0.0)
        self.assertEqual(model(1, 0), 1.0)
        self.assertEqual(model(2, 500_000_000), 2.5)
        self.assertEqual(model(-1, 500_000_000), -0.5)
        self.assertEqual(model(2**40, 0), float(2**40))
        # Oversized seconds saturate through the imul overflow guard.
        self.assertEqual(model(2**62, 0), 0.0)

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                ts.inspect(path)
            path.write_bytes(self.mutated(ts.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                ts.inspect(path)

    def test_body_and_fde_mutations_rejected(self):
        for va in (ts.START, ts.START + 0x1b, ts.START + 0x34, ts.START + 0x5c, ts.START + 0x159):
            with self.assertRaisesRegex(ValueError, 'Helper body bytes changed'):
                ts.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Helper FDE record changed'):
            ts.analyze(self.mutated(ts.FDE_VA + 8, b'\x99\x99\x99\x99'))

    def test_branch_displacement_mutations_rejected(self):
        # The body identity gate fires for any body mutation; mutate the
        # retained constants and GOT relocations to reach the deeper checks.
        with self.assertRaisesRegex(ValueError, '1e6 divisor constant changed'):
            ts.analyze(self.mutated(ts.ONE_E6_VA, struct.pack('<d', 2e6)))
        with self.assertRaisesRegex(ValueError, '"Time Sub" format anchor changed'):
            ts.analyze(self.mutated(ts.TIMESUB_STR_VA + 2, b'X'))
        with self.assertRaisesRegex(ValueError, 'Panic-state global initial value changed'):
            ts.analyze(self.mutated(ts.PANIC_STATE_VA, struct.pack('<I', 4)))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in (ts.GOT_INNER, ts.GOT_FMT, ts.GOT_DEALLOC,
                                         ts.GOT_PANICPATH, ts.GOT_SELF):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 5)
        messages = {ts.GOT_INNER: 'Inner callee GOT slot changed',
                    ts.GOT_FMT: 'Format callee GOT slot changed',
                    ts.GOT_DEALLOC: 'Dealloc callee GOT slot changed',
                    ts.GOT_PANICPATH: 'Panic-path callee GOT slot changed',
                    ts.GOT_SELF: 'Helper self GOT slot changed'}
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, messages[va]):
                ts.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 8)))

    def test_call_census_counts(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_e8'], 0)
        self.assertEqual(census['lea_references'], 0)
        self.assertEqual(census['got_indirect_sites'], 72)
        self.assertEqual(census['distinct_caller_functions'], 60)


if __name__ == '__main__':
    unittest.main()
