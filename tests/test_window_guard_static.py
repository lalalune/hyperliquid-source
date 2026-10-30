"""Target-grounded controls for the static window-guard packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import window_guard_static as wg
from elf_index import sections


class WindowGuardEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not wg.TARGET.is_file() or wg.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = wg.inspect(wg.TARGET)
        cls.data = wg.TARGET.read_bytes()
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
        record = wg.ROOT / 'research/work-items/RE-001-ema-window-guard-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        guard = self.result['guard']
        self.assertEqual(guard['start_va'], '0x474fb90')
        self.assertEqual(guard['end_va_exclusive'], '0x474fce5')
        self.assertEqual(guard['bytes'], 341)
        self.assertEqual(guard['sha256'],
                         '2b098dfa6d806c619401899dd89d9a71750a99f639e5008b4ff80e490d81a4ba')

    def test_chrono_panic_anchor(self):
        panic = self.result['chrono_anchors']['panic']
        self.assertEqual(panic['message'], '`NaiveDateTime + TimeDelta` overflowed')
        self.assertEqual(panic['line'], 1631)
        self.assertEqual(panic['column'], 38)
        self.assertTrue(panic['path'].endswith('chrono-0.4.38/src/naive/datetime/mod.rs'))

    def test_day_division_identity(self):
        # The decoded sequence computes trunc(n / 86400) for non-negative
        # range-checked results of the first chrono callee.
        for n in (0, 1, 30, 599, 3600, 86399, 86400, 86401, 172800, 10**9):
            high = (n * wg.DAY_MAGIC) >> 64
            self.assertEqual(high >> 13, n // wg.SECS_PER_DAY, msg=f'failed for {n}')

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                wg.inspect(path)
            path.write_bytes(self.mutated(wg.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                wg.inspect(path)

    def test_body_and_fde_mutations_rejected(self):
        for va in (wg.START, wg.START + 0x70, wg.START + 0x9e, wg.START + 0x11c):
            with self.assertRaisesRegex(ValueError, 'Window-guard body bytes changed'):
                wg.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Window-guard FDE record changed'):
            wg.analyze(self.mutated(wg.FDE_VA + 8, b'\x22\x22\x22\x22'))

    def test_panic_anchor_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Panic message changed'):
            wg.analyze(self.mutated(wg.MSG_VA + 4, b'X'))
        with self.assertRaisesRegex(ValueError, 'Panic Location layout changed'):
            wg.analyze(self.mutated(wg.LOC_VA + 8, struct.pack('<I', 1632)))
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        path_va = None
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address == wg.LOC_VA:
                path_va = addend
        self.assertIsNotNone(path_va)
        with self.assertRaisesRegex(ValueError, 'chrono datetime path changed'):
            wg.analyze(self.mutated(path_va + 40, b'X'))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in (wg.GOT_PANIC, wg.GOT_CALLEE1,
                                         wg.GOT_CALLEE2, wg.GOT_UPDATE):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 4)
        messages = {wg.GOT_PANIC: 'Panic callee GOT slot changed',
                    wg.GOT_CALLEE1: 'callee1 GOT slot changed',
                    wg.GOT_CALLEE2: 'callee2 GOT slot changed',
                    wg.GOT_UPDATE: 'update GOT slot changed'}
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, messages[va]):
                wg.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 8)))

    def test_call_census(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_e8'], ['0x4899415', '0x4899910'])
        self.assertEqual(census['lea_references'], 0)
        self.assertEqual(census['containing_function'], {'start': '0x4898810', 'end': '0x489a550'})


if __name__ == '__main__':
    unittest.main()
