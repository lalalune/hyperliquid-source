"""Target-grounded controls for the static read-lock helper packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import readlock_static as rl
from elf_index import sections


class ReadLockEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not rl.TARGET.is_file() or rl.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = rl.inspect(rl.TARGET)
        cls.data = rl.TARGET.read_bytes()
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
        record = rl.ROOT / 'research/work-items/readlock-helper-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        helper = self.result['helper']
        self.assertEqual(helper['start_va'], '0x358dcd0')
        self.assertEqual(helper['end_va_exclusive'], '0x358de41')
        self.assertEqual(helper['bytes'], 369)
        self.assertEqual(helper['sha256'],
                         'bd32c3cf61058a8a518f39ace487602c06da8ef64410fb5b67cd3d99dbef8e20')

    def test_dependency_anchors(self):
        anchors = self.result['dependency_anchors']
        self.assertEqual(anchors['std_once']['rustc_commit'],
                         'e408947bfd200af42db322daf0fadfe7e26d3bd1')
        self.assertEqual((anchors['std_once']['line'], anchors['std_once']['column']), (219, 20))
        self.assertEqual(anchors['parking_lot']['crate'], 'parking_lot-0.12.3')
        self.assertEqual((anchors['parking_lot']['line'], anchors['parking_lot']['column']),
                         (1145, 45))

    def test_census_counts(self):
        census = self.result['call_census']
        self.assertEqual(census['sites'], 952)
        self.assertEqual(census['distinct_functions'], 358)

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                rl.inspect(path)
            path.write_bytes(self.mutated(rl.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                rl.inspect(path)

    def test_body_and_fde_mutations_rejected(self):
        for va in (rl.START, rl.START + 0x30, rl.START + 0x100):
            with self.assertRaisesRegex(ValueError, 'Read-lock body bytes changed'):
                rl.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Read-lock FDE record changed'):
            rl.analyze(self.mutated(rl.FDE_VA + 8, b'\x66\x66\x66\x66'))

    def test_anchor_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            rl.analyze(self.mutated(rl.ONCE_LOC + 16, struct.pack('<I', 220)))
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            rl.analyze(self.mutated(rl.RWLOC_LOC + 16, struct.pack('<I', 1146)))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        got_slots = {got: target for _, got, target in rl.GOT_SITES}
        found = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and (address in got_slots or address == rl.STRUCT_VA):
                found[address] = (rela['address'] + off, addend)
        self.assertEqual(len(found), len(got_slots) + 1)
        for va, (slot_va, addend) in found.items():
            message = ('Descriptor struct relocation changed' if va == rl.STRUCT_VA
                       else 'Call target changed')
            with self.assertRaisesRegex(ValueError, message):
                rl.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 8)))


if __name__ == '__main__':
    unittest.main()
