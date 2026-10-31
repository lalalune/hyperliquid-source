"""Target-grounded controls for the static vault-deposit-body packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import vault-deposit-body_static as tg
from elf_index import sections


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not tg.TARGET.is_file() or tg.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = tg.inspect(tg.TARGET)
        cls.data = tg.TARGET.read_bytes()
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
        record = tg.ROOT / 'research/work-items/RE-001-vault-deposit-body-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        body = self.result['body']
        self.assertEqual(body['start_va'], '0x3956320')
        self.assertEqual(body['bytes'], 6299)
        self.assertEqual(body['sha256'], tg.BODY_SHA256)
        self.assertEqual(len(tg.BODY), 6299)
        self.assertEqual(len(tg.BRANCHES), 195)
        self.assertEqual(len(tg.DIRECT_CALLS), 15)
        self.assertEqual(len(tg.INDIRECT_CALLS), 39)
        self.assertEqual(len(tg.LOCATIONS), 5)

    def test_branch_table_shape(self):
        for offset, pattern, rel_pos, insn_len, destination in tg.BRANCHES:
            raw = bytes.fromhex(pattern)
            self.assertEqual(len(raw), insn_len)
            self.assertTrue(0 <= offset < tg.END - tg.START - insn_len)
            self.assertTrue(tg.START <= destination < tg.END)

    def test_location_table_shape(self):
        seen = {(i['path'], i['line']) for i in self.result['locations']}
        expected = {(tg.LOCATIONS[i][2].decode().rsplit('src/', 1)[-1], tg.LOCATIONS[i][3])
                   for i in range(len(tg.LOCATIONS))}
        self.assertEqual(seen, expected)

    def test_identity_rejects_size_and_sha_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                tg.inspect(path)
            path.write_bytes(self.mutated(tg.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                tg.inspect(path)

    def test_body_and_fde_mutations_rejected(self):
        for va in (tg.START, tg.START + 0x40, tg.START + (tg.END - tg.START) // 2,
                   tg.END - 8):
            with self.assertRaisesRegex(ValueError, 'body bytes changed'):
                tg.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'FDE record changed'):
            tg.analyze(self.mutated(tg.FDE_VA + 8, b'\x22\x22\x22\x22'))

    def test_location_mutations_rejected(self):
        if not tg.LOCATIONS:
            self.skipTest('no panic Locations in this body')
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            tg.analyze(self.mutated(tg.LOCATIONS[0][1] + 8,
                                    struct.pack('<I', tg.LOCATIONS[0][3] + 1)))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        loc_vas = {lv for _, lv, _, _, _ in tg.LOCATIONS}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in loc_vas:
                slots[address] = (rela['address'] + off, addend)
        self.assertGreater(len(slots), 0)
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, 'Location|path|layout'):
                tg.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 0x10)))

    def test_census_record(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_e8'], [hex(x) for x in tg.CALLERS])
        self.assertEqual(census['lea_references'], tg.LEA_REFS)


if __name__ == '__main__':
    unittest.main()
