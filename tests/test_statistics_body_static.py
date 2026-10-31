"""Target-grounded controls for the static statistics-body packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import statistics_body_static as sb
from elf_index import sections


class StatisticsBodyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not sb.TARGET.is_file() or sb.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = sb.inspect(sb.TARGET)
        cls.data = sb.TARGET.read_bytes()
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
        record = sb.ROOT / 'research/work-items/RE-001-statistics-body-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        body = self.result['body']
        self.assertEqual(body['start_va'], '0x4898810')
        self.assertEqual(body['end_va_exclusive'], '0x489a544')
        self.assertEqual(body['bytes'], 7476)
        self.assertEqual(body['sha256'], sb.BODY_SHA256)
        self.assertEqual(len(sb.BODY), 7476)
        self.assertEqual(len(sb.BRANCHES), 240)
        self.assertEqual(len(sb.DIRECT_CALLS), 12)
        self.assertEqual(len(sb.INDIRECT_CALLS), 37)
        self.assertEqual(len(sb.LOCATIONS), 12)
        self.assertEqual(self.result['target_sha256'],
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')

    def test_guard_call_anchor(self):
        guard = self.result['anchors']['guard_calls']
        self.assertEqual(guard['target'], '0x474fb90')
        self.assertEqual(guard['sites'], ['0x4899415', '0x4899910'])
        # The window-guard packet's census bound exactly these two sites.

    def test_helper_got_anchors(self):
        anchors = self.result['anchors']
        self.assertEqual(anchors['chrono_helper']['target'], '0x15206e0')
        self.assertEqual(anchors['chrono_helper']['got'], '0x576e8a8')
        self.assertEqual(anchors['time_sub']['target'], '0x1447130')
        self.assertEqual(anchors['time_sub']['got'], '0x576e8c0')

    def test_panic_location_anchors(self):
        locations = {(item['path'], item['line'])
                     for item in self.result['anchors']['panic_locations']}
        for expected in [('collections/btree/navigate.rs', 161),
                         ('collections/btree/navigate.rs', 198),
                         ('collections/btree/node.rs', 670),
                         ('collections/btree/map/entry.rs', 614),
                         ('collections/btree/node.rs', 618),
                         ('collections/btree/map.rs', 306),
                         ('collections/btree/navigate.rs', 534),
                         ('collections/btree/navigate.rs', 600),
                         ('naive/datetime/mod.rs', 1631)]:
            self.assertIn(expected, locations)
        # datetime/mod.rs:1631:38 shares the Location struct VA with the guard.
        shared = [item for item in self.result['anchors']['panic_locations']
                  if item['line'] == 1631]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]['location_va'], '0x566af18')

    def test_identity_rejects_size_and_sha_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                sb.inspect(path)
            path.write_bytes(self.mutated(sb.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                sb.inspect(path)

    def test_body_and_fde_mutations_rejected(self):
        for va in (sb.START, sb.START + 0x100, sb.START + 0x800, sb.START + 0x1d00):
            with self.assertRaisesRegex(ValueError, 'body bytes changed'):
                sb.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Statistics FDE record changed'):
            sb.analyze(self.mutated(sb.FDE_VA + 8, b'\x22\x22\x22\x22'))

    def test_branch_table_shape(self):
        # Every retained branch row decodes and stays inside the body extent.
        for offset, pattern, rel_pos, insn_len, destination in sb.BRANCHES:
            raw = bytes.fromhex(pattern)
            self.assertEqual(len(raw), insn_len)
            self.assertTrue(0 <= offset < sb.END - sb.START - insn_len)
            self.assertTrue(sb.START <= destination < sb.END)

    def test_location_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            sb.analyze(self.mutated(sb.LOCATIONS[0][1] + 8,
                                    struct.pack('<I', sb.LOCATIONS[0][3] + 1)))
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        path_va = None
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address == sb.LOCATIONS[-1][1]:
                path_va = addend
        self.assertIsNotNone(path_va)
        with self.assertRaisesRegex(ValueError, 'panic path changed'):
            sb.analyze(self.mutated(path_va + 40, b'X'))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in (sb.CALLEE1_GOT, sb.TIMESUB_GOT):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 2)
        messages = {sb.CALLEE1_GOT: 'chrono helper GOT slot changed',
                    sb.TIMESUB_GOT: 'Time Sub GOT slot changed'}
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, messages[va]):
                sb.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 0x10)))

    def test_census_record(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_e8'], ['0x474f9c0', '0x474fa28'])
        self.assertEqual(census['lea_references'], 0)
        self.assertEqual(census['containing_function'],
                         {'start': '0x474f8a0', 'end': '0x474fa44'})


if __name__ == '__main__':
    unittest.main()
