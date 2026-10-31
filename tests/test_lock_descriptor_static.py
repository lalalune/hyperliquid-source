"""Target-grounded controls for the static lock-guard cell packet (no node execution)."""
import json
import struct
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import lock_descriptor_static as ld
from elf_index import sections


class LockDescriptorEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ld.TARGET.is_file() or ld.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = ld.inspect(ld.TARGET)
        cls.data = ld.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va < s['address'] + s['size']]
        self.assertEqual(len(matches), 1)
        s = matches[0]
        return s['offset'] + va - s['address']

    def mutated_read(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_retained_record_matches_authenticated_target(self):
        record = ld.ROOT / 'research/work-items/RE-001-lock-descriptor-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_cell_layout(self):
        cell = self.result['cell']
        self.assertEqual(cell['slot_0x00'], '0x35ab620')
        self.assertEqual(cell['slot_0x28'], '0x3790fc0')
        self.assertEqual(cell['state_word_0x20'], 3)
        self.assertEqual(cell['bytes'], 0x40)
        # The two relocation-bound slots sit exactly 0x28 apart inside the cell.
        self.assertEqual(0x57862a0 - 0x5786278, 0x28)

    def test_glue_zeroes_24_bytes_and_returns_argument(self):
        glue = ld.DROP_BODY
        self.assertEqual(len(glue), 18)
        self.assertEqual(glue[:3], bytes.fromhex('4889f8'))            # mov rax, rdi
        self.assertEqual(glue[3:11], bytes.fromhex('48c7471800000000'))  # [rdi+0x18] = 0
        self.assertEqual(glue[11:], bytes.fromhex('0f57c00f1107c3'))   # xmm0=0; [rdi]=0; ret
        self.assertEqual(self.result['zeroing_glue']['reachability'],
                         'cell slot +0x00 only; zero code references')

    def test_accessor_constant_and_lookup(self):
        acc = self.result['accessor']
        self.assertEqual(acc['constant_index'], '0xaf93b')
        self.assertEqual(acc['lookup'], {'got': '0x576e890', 'target': '0x151f6f0'})
        self.assertEqual(acc['reachability'], 'cell slot +0x28 only; zero code references')
        # 0xaf93b = 719163, a plain 32-bit constant selector.
        self.assertEqual(ld.ACC_INDEX, 719163)

    def test_sibling_census_and_caller_fdes(self):
        census = self.result['call_census']['sibling']
        self.assertEqual(census['got_indirect_sites'], 3)
        self.assertEqual(census['direct_e8'], 0)
        self.assertEqual(len(census['caller_fdes']), 3)
        for (lo, hi), site in zip(ld.CALLER_FN, ld.SIB_CALLERS):
            self.assertTrue(lo <= site < hi)
        # The 1e9-nanosecond timeout is shared with the 952-site helper packet.
        self.assertEqual(self.result['sibling_guard']['park_timeout_ns'], 10**9)
        self.assertEqual(self.result['sibling_guard']['lock_cmpxchg'], 4)

    def test_cell_lea_partition(self):
        # Exactly twelve rip-relative lea references cell-wide: six in the
        # sibling, six in the helper bound by RE-001-readlock-helper-94.
        leas = self.result['call_census']['cell_lea_references']
        self.assertEqual(leas, {'sibling': 6, 'helper': 6})
        self.assertEqual(len(ld.SIB_LEA_OFFSETS), 6)
        self.assertEqual(len(ld.HELPER_LEA_SITES), 6)
        self.assertTrue(ld.HELPER_START <= ld.HELPER_LEA_SITES[0] < ld.HELPER_END)
        self.assertTrue(ld.HELPER_START <= ld.HELPER_LEA_SITES[-1] < ld.HELPER_END)

    def test_mutation_control_bodies(self):
        for start, old, name in [(ld.DROP_START, ld.DROP_BODY, 'DROP_BODY'),
                                 (ld.ACC_START, ld.ACC_BODY, 'ACC_BODY'),
                                 (ld.SIB_START, ld.SIB_BODY, 'SIB_BODY')]:
            mutated = bytearray(old)
            mutated[len(mutated) // 2] ^= 0xFF
            with unittest.mock.patch.object(ld, name, bytes(mutated)):
                with self.assertRaises(ValueError):
                    ld.analyze(self.data)

    def test_mutation_control_cell_and_relocation(self):
        # Flip the cell state word in the raw image.
        data = self.mutated_read(ld.DESC_VA + 0x20, struct.pack('<Q', 4))
        with unittest.mock.patch.object(ld, 'DESC', data_read := ld.Reader(data).read(ld.DESC_VA, 0x40)):
            with self.assertRaises(ValueError):
                ld.analyze(data)
        # Corrupt the .rela.dyn addend behind the cell's first slot.
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        base = self.offset(rela['address'])
        data = bytearray(self.data)
        for entry in range(base, base + rela['size'], 24):
            if struct.unpack_from('<Q', data, entry)[0] == ld.DESC_VA:
                addend = struct.unpack_from('<q', data, entry + 16)[0]
                data[entry + 16:entry + 24] = struct.pack('<q', addend + 8)
                break
        else:
            self.fail('cell relocation entry not found')
        with self.assertRaises(ValueError):
            ld.analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
