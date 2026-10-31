"""Target-grounded controls for the static Once state-machine packet (no node execution)."""
import json
import struct
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import once_state_static as osm
from elf_index import sections


class OnceStateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not osm.TARGET.is_file() or osm.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = osm.inspect(osm.TARGET)
        cls.data = osm.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def test_retained_record_matches_authenticated_target(self):
        record = osm.ROOT / 'research/work-items/RE-001-once-state-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_jump_table_dispatch(self):
        table = self.result['states']['jump_table']
        self.assertEqual(table['entries'], 4)
        self.assertEqual(table['targets'],
                         ['0x4ee3c3a', '0x4ee3c76', '0x4ee3cf7', '0x4ee3c52'])
        # The poisoned-state entry (index 2) is the panic block.
        self.assertEqual(int(table['targets'][2], 16), 0x4ee3cf7)
        for target in table['targets']:
            self.assertTrue(osm.START <= int(target, 16) < osm.END)

    def test_futex_sequence(self):
        futex = self.result['futex']
        self.assertEqual(futex['syscall_selector'], '0xca (SYS_futex, x86-64)')
        self.assertEqual(futex['wait_operation'], '0x89')
        self.assertEqual(futex['wake_operation'], '0x81')
        self.assertEqual(futex['wake_count'], '0x7fffffff (wake all)')
        self.assertEqual(futex['observed_sites'], 4)
        # 0xca is the x86-64 futex syscall number.
        self.assertEqual(0xca, 202)

    def test_poison_panic(self):
        panic = self.result['poison_panic']
        self.assertTrue(panic['message_prefix'].startswith('Once instance'))
        self.assertIn('poisoned', panic['message_prefix'])
        self.assertEqual(panic['esi_operand'], '0x55')
        self.assertEqual(panic['callee'], '0x157b810')
        self.assertEqual(panic['resume_unwind'], '0x5660110')

    def test_census_top_shared_helper(self):
        census = self.result['call_census']
        self.assertEqual(census['got_indirect_sites'], 1252)
        self.assertEqual(census['direct_e8'], 0)
        self.assertEqual(census['got_slot'], '0x576e8b8')
        # The lock-cell sibling guard's call site is inside the census.
        self.assertEqual(census['lock_cell_sibling_site'], '0x358dc26')

    def test_mutation_control_body(self):
        mutated = bytearray(osm.BODY)
        mutated[len(mutated) // 2] ^= 0xFF
        with unittest.mock.patch.object(osm, 'BODY', bytes(mutated)):
            with self.assertRaises(ValueError):
                osm.analyze(self.data)

    def test_mutation_control_jump_table(self):
        # Flip one displacement entry of the jump table in the raw image.
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= osm.JUMP_TABLE_VA < s['address'] + s['size']]
        s = matches[0]
        off = s['offset'] + osm.JUMP_TABLE_VA - s['address']
        data = bytearray(self.data)
        entry = struct.unpack_from('<i', data, off + 8)[0]   # index 2
        data[off + 8:off + 12] = struct.pack('<i', entry + 8)
        with self.assertRaises(ValueError):
            osm.analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
