"""Controls for the node 94 price-level insertion evidence collector."""
import hashlib
import unittest
from unittest.mock import patch

from tools import price_level_tree_insert94 as tree
from tools.elf_index import sections
from tools.fde_extents import eh_frame_records


class PriceLevelTreeEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tree.INPUT.read_bytes()
        tree.authenticate(cls.data)
        cls.sections = sections(cls.data)
        cls.params = tree.split_parameters(cls.data, cls.sections)

    def test_authenticated_input_and_corrupted_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tree.DIGEST)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tree.authenticate(b'corrupted')

    def test_fde_extents_and_file_backing(self):
        _, records = eh_frame_records(self.data, self.sections)
        for start, end, _ in tree.FUNCTIONS:
            matches = [r for r in records if r['start'] == start]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]['end'], end)
            raw, _ = tree.read_va(self.data, self.sections, start, end - start)
            self.assertEqual(len(raw), end - start)

    def test_pins_calls_and_branches(self):
        self.assertEqual(len(tree.check_pins(self.data, self.sections)), len(tree.PINS))
        self.assertEqual(len(tree.call_rows(self.data, self.sections)), 6)
        self.assertEqual(len(tree.branch_rows(self.data, self.sections)), 46)
        self.assertEqual(len(tree.diagnostic_rows(self.data, self.sections)), 9)
        self.assertEqual(len(tree.import_rows(self.data, self.sections)), 31)

    def test_corrupt_instruction_rejected(self):
        sec = [{'type': 1, 'address': 0x1000, 'offset': 0, 'size': 3}]
        pins = (('test', 0x1000, '010203'),)
        self.assertEqual(len(tree.check_pins(b'\x01\x02\x03', sec, pins)), 1)
        with self.assertRaisesRegex(ValueError, 'witness mismatch'):
            tree.check_pins(b'\x01\x00\x03', sec, pins)

    def test_relative_branch_corruption_rejected(self):
        sec = [{'type': 1, 'address': 0x1000, 'offset': 0, 'size': 2}]
        with patch.object(tree, 'BRANCHES', ((0x1000,0x74,0x1004,'branch'),)):
            self.assertEqual(tree.branch_rows(b'\x74\x02',sec)[0][-1], '0x1004')
            with self.assertRaisesRegex(ValueError, 'unexpected branch'):
                tree.branch_rows(b'\x74\x03',sec)
            with self.assertRaisesRegex(ValueError, 'unexpected branch'):
                tree.branch_rows(b'\x75\x02',sec)
            with self.assertRaisesRegex(ValueError, 'unsupported branch'):
                tree.branch_rows(b'\x90\x02',sec)

    def test_unmapped_crossing_and_nobits_addresses_rejected(self):
        sec = [{'type': 1, 'address': 0x1000, 'offset': 0, 'size': 4},
               {'type': 8, 'address': 0x2000, 'offset': 0, 'size': 4}]
        self.assertEqual(tree.read_va(b'abcd',sec,0x1001,2)[0],b'bc')
        for va, size in ((0x999,1),(0x1003,2),(0x2000,1),(0x1000,0),(-1,1)):
            with self.subTest(va=va,size=size), self.assertRaises(ValueError):
                tree.read_va(b'abcd',sec,va,size)
        with self.assertRaises(ValueError):
            tree.read_va(b'abcd',sec + [sec[0]],0x1000,1)

    def test_full_node_split_boundaries(self):
        expected = {
            0:(4,'left',0,5,6), 4:(4,'left',4,5,6),
            5:(5,'left',5,6,5), 6:(5,'right',0,5,6),
            7:(6,'right',0,6,5), 11:(6,'right',4,6,5),
        }
        for index, result in expected.items():
            with self.subTest(index=index):
                self.assertEqual(tree.split_case(index,self.params),result)
        for index in (-1,12):
            with self.assertRaises(ValueError):
                tree.split_case(index,self.params)

    def test_twelve_fixtures_preserve_sorted_keys(self):
        rows = tree.fixture_rows(self.params)
        self.assertEqual(len(rows),12)
        originals = list(range(2,24,2))
        for index,key,pivot,side,dst,nleft,nright,promoted,left,right in rows:
            with self.subTest(index=index):
                l = [int(x) for x in left.split(',')]
                r = [int(x) for x in right.split(',')]
                self.assertEqual([len(l),len(r)],[nleft,nright])
                self.assertEqual(l + [promoted] + r, sorted(originals+[key]))
                self.assertEqual(promoted,originals[pivot])
                self.assertEqual((l if side == 'left' else r)[dst],key)

    def test_nonfull_cases_and_parent_edges(self):
        rows = tree.nonfull_cases(self.params)
        self.assertEqual(len(rows), 66)
        for length,index,key,shifted,result in rows:
            old = list(range(2,2*length+2,2))
            old.insert(index,key)
            self.assertEqual(result,','.join(map(str,old)))
            self.assertEqual(shifted,length-index)
        parents = tree.parent_cases(self.params)
        self.assertEqual(len(parents),12)
        for index,pivot,side,dst,new_child,left,right in parents:
            edges = [int(x) for x in (left+','+right).split(',')]
            expected = list(range(12))
            expected.insert(index+1,new_child)
            self.assertEqual(edges,expected)

    def test_corrupt_actual_input_and_instruction(self):
        bad = bytearray(self.data)
        _, off = tree.read_va(bad,self.sections,0x4239fe2,4)
        bad[off+3] ^= 1
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tree.authenticate(bad)
        with self.assertRaisesRegex(ValueError,'witness mismatch'):
            tree.check_pins(bad,self.sections)
        _, off = tree.read_va(bad,self.sections,0x423a72f,6)
        bad[off+2] ^= 1
        with self.assertRaisesRegex(ValueError,'indirect slot'):
            tree.import_rows(bad,self.sections)

    def test_location_relocations_reject_corruption(self):
        altered = list(tree.LOCATIONS)
        altered[0] = 0
        with patch.object(tree, 'LOCATIONS',tuple(altered)):
            with self.assertRaises(ValueError):
                tree.diagnostic_rows(self.data,self.sections)


if __name__ == '__main__':
    unittest.main()
