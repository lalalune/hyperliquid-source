"""Static and corruption controls for the pending-total tree repair packet."""
import hashlib
import struct
import unittest

from tools import staking_pending_total_repair94 as research


class TestPendingTotalRepair(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = research.Image(research.BINARY.read_bytes())
        cls.image.validate()

    def test_target_digest_and_wrong_input(self):
        self.assertEqual(hashlib.sha256(self.image.data).hexdigest(), research.DIGEST)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.Image(b'not the target')

    def test_corrupted_target_digest_is_rejected(self):
        damaged = bytearray(self.image.data)
        damaged[self.image.offset(0x2fc7e4c)] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.Image(damaged)

    def test_elf_virtual_range_checks(self):
        for va, size in ((-1, 1), (0, 0), (1 << 63, 4), (True, 4)):
            with self.subTest(va=va), self.assertRaises(ValueError):
                self.image.offset(va, size)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.offset(bss['address'])

    def test_all_exact_witnesses_fail_when_changed(self):
        for name, va, expected, _ in research.PINS:
            with self.subTest(name=name):
                changed = bytes([bytes.fromhex(expected)[0] ^ 1])
                with self.assertRaisesRegex(ValueError, 'byte witness mismatch'):
                    research.Overlay(self.image, va, changed).validate()

    def test_boundaries_and_instruction_walk(self):
        observed = {}
        for va, name in research.FUNCTIONS:
            f = self.image.fdes[va]
            rows = research.decode_function(self.image, va)
            self.assertEqual(rows[0]['address'], va)
            self.assertEqual(sum(r['size'] for r in rows), f['end'] - va)
            observed[name] = (f['end'], len(rows))
        self.assertEqual(observed, {
            'remove_leaf_repair': (0x2fc8679, 410), 'borrow_left': (0x2fa4c48, 174),
            'borrow_right': (0x2fa926f, 189), 'merge_and_track': (0x2faebe8, 228)})

    def test_bad_instruction_and_truncated_instruction(self):
        with self.assertRaises(ValueError):
            research.decode_one(b'\xe8\x00', 0, 0x1000)
        with self.assertRaises(ValueError):
            research.decode_one(b'\x0f\xff', 0, 0x1000)

    def test_branch_into_instruction_interior_is_rejected(self):
        va = 0x2fc7f03
        old = self.image.integer(va, 4, signed=True)
        changed = struct.pack('<i', old+1)
        with self.assertRaisesRegex(ValueError, 'instruction interior'):
            research.decode_function(research.Overlay(self.image, va, changed), 0x2fc7e30)

    def test_node_geometry(self):
        self.assertEqual(research.layout(self.image), {
            'keys_offset': 184, 'key_stride': 20, 'value_offset': 0, 'value_stride': 16,
            'parent_offset': 176, 'parent_edge_offset': 404, 'count_offset': 406,
            'child_offset': 408, 'capacity': 11, 'minimum_nonroot': 5,
            'leaf_allocation': 408, 'inner_allocation': 504})

    def test_leaf_copy_projection_all_slots(self):
        layout = research.layout(self.image)
        for n in range(1, 12):
            for slot in range(n):
                with self.subTest(n=n, slot=slot):
                    before = bytearray((i*37+9) % 256 for i in range(408))
                    struct.pack_into('<H', before, 406, n)
                    expected = bytearray(before)
                    key = bytes(before[184+slot*20:184+(slot+1)*20])
                    value = bytes(before[slot*16:(slot+1)*16])
                    for j in range(slot, n-1):
                        expected[184+j*20:184+(j+1)*20] = before[184+(j+1)*20:184+(j+2)*20]
                        expected[j*16:(j+1)*16] = before[(j+1)*16:(j+2)*16]
                    struct.pack_into('<H', expected, 406, n-1)
                    after, removed_key, removed_value = research.leaf_projection(self.image, before, slot)
                    self.assertEqual((after, removed_key, removed_value), (bytes(expected), key, value))
                    self.assertEqual(layout['capacity'], 11)

    def test_invalid_leaf_fixtures_are_rejected(self):
        node = bytearray(408)
        with self.assertRaises(ValueError):
            research.leaf_projection(self.image, node, 0)
        struct.pack_into('<H', node, 406, 12)
        with self.assertRaises(ValueError):
            research.leaf_projection(self.image, node, 0)
        struct.pack_into('<H', node, 406, 2)
        with self.assertRaises(ValueError):
            research.leaf_projection(self.image, node, 2)
        with self.assertRaises(ValueError):
            research.leaf_projection(self.image, node[:-1], 0)

    def test_initial_repair_boundary(self):
        c = research.choose_repair
        self.assertEqual(c(self.image, 6, 0, 0, True), 'no_repair')
        self.assertEqual(c(self.image, 5, 0, 0, False), 'root')
        self.assertEqual(c(self.image, 5, 6, 1, True), 'merge_left')
        self.assertEqual(c(self.image, 5, 7, 1, True), 'borrow_left')
        self.assertEqual(c(self.image, 5, 6, 0, True), 'merge_right')
        self.assertEqual(c(self.image, 5, 7, 0, True), 'borrow_right')
        with self.assertRaises(ValueError):
            c(self.image, 0, 2, 0, True)

    def test_initial_branch_mutations_change_the_decision(self):
        c = research.choose_repair
        underfull = research.Overlay(self.image, 0x2fc7f02, b'\x86')
        self.assertNotEqual(c(underfull, 6, 0, 0, False), c(self.image, 6, 0, 0, False))
        left = research.Overlay(self.image, 0x2fc7f87, b'\x86')
        self.assertNotEqual(c(left, 5, 6, 1, True), c(self.image, 5, 6, 1, True))
        right = research.Overlay(self.image, 0x2fc801b, b'\x76')
        self.assertNotEqual(c(right, 5, 6, 0, True), c(self.image, 5, 6, 0, True))

    def test_upward_repair_and_root_flag(self):
        u = research.upward_repair
        self.assertEqual(u(self.image, 0, 0, 0, False), ('empty_root', 0))
        self.assertEqual(u(self.image, 1, 0, 0, False), ('nonempty_root', 0))
        self.assertEqual(u(self.image, 4, 6, 1, True), ('merge_left', 0))
        self.assertEqual(u(self.image, 4, 7, 1, True), ('borrow_left', 1))
        self.assertEqual(u(self.image, 0, 11, 0, True), ('borrow_right', 5))
        with self.assertRaises(ValueError):
            u(self.image, 5, 0, 0, True)

    def test_upward_branch_mutation_changes_the_decision(self):
        mutant = research.Overlay(self.image, 0x2fc81e7, b'\x86')
        self.assertNotEqual(research.upward_repair(mutant, 4, 6, 1, True),
                            research.upward_repair(self.image, 4, 6, 1, True))

    def test_borrow_guard_boundary_and_failure_precedence(self):
        for side in ('left', 'right'):
            with self.subTest(side=side):
                g = lambda d,s,n: research.borrow_guard(self.image,d,s,n,side)
                self.assertEqual(g(4, 7, 1), 'guards_pass')
                self.assertEqual(g(10, 0, 2), 'capacity_failure')
                self.assertEqual(g(4, 0, 1), 'source_failure')
                self.assertEqual(g(10, 1, 1), 'guards_pass')
                self.assertEqual(g(11, 1, 1), 'capacity_failure')
                self.assertEqual(g(0, 0, 0), 'guards_pass')  # Guard only, not a safe operation.

    def test_borrow_count_branch_corruption_rejected(self):
        bad = research.Overlay(self.image, 0x2fa493a, b'\x83')
        with self.assertRaises(ValueError):
            research.borrow_guard(bad, 1, 1, 1, 'left')

    def test_merge_cursor_and_failure_precedence(self):
        m = research.merge_cursor
        self.assertEqual(m(self.image, 5, 5, 0, 5), ('merged', 5))
        self.assertEqual(m(self.image, 5, 5, 1, 5), ('merged', 11))
        self.assertEqual(m(self.image, 5, 5, 3, 5), ('merged', 11))
        self.assertEqual(m(self.image, 5, 5, 2, 5), ('merged', 5))
        self.assertEqual(m(self.image, 5, 6, 1, 7), ('cursor_failure', None))
        self.assertEqual(m(self.image, 5, 6, 1, 6), ('capacity_failure', None))
        with self.assertRaises(ValueError):
            m(self.image, 12, 0, 0, 0)

    def test_merge_guard_mutation_rejected(self):
        mutant = research.Overlay(self.image, 0x2fae7f0, b'\x87')
        with self.assertRaises(ValueError):
            mutant.validate()
        self.assertTrue(research.taken(research.branch_kind(self.image, 0x2fae7ef), 12, 12))
        self.assertFalse(research.taken(research.branch_kind(mutant, 0x2fae7ef), 12, 12))

    def test_transfer_projection_conserves_rows_and_separator(self):
        geom = research.layout(self.image)
        def ids(node):
            return [(int.from_bytes(k,'big'), int.from_bytes(v[:8],'little'))
                    for k,v in research.pairs(geom,node)]
        left = research.fixture_node(geom, range(4))
        parent = research.fixture_node(geom, [4])
        right = research.fixture_node(geom, range(5,12))
        l,p,r,freed = research.transfer_projection(self.image,left,parent,right,'borrow_left',2)
        self.assertEqual(ids(l), [(0,0),(1,1)])
        self.assertEqual(ids(p), [(2,2)])
        self.assertEqual(ids(r), [(x,x) for x in range(3,12)])
        self.assertFalse(freed)
        left = research.fixture_node(geom, range(2))
        parent = research.fixture_node(geom, [2])
        right = research.fixture_node(geom, range(3,8))
        l,p,r,freed = research.transfer_projection(self.image,left,parent,right,'borrow_right',3)
        self.assertEqual(ids(l), [(x,x) for x in range(5)])
        self.assertEqual(ids(p), [(5,5)])
        self.assertEqual(ids(r), [(6,6),(7,7)])
        self.assertFalse(freed)
        left = research.fixture_node(geom, range(4))
        parent = research.fixture_node(geom, [4])
        right = research.fixture_node(geom, range(5,11))
        l,p,r,freed = research.transfer_projection(self.image,left,parent,right,'merge')
        self.assertEqual(ids(l), [(x,x) for x in range(11)])
        self.assertEqual(ids(p), [])
        self.assertEqual(r, right)
        self.assertTrue(freed)
        self.assertEqual(l[176:184], left[176:184])

    def test_transfer_projection_rejects_corrupt_fixtures(self):
        geom = research.layout(self.image)
        left = research.fixture_node(geom, range(6))
        parent = research.fixture_node(geom, [6])
        right = research.fixture_node(geom, range(7,13))
        with self.assertRaises(ValueError):
            research.transfer_projection(self.image,left,parent,right,'merge')
        with self.assertRaises(ValueError):
            research.transfer_projection(self.image,left,parent,right,'borrow_left',0)
        with self.assertRaises(ValueError):
            research.transfer_projection(self.image,left,parent,right,'borrow_left',12)
        corrupt = bytearray(parent)
        struct.pack_into('<H',corrupt,406,12)
        with self.assertRaises(ValueError):
            research.transfer_projection(self.image,left,corrupt,right,'borrow_left',1)

    def test_child_transfer_and_parent_edge_reindex(self):
        left, right = [0,1,2,3,4], [5,6,7,8,9,10,11,12]
        a,b,links = research.child_projection(self.image,left,right,'borrow_left',2)
        self.assertEqual(a,[0,1,2])
        self.assertEqual(b,[3,4,5,6,7,8,9,10,11,12])
        self.assertEqual(links,[(x,'left',i) for i,x in enumerate(a)] +
                         [(x,'right',i) for i,x in enumerate(b)])
        a,b,links = research.child_projection(self.image,[0,1,2],[3,4,5,6,7,8], 'borrow_right',3)
        self.assertEqual(a,[0,1,2,3,4,5])
        self.assertEqual(b,[6,7,8])
        self.assertEqual(links[-1],(8,'right',2))
        a,b,links = research.child_projection(self.image,[0,1,2,3,4],[5,6,7,8,9,10,11], 'merge')
        self.assertEqual(a,list(range(12)))
        self.assertEqual(b,[])
        self.assertEqual(links[-1],(11,'left',11))

    def test_child_projection_rejects_invalid_controls(self):
        with self.assertRaises(ValueError):
            research.child_projection(self.image,[0,1],[1,2],'merge')
        with self.assertRaises(ValueError):
            research.child_projection(self.image,[],[1],'merge')
        with self.assertRaises(ValueError):
            research.child_projection(self.image,[0],[1],'borrow_left',1)
        mutant = research.Overlay(self.image,0x2fa90c4,b'\x4d')
        with self.assertRaisesRegex(ValueError,'byte witness mismatch'):
            research.child_projection(mutant,[0,1],[2,3],'borrow_right',1)

    def test_raw_rel32_candidates(self):
        rows = research.scan_raw_e8(self.image, [va for va,_ in research.FUNCTIONS])
        self.assertEqual(len(rows), 7)
        counts = {name: sum(r['target'] == hex(va) for r in rows) for va,name in research.FUNCTIONS}
        self.assertEqual(counts, {'remove_leaf_repair':2, 'borrow_left':2, 'borrow_right':2, 'merge_and_track':1})
        for row in rows:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(data[0], 0xe8)
            self.assertEqual(int(row['site'],16)+5+struct.unpack_from('<i',data,1)[0],int(row['target'],16))

    def test_dynamic_copy_imports(self):
        symbols = research.import_symbols(self.image)
        for load, prefix, call_bytes, sites in research.REGISTER_CALLS:
            slot = self.image.rip(load, prefix)
            self.assertEqual(symbols[slot], 'memmove')
            self.assertTrue(sites)
            for site in sites:
                self.assertEqual(self.image.read(site, len(bytes.fromhex(call_bytes))).hex(), call_bytes)
        self.assertEqual(symbols[0x576dfe0], 'memcpy')

    def test_failure_records_preserve_packed_length(self):
        rows = research.failure_rows(self.image)
        self.assertEqual(len(rows), 12)
        row = next(r for r in rows if r['name'] == 'empty_internal')
        self.assertEqual((row['raw_argument'], row['encoding'], len(row['text'])), (123, 'packed_literal', 61))
        self.assertIn('CAPACITY', next(r for r in rows if r['name'] == 'merge_capacity')['text'])

    def test_reproducible_serialization(self):
        files = research.generate(self.image)
        self.assertEqual(len(files), 16)
        self.assertEqual(files['summary.json'], research.json_bytes(__import__('json').loads(files['summary.json'])))
        self.assertEqual(len(files['leaf-cases.tsv'].splitlines()), 67)
        self.assertEqual(len(files['repair-cases.tsv'].splitlines()), 276)


if __name__ == '__main__':
    unittest.main()
