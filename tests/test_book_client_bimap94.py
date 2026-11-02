"""Static and synthetic controls for the node 94 client-ID index packet."""
import struct
import unittest

from tools import book_client_bimap94 as m


class EvidenceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.BINARY.read_bytes()
        cls.sections = m.sections(cls.data)
        cls.records = m.analyse(cls.data)

    def test_identity_and_eight_fde_ranges(self):
        m.checked_data(self.data)
        rows = self.records[0]
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(row['size'] for row in rows), 6385)
        self.assertEqual(len({row['start'] for row in rows}), len(rows))
        self.assertTrue(all(len(bytes.fromhex(row['bytes_hex'])) == row['size'] for row in rows))

    def test_wrong_digest_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.checked_data(b'not the captured binary')

    def test_calls_and_relative_relocations(self):
        fn, calls, branches, witnesses, copies, constants, literals, locations = self.records
        self.assertEqual((len(calls), len(branches), len(witnesses)), (17, 36, 17))
        edges = {row[0]: row[-1] for row in calls}
        self.assertEqual(edges['put_grow_oid'], '0x357da80')
        self.assertEqual(edges['put_grow_client'], '0x35781f0')
        self.assertEqual(edges['insert_to_bimap'], '0x342aa50')
        self.assertEqual(len(copies), 10)
        self.assertEqual(len(literals), 3)
        self.assertEqual(locations[0][-3:], ('src/raw/mod.rs', 37, 40))
        self.assertEqual(sum(row[3] != row[5] for row in copies), 2)
        values = {row[0]: row[-1] for row in constants}
        self.assertEqual(values['user_bucket_bytes'], 0x78)
        self.assertEqual(values['oid_bucket_bytes'], 0x18)
        self.assertEqual(values['client_bucket_bytes'], 0x18)
        self.assertEqual(values['allocation_layout_ceiling'], 0x7ffffffffffffff0)

    @staticmethod
    def one_section(raw, address=0x1000):
        return bytes(raw), [dict(name='.text', type=1, flags=4, address=address,
                                 offset=0, size=len(raw))]

    def test_direct_call_opcode_and_displacement_corruption(self):
        target, raw = m.direct(self.data, self.sections, 0x342aa73)
        self.assertEqual(target, 0x379f580)
        changed = bytearray(raw)
        changed[0] = 0x90
        data, secs = self.one_section(changed)
        with self.assertRaises(ValueError):
            m.direct(data, secs, 0x1000)
        changed[0] = 0xe8
        changed[1] ^= 1
        data, secs = self.one_section(changed, 0x342aa73)
        self.assertNotEqual(m.direct(data, secs, 0x342aa73)[0], target)

    def test_branch_corruption(self):
        target, fallthrough, raw = m.branch(self.data, self.sections, 0x342aaa0)
        self.assertEqual((target, fallthrough), (0x342acfa, 0x342aaa6))
        changed = bytearray(raw)
        changed[1] = 0x90
        data, secs = self.one_section(changed, 0x342aaa0)
        with self.assertRaises(ValueError):
            m.branch(data, secs, 0x342aaa0)
        changed = bytearray(raw)
        changed[-1] ^= 1
        data, secs = self.one_section(changed, 0x342aaa0)
        self.assertNotEqual(m.branch(data, secs, 0x342aaa0)[0], target)

    def test_rip_indirect_corruption(self):
        slot, raw = m.indirect(self.data, self.sections, 0x379f70a)
        self.assertEqual(slot, 0x5773748)
        raw = bytearray(raw)
        raw[1] ^= 1
        data, secs = self.one_section(raw, 0x379f70a)
        with self.assertRaises(ValueError):
            m.indirect(data, secs, 0x379f70a)

    def test_instructions_reject_corruption(self):
        _, site, pattern = m.WITNESSES[6]
        raw = bytearray.fromhex(pattern)
        data, secs = self.one_section(raw, site)
        m.validate_witness(data, secs, site, bytes.fromhex(pattern))
        raw[len(raw)//2] ^= 1
        data, secs = self.one_section(raw, site)
        with self.assertRaisesRegex(ValueError, 'witness'):
            m.validate_witness(data, secs, site, bytes.fromhex(pattern))

    def test_byte_mutation_is_rejected_even_without_digest_gate(self):
        changed = bytearray(self.data)
        off, _ = m.read_va(changed, self.sections, 0x379f580, 1, True)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'function byte digest'):
            m.analyse(changed, verify_digest=False)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.checked_data(changed)
        changed[off] ^= 1
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            slot, info, _ = struct.unpack_from('<QQq', changed, pos)
            if slot == 0x5773748 and info == 8:
                changed[pos + 16] ^= 1
                break
        else:
            self.fail('expected relocation not found')
        with self.assertRaisesRegex(ValueError, 'indirect call or relocation'):
            m.analyse(changed, verify_digest=False)

    def test_address_must_be_unique_file_backed_and_executable(self):
        data, sec = self.one_section(b'abcdefgh')
        with self.assertRaises(ValueError):
            m.read_va(data, sec, 0x1007, 2)
        bad = [dict(sec[0], type=8)]
        with self.assertRaises(ValueError):
            m.read_va(data, bad, 0x1000, 1)
        with self.assertRaises(ValueError):
            m.read_va(data, sec * 2, 0x1000, 1)
        with self.assertRaises(ValueError):
            m.read_va(data, [dict(sec[0], flags=0)], 0x1000, 1, True)
        with self.assertRaises(ValueError):
            m.read_va(data, sec, (1 << 64)-1, 2)

    def test_duplicate_and_truncated_relocations_rejected(self):
        row = struct.pack('<QQq', 0x20, 8, 0x100)
        secs = [dict(type=4, offset=0, size=len(row))]
        self.assertEqual(m.relocations(row, secs), {0x20: 0x100})
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            m.relocations(row * 2, [dict(type=4, offset=0, size=len(row)*2)])
        with self.assertRaisesRegex(ValueError, 'truncated'):
            m.relocations(row, [dict(type=4, offset=0, size=len(row)-1)])


class ProjectionControls(unittest.TestCase):
    A = bytes.fromhex('00' * 16)
    B = bytes.fromhex('01' * 16)
    C = bytes.fromhex('02' * 16)

    def test_fresh_and_identical_pair(self):
        oids, clients, path = m.bind({}, {}, 7, self.A)
        self.assertEqual((oids, clients, path), ({7:self.A}, {self.A:7}, 'updated'))
        self.assertEqual(m.bind(oids, clients, 7, self.A), (oids, clients, 'same'))

    def test_one_oid_changes_client(self):
        oids, clients, _ = m.bind({7:self.A}, {self.A:7}, 7, self.B)
        self.assertEqual(oids, {7:self.B})
        self.assertEqual(clients, {self.B:7})

    def test_client_reassigned_to_different_oid(self):
        oids, clients, _ = m.bind({7:self.A}, {self.A:7}, 8, self.A)
        self.assertEqual(oids, {8:self.A})
        self.assertEqual(clients, {self.A:8})

    def test_both_sides_reassigned(self):
        oids, clients, _ = m.bind({7:self.A, 8:self.B}, {self.A:7, self.B:8}, 7, self.B)
        self.assertEqual(oids, {7:self.B})
        self.assertEqual(clients, {self.B:7})

    def test_matching_pair_does_not_repair_an_inconsistent_reverse_map(self):
        self.assertEqual(m.bind({7:self.A}, {}, 7, self.A), ({7:self.A}, {}, 'same'))

    def test_key_comparison_uses_all_sixteen_bytes(self):
        for position in range(16):
            changed = bytearray(self.A)
            changed[position] = 1
            oids, clients, _ = m.bind({7:self.A}, {self.A:7}, 7, bytes(changed))
            self.assertEqual(oids, {7:bytes(changed)})
            self.assertEqual(clients, {bytes(changed):7})

    def test_small_synthetic_sequences_preserve_bijection(self):
        oids, clients = {}, {}
        for oid, client in ((0,self.A),(1,self.B),(0,self.B),(2,self.C),
                            (1,self.A),(0,self.C),(2,self.B),(2,self.B)):
            oids, clients, _ = m.bind(oids, clients, oid, client)
            self.assertEqual({client:oid for oid, client in oids.items()}, clients)

    def test_growth_thresholds(self):
        self.assertEqual(m.growth_choice(0, 0), ('allocate', 4))
        self.assertEqual(m.growth_choice(3, 0), ('in_place', None))
        self.assertEqual(m.growth_choice(3, 1), ('allocate', 8))
        self.assertEqual(m.growth_choice(15, 6), ('in_place', None))
        self.assertEqual(m.growth_choice(15, 7), ('allocate', 32))
        self.assertEqual(m.growth_choice(31, 13), ('in_place', None))
        self.assertEqual(m.growth_choice(31, 14), ('allocate', 64))

    def test_allocation_size_classes_and_layout_ceiling(self):
        classes = ((0,4),(3,4),(4,8),(7,8),(8,16),(14,16),(15,32),(28,32),(29,64))
        for requested, buckets in classes:
            with self.subTest(requested=requested):
                observed, total = m.allocation_layout(24, requested)
                self.assertEqual(observed, buckets)
                self.assertEqual(total, 24 * buckets + buckets + 16)
        bound = 7 * (1 << 55)
        self.assertEqual(m.allocation_layout(24, bound)[0], 1 << 58)
        self.assertIsNone(m.allocation_layout(24, bound + 1))
        self.assertIsNone(m.allocation_layout(24, 1 << 61))
        with self.assertRaises(ValueError):
            m.allocation_layout(25, 1)

    def test_growth_rejects_malformed_inputs_and_count_overflow(self):
        for args in ((5,0),(-1,0),(3,4),(3,-1),(3,0,-1)):
            with self.assertRaises(ValueError):
                m.growth_choice(*args)
        self.assertEqual(m.growth_choice((1 << 63)-1, 1, (1 << 64)-1), ('overflow', None))
        self.assertEqual(m.growth_choice((1 << 63)-1, 1 << 62), ('layout_overflow', None))


if __name__ == '__main__':
    unittest.main()
