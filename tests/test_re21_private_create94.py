import hashlib
import json
from pathlib import Path
import struct
import unittest

from tools import re21_private_create94 as m


class PrivateCreateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        m.authenticate(cls.data)
        cls.secs, cls.index = m.unwind_index(cls.data)
        _, cls.frames = m.eh_frame_records(cls.data, cls.secs)
        cls.evidence = m.collect(cls.data)

    def mutate_va(self, va, callback):
        off = m.file_offset(self.secs, va, 1, len(self.data))
        old = self.data[off]
        self.data[off] ^= 1
        try:
            with self.assertRaises(m.EvidenceError):
                callback()
        finally:
            self.data[off] = old

    def test_full_digest_and_corruption(self):
        self.assertEqual(m.authenticate(self.data), m.DIGEST)
        self.mutate_va(0x24f0410, lambda: m.authenticate(self.data))

    def test_saved_outputs_equal_fresh_collection(self):
        packet = m.ROOT / 'research/work-items/RE-021-private-create-94'
        for name, content in self.evidence.items():
            with self.subTest(name=name):
                self.assertEqual((packet / name).read_bytes(), content)

    def test_fde_records_body_hashes_and_order(self):
        rows, bodies, unwind, exceptions = m.selected_frames(self.data, self.secs, self.index, self.frames)
        self.assertEqual(len(rows), 11)
        self.assertEqual([int(x['start_va'], 16) for x in rows], sorted(x[0] for x in m.FUNCTIONS))
        self.assertEqual(sum(x['size'] for x in rows), 10053)
        self.assertEqual(len(bodies), len(unwind))
        self.assertEqual(len(exceptions), 8)
        self.mutate_va(0x24f0410, lambda: m.selected_frames(self.data, self.secs, self.index, self.frames))

    def test_missing_duplicate_and_wrong_fde(self):
        selected = [f for f in self.frames if f['start'] in {x[0] for x in m.FUNCTIONS}]
        with self.assertRaises(m.EvidenceError):
            m.selected_frames(self.data, self.secs, self.index, selected[:-1])
        with self.assertRaises(m.EvidenceError):
            m.selected_frames(self.data, self.secs, self.index, selected + [selected[0]])
        modified = [dict(f) for f in selected]
        modified[0]['end'] += 1
        with self.assertRaises(m.EvidenceError):
            m.selected_frames(self.data, self.secs, self.index, modified)

    def test_file_backed_interval_rejections(self):
        seed = 0x5788348
        with self.assertRaises(m.EvidenceError):
            m.file_offset(self.secs, seed, 1, len(self.data))
        with self.assertRaises(m.EvidenceError):
            m.file_offset(self.secs, 0xffffffffffffffff, 2, len(self.data))
        with self.assertRaises(m.EvidenceError):
            m.file_offset(self.secs, 0x574f0c0, 0, len(self.data))
        with self.assertRaises(m.EvidenceError):
            m.file_offset(self.secs, 0x574f0c0, 1, len(self.data), executable=True)
        fake = [{'type': 1, 'flags': 2, 'address': 100, 'offset': 0, 'size': 10}]
        with self.assertRaises(m.EvidenceError):
            m.file_offset(fake, 109, 2, 10)
        with self.assertRaises(m.EvidenceError):
            m.file_offset(fake * 2, 100, 1, 10)
        fake[0]['type'] = 8
        with self.assertRaises(m.EvidenceError):
            m.file_offset(fake, 100, 1, 10)

    def test_instruction_windows_detect_corruption(self):
        self.assertEqual(len(m.verify_pins(self.data, self.secs)), 98)
        for va in (0x24f0427, 0x24f09f6, 0x278b72a, 0x27c5399, 0x2787f0d, 0x4c96e36):
            with self.subTest(va=hex(va)):
                self.mutate_va(va, lambda: m.verify_pins(self.data, self.secs))

    def test_branch_displacement_corruption(self):
        self.assertEqual(len(m.extract_transfers(self.data, self.secs)), 91)
        for va in (0x24f050b, 0x24f09d1, 0x276e8d3, 0x278b882, 0x27c53c0, 0x2788001):
            with self.subTest(va=hex(va)):
                self.mutate_va(va, lambda: m.extract_transfers(self.data, self.secs))

    def test_unsupported_and_truncated_branch(self):
        fake = [{'type': 1, 'flags': 6, 'address': 0x100, 'offset': 0, 'size': 2}]
        with self.assertRaises(m.EvidenceError):
            m.decode_transfer(b'\xe8\x00', fake, 0x100)
        with self.assertRaises(m.EvidenceError):
            m.decode_transfer(b'\x90\x90', fake, 0x100)

    def test_selected_relocations_and_bad_addend(self):
        rows = m.read_relative_relocations(self.data, self.secs)
        self.assertEqual(len(rows), 25)
        by_name = {r['name']: r for r in rows}
        self.assertEqual(by_name['prior_address09_callback']['addend'], '0x4e9d2a0')
        off = int(by_name['creation_callback_method']['record_file_offset'], 16) + 16
        old = self.data[off]
        self.data[off] ^= 1
        try:
            with self.assertRaises(m.EvidenceError):
                m.read_relative_relocations(self.data, self.secs)
        finally:
            self.data[off] = old
        off = int(by_name['opcode_f0_slot']['record_file_offset'], 16) + 8
        old = self.data[off]
        self.data[off] ^= 1
        try:
            with self.assertRaises(m.EvidenceError):
                m.read_relative_relocations(self.data, self.secs)
        finally:
            self.data[off] = old

    def test_duplicate_relocation_is_rejected(self):
        rows = m.read_relative_relocations(self.data, self.secs)
        offset = int(rows[0]['record_file_offset'], 16) + 24
        old = self.data[offset:offset + 8]
        struct.pack_into('<Q', self.data, offset, 0x56acf08)
        try:
            with self.assertRaises(m.EvidenceError):
                m.read_relative_relocations(self.data, self.secs)
        finally:
            self.data[offset:offset + 8] = old

    def test_prior_object_and_action_table_mutation(self):
        dep = m.extract_dependencies(self.data, self.secs)
        self.assertEqual(dep['prior_address09_bytes'], '00' * 19 + '09')
        self.assertEqual(dep['action_destinations'][1], '0x2515f19')
        for va in (0x574f0c0, 0x3e5788, 0x2793094, 0x2515cb2):
            with self.subTest(va=hex(va)):
                self.mutate_va(va, lambda: m.extract_dependencies(self.data, self.secs))

    def test_frame_lanes_and_changed_displacement(self):
        rows = m.extract_lanes(self.data, self.secs)
        lanes = {(r['opcode'], r['field']): int(r['frame_offset'], 16) for r in rows}
        for field in ('input_low', 'input_high', 'value_low', 'value_high', 'gas', 'caller_low', 'caller_high'):
            self.assertEqual(lanes['f0', field], lanes['f5', field])
        self.assertEqual((lanes['f5', 'salt_low'], lanes['f5', 'salt_high']), (8, 24))
        self.mutate_va(0x24f0a6c, lambda: m.extract_lanes(self.data, self.secs))

    def test_exception_table_and_landing_corruption(self):
        tables = json.loads(self.evidence['exception-sites.json'])
        edges = m.selected_exception_edges(tables)
        self.assertEqual([e['landing_va'] for e in edges],
                         ['0x24f0786', '0x24f0b78', '0x276e920', '0x276e905'])
        calls = {row['name']: row['target_va'] for row in m.extract_transfers(self.data, self.secs)}
        for name in ('f0_unwind_resume', 'f5_unwind_resume',
                     'adapter_payload_unwind_resume', 'adapter_call_unwind_resume'):
            self.assertEqual(calls[name], '0x5660110')
        broken = json.loads(self.evidence['exception-sites.json'])
        broken[0]['entries'][3]['landing_va'] = '0x24f0787'
        with self.assertRaises(m.EvidenceError):
            m.selected_exception_edges(broken)
        frame = next(f for f in self.frames if f['start'] == 0x24f0410)
        self.mutate_va(frame['lsda'], lambda: m.parse_exception_table(self.data, self.secs, frame))

    def test_constants_and_relational_boundaries(self):
        c = m.extract_constants(self.data, self.secs)
        self.assertEqual((c['revision_argument'], c['call_depth_limit'], c['default_input_limit']), (18, 1024, 49152))
        self.assertEqual((c['create_base_gas'], c['create2_base_gas']), (32000, 32000))
        self.assertEqual((c['status_collision'], c['status_checkpoint_overflow']), (0x5e, 0x5f))
        calls = {row['name']: row['target_va'] for row in m.extract_transfers(self.data, self.secs)}
        self.assertEqual(calls['owned_membership'], calls['borrowed_membership'])
        self.assertEqual(calls['owned_membership'], '0x27c52e0')

    def test_failure_edges_distinguish_tag_and_status(self):
        rows = m.failure_paths(m.extract_transfers(self.data, self.secs),
                               m.extract_constants(self.data, self.secs))
        by_name = {r['branch']: r for r in rows}
        self.assertEqual(len(rows), 27)
        self.assertEqual((by_name['caller_load_error']['outcome_kind'], by_name['caller_load_error']['outcome']),
                         ('outer_tag', '0x4'))
        self.assertEqual((by_name['owned_miss']['failure_edge'], by_name['owned_miss']['outcome']),
                         ('fallthrough', '0x5e'))
        self.assertEqual((by_name['borrowed_hit']['failure_edge'], by_name['borrowed_hit']['outcome']),
                         ('taken', '0x5e'))
        self.assertEqual(by_name['checkpoint_nonce_zero']['failure_edge'], 'fallthrough')

    def test_fork_selector_and_comparison_corruption(self):
        relas = m.read_relative_relocations(self.data, self.secs)
        cases, matrix = m.extract_selector_and_matrix(self.data, self.secs, relas)
        self.assertEqual([x['raw_revision'] for x in cases], [9, 10, 18])
        self.assertEqual(cases[0]['opcode_table_va'], cases[1]['opcode_table_va'])
        self.assertEqual(len(matrix), 6)
        self.assertEqual({r['target_fde_start_va'] for r in matrix},
                         {'0x24f0410', '0x24f07e0', '0x4c96150', '0x4c96d10', '0x4c95d80', '0x4c96540'})
        for va in (0x6f2ab0, 0x44bd994, 0x4c95e8a):
            with self.subTest(va=hex(va)):
                self.mutate_va(va, lambda: m.extract_selector_and_matrix(self.data, self.secs, relas))

    def test_source_locations_and_mutations(self):
        relas = m.read_relative_relocations(self.data, self.secs)
        rows = m.extract_source_locations(self.data, self.secs, relas)
        self.assertEqual(len(rows), 10)
        self.assertEqual({r['relative_suffix'] for r in rows},
                         {'revm-interpreter-15.0.0/src/interpreter/shared_memory.rs',
                          'revm-19.2.0/src/journaled_state.rs'})
        for va in (0x24f0734, 0x56b8320, 0x200b2d):
            with self.subTest(va=hex(va)):
                self.mutate_va(va, lambda: m.extract_source_locations(self.data, self.secs, relas))

    def test_unmasked_window_comparison_rejects_either_side(self):
        rows = m.compare_revision18_windows(self.data, self.secs)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r['comparison'] == 'raw_equal' and r['normalization_mask'] == 'none'
                            and r['private_bytes'] == r['standard_bytes'] for r in rows))
        for va in (0x24f04e7, 0x4c95e57, 0x24f08f9, 0x4c96659):
            with self.subTest(va=hex(va)):
                self.mutate_va(va, lambda: m.compare_revision18_windows(self.data, self.secs))

    def test_salted_preimage_lane_projection_and_mutations(self):
        rows = m.extract_salted_preimage_lanes(self.data, self.secs)
        self.assertEqual(len(rows), 85)
        frame = bytearray(136)
        frame[0x08:0x28] = bytes(range(32))
        frame[0x70:0x84] = bytes(range(20))
        digest = bytes(range(32, 64))
        result = bytearray()
        for row in rows:
            if row['source'] == 'literal':
                result.append(int(row['literal_byte'], 16))
            elif row['source'] == 'frame':
                result.append(frame[int(row['source_offset'], 16)])
            else:
                result.append(digest[int(row['source_offset'], 16)])
        self.assertEqual(bytes(result), b'\xff' + bytes(range(20)) + bytes(reversed(range(32))) + digest)
        for va in (0x278b596, 0x278b68f, 0x278b73e, 0x278b817):
            with self.subTest(va=hex(va)):
                self.mutate_va(va, lambda: m.extract_salted_preimage_lanes(self.data, self.secs))


class SyntheticProjectionTests(unittest.TestCase):
    @staticmethod
    def reference_fold(a, b):
        mask32 = (1 << 32) - 1
        a0, a1, b0, b1 = a & mask32, a >> 32, b & mask32, b >> 32
        product = a0 * b0 + ((a0 * b1 + a1 * b0) << 32) + ((a1 * b1) << 64)
        return ((product & m.MASK64) ^ (product >> 64)) & m.MASK64

    def test_address_hash_against_limb_oracle(self):
        keys = [bytes(20), bytes.fromhex('00' * 19 + '09'), bytes(range(20)), bytes([255]) * 20]
        seeds = [(0, 0, 0), (1, 2, 3), (m.MASK64, 0x12345678, 0xfedcba9876543210)]
        for key in keys:
            for seed, secret0, secret1 in seeds:
                words = [int.from_bytes(key[i:i + 8], 'little') for i in (0, 4, 8, 12)]
                u = self.reference_fold(words[2] ^ secret1, words[3] ^ secret0)
                v = self.reference_fold(words[0] ^ seed, words[1] ^ secret0)
                expected = self.reference_fold(u ^ v ^ 20, secret0)
                self.assertEqual(m.address_hash(key, seed, secret0, secret1), expected)
        with self.assertRaises(m.EvidenceError):
            m.address_hash(b'\x09', 1, 2, 3)

    def test_lookup_hit_empty_and_all_address_bit_mutations(self):
        address = bytes.fromhex('00' * 19 + '09')
        seeds = (17, 21, 97)
        h = m.address_hash(address, *seeds)
        mask = 31
        slot = h & mask
        controls = bytearray(b'\xff' * 32)
        keys = [None] * 32
        controls[slot] = h >> 57
        keys[slot] = address
        self.assertTrue(m.probe(address, bytes(controls), keys, *seeds))
        for bit in range(160):
            changed = bytearray(address)
            changed[bit // 8] ^= 1 << (bit % 8)
            changed = bytes(changed)
            h2 = m.address_hash(changed, *seeds)
            p = h2 & mask
            fake_ctrl = bytearray(b'\xff' * 32)
            fake_keys = [None] * 32
            fake_ctrl[p] = h2 >> 57
            fake_keys[p] = address
            self.assertFalse(m.probe(changed, bytes(fake_ctrl), fake_keys, *seeds))

    def test_lookup_candidates_precede_empty_and_deleted_group(self):
        key = bytes.fromhex('00' * 19 + '09')
        seeds = (17, 21, 97)
        h = m.address_hash(key, *seeds)
        start, fp = h & 31, h >> 57
        controls = bytearray(b'\xff' * 32)
        keys = [None] * 32
        p = (start + 7) & 31
        controls[p] = fp
        keys[p] = key
        self.assertTrue(m.probe(key, bytes(controls), keys, *seeds))
        controls = bytearray(b'\x80' * 32)
        controls[(start + 16) & 31] = fp
        controls[(start + 17) & 31] = 0xff
        keys = [None] * 32
        keys[(start + 16) & 31] = key
        self.assertTrue(m.probe(key, bytes(controls), keys, *seeds))
        controls[(start + 16) & 31] = 0x80
        self.assertFalse(m.probe(key, bytes(controls), keys, *seeds))

    def test_lookup_invalid_tables_are_model_errors(self):
        key = bytes(20)
        with self.assertRaises(m.EvidenceError):
            m.probe(key, bytes(15), [None] * 15, 1, 2, 3)
        fp = m.address_hash(key, 1, 2, 3) >> 57
        controls = bytearray(b'\xff' * 16)
        controls[m.address_hash(key, 1, 2, 3) & 15] = fp
        with self.assertRaises(m.EvidenceError):
            m.probe(key, bytes(controls), [None] * 16, 1, 2, 3)
        with self.assertRaises(m.EvidenceError):
            m.probe(key, bytes(16), [bytes([1]) * 20] * 16, 1, 2, 3)

    def test_nonce_preimage_boundaries_and_overflow(self):
        address = bytes(range(20))
        for n, prefix, number in ((0, 0xd6, '80'), (1, 0xd6, '01'), (127, 0xd6, '7f'),
                                  (128, 0xd7, '8180'), (255, 0xd7, '81ff'), (256, 0xd8, '820100')):
            self.assertEqual(m.create_preimage(address, n), bytes([prefix, 0x94]) + address + bytes.fromhex(number))
        self.assertEqual(m.create_preimage(address, m.MASK64 - 1)[-9:], bytes.fromhex('88fffffffffffffffe'))
        with self.assertRaises(m.EvidenceError):
            m.create_preimage(address, m.MASK64)
        with self.assertRaises(m.EvidenceError):
            m.create_preimage(address[:-1], 0)

    def test_salted_preimage_width_and_byte_order(self):
        address, salt, digest = bytes(range(20)), bytes(range(32)), bytes(range(32, 64))
        expected = b'\xff' + address + bytes(reversed(range(32))) + digest
        self.assertEqual(len(expected), 85)
        self.assertEqual(m.create2_preimage(address, salt, digest), expected)
        self.assertNotEqual(m.create2_preimage(address, salt, digest)[21:53], salt)
        for args in ((address[:-1], salt, digest), (address, salt[:-1], digest), (address, salt, digest[:-1])):
            with self.assertRaises(m.EvidenceError):
                m.create2_preimage(*args)

    def test_gas_word_and_boundary_cases(self):
        for length in (0, 1, 31, 32, 33, 49152):
            words = (length + 31) // 32
            for salted in (False, True):
                cost = 32000 + words * (8 if salted else 2)
                fail = m.projected_gas(length, cost - 1, salted)
                ok = m.projected_gas(length, cost, salted)
                self.assertEqual(fail['status'], 0x50)
                self.assertEqual(ok, {'status': 0x20, 'remaining': 0, 'child': 0})
                self.assertEqual(m.projected_gas(length, cost + 128, salted),
                                 {'status': 0x20, 'remaining': 2, 'child': 126})
        self.assertEqual(m.projected_gas(33, 3, False), {'status': 0x50, 'remaining': 3, 'child': None})
        self.assertEqual(m.projected_gas(33, 4, True), {'status': 0x50, 'remaining': 0, 'child': None})
        with self.assertRaises(m.EvidenceError):
            m.projected_gas(-1, 0, False)

    def test_revision9_and_revision18_gas_comparison(self):
        for length in (0, 1, 31, 32, 33, 128, 49152):
            words = (length + 31) // 32
            for salted in (False, True):
                old = 32000 + (6 * words if salted else 0)
                new = old + 2 * words
                self.assertEqual(m.projected_gas(length, old, salted, revision=9)['status'], 0x20)
                self.assertEqual(m.projected_gas(length, new, salted, revision=18)['status'], 0x20)
                if words:
                    self.assertEqual(m.projected_gas(length, old, salted, revision=18)['status'], 0x50)
        with self.assertRaises(m.EvidenceError):
            m.projected_gas(0, 32000, False, revision=10)
        # This only tests the saturating arithmetic projection; it does not
        # assert that an enormous input can pass the target's configured cap.
        huge = m.MASK64
        rounded = m.MASK64 >> 5
        expected_charge = 2 * rounded
        self.assertEqual(m.projected_gas(huge, expected_charge - 1, False)['status'], 0x50)
        self.assertEqual(m.projected_gas(huge, expected_charge + 32000, False)['status'], 0x20)

    def test_four_limb_addition_against_big_integer(self):
        values = (0, 1, m.MASK64, 1 << 64, (1 << 255), (1 << 256) - 1)
        limbs = lambda n: tuple((n >> (64 * i)) & m.MASK64 for i in range(4))
        for a in values:
            for b in values:
                result, carry = m.add_limbs(limbs(a), limbs(b))
                actual = sum(x << (64 * i) for i, x in enumerate(result))
                self.assertEqual(actual, (a + b) % (1 << 256))
                self.assertEqual(carry, (a + b) >> 256)
        with self.assertRaises(m.EvidenceError):
            m.add_limbs((0,), (0,))


if __name__ == '__main__':
    unittest.main()
