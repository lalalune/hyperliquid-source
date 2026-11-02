import hashlib
from pathlib import Path
import unittest

from tools import spot_level_tag94 as m


class SpotLevelTagEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = m.Image(bytearray((m.ROOT / 'artifacts/node/94/hl-node').read_bytes()))

    def flip(self, va, action):
        off, _ = self.image.read(va, 1, True)
        self.image.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                action()
        finally:
            self.image.data[off] ^= 1

    def test_target_identity_rejects_corruption(self):
        m.verify_digest(self.image.data)
        with self.assertRaises(ValueError):
            m.verify_digest(b'not the authenticated ELF')
        with self.assertRaises(ValueError):
            m.verify_digest(self.image.data, '0' * 64)

    def test_selected_fdes_link_to_index_and_body_hash(self):
        for _, start, end, digest in m.FUNCTIONS:
            f = self.image.fde(start, end)
            self.assertEqual(self.image.index[start], f['fde'])
            self.assertEqual(hashlib.sha256(self.image.read(start, end-start, True)[1]).hexdigest(), digest)
        with self.assertRaises(ValueError):
            self.image.fde(m.FUNCTIONS[0][1] + 1, m.FUNCTIONS[0][2])
        with self.assertRaises(ValueError):
            self.image.fde(m.FUNCTIONS[0][1], m.FUNCTIONS[0][2] + 1)

    def test_nonfile_and_outside_ranges_rejected(self):
        bss = next(s for s in self.image.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        for va, size in ((bss['address'], 1), (1 << 63, 1), (0, 0), (0, -1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                self.image.read(va, size)
        sec = next(s for s in self.image.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.read(sec['address'] + sec['size'] - 1, 2, True)

    def test_every_witness_rejects_changed_byte(self):
        for name, start, end, digest in m.WINDOWS:
            with self.subTest(name=name):
                m.verify_window(self.image, start, end, digest)
                self.flip(start, lambda: m.verify_window(self.image, start, end, digest))

    def test_every_branch_checks_opcode_and_displacement(self):
        for site, opcode, dest, name in m.BRANCHES:
            with self.subTest(name=name):
                _, raw, actual = m.branch(self.image, site, opcode, dest)
                self.assertEqual(actual, dest)
                self.flip(site, lambda: m.branch(self.image, site, opcode, dest))
                self.flip(site + len(raw) - 1, lambda: m.branch(self.image, site, opcode, dest))

    def test_every_call_checks_opcode_and_displacement(self):
        for indirect, items in ((False, m.CALLS), (True, m.SLOTS)):
            for site, dest, name in items:
                with self.subTest(name=name):
                    _, raw, actual = m.edge(self.image, site, dest, indirect)
                    self.assertEqual(actual, dest)
                    self.flip(site, lambda: m.edge(self.image, site, dest, indirect))
                    self.flip(site + len(raw) - 1, lambda: m.edge(self.image, site, dest, indirect))

    def test_immediates_are_bound_to_instruction_encodings(self):
        c = m.constants(self.image)
        self.assertEqual((c['entry_zero_head'], c['entry_zero_tail']), (0, 0))
        self.assertEqual((c['head_present_store'], c['tail_present_store']), (1, 1))
        self.assertEqual((c['non_split_marker'], c['promoted_marker_test']), (2, 2))
        self.assertEqual((c['leaf_allocation'], c['internal_allocation']), (0x1c8, 0x228))
        self.assertEqual(1 << c['value_stride_shift'], 32)
        self.flip(0x1a94a40, lambda: m.constants(self.image))

    def test_promoted_first_qword_is_moved_to_the_compared_slot(self):
        _, take = self.image.read(0x1a94b12, 4, True)
        _, save = self.image.read(0x1a94b37, 5, True)
        _, restore = self.image.read(0x1a94c75, 5, True)
        _, compare = self.image.read(0x1a94cb1, 4, True)
        self.assertEqual(take.hex(), '488b3402')
        self.assertEqual(save.hex(), '4889742418')
        self.assertEqual(restore.hex(), '488b442418')
        self.assertEqual(compare.hex(), '4883f902')
        _, result_store = self.image.read(0x1a94c7a, 5, True)
        self.assertEqual(result_store.hex(), '4889442428')
        self.flip(0x1a94cb1, lambda: m.constants(self.image))

    def test_parent_promoted_word_feeds_full_width_test(self):
        expected = ((0x1a9503e, '488b1403'),
                    (0x1a95063, '48899424a0000000'),
                    (0x1a9536a, '488b8424a00000004889442428'),
                    (0x1a953a7, '488b4c24284883f902'))
        for address, raw in expected:
            with self.subTest(address=address):
                self.assertEqual(self.image.read(address, len(bytes.fromhex(raw)), True)[1].hex(), raw)

    def test_split_models_preserve_order_and_key_count(self):
        c = m.constants(self.image)
        cases = m.split_cases(c)
        old = list(range(0, 22, 2))
        for index, pivot, side, local, left_count, right_count in cases:
            inserted = -1 if index == 0 else (old[-1] + 1 if index == len(old) else old[index - 1] + 1)
            left, right = old[:pivot], old[pivot + 1:]
            (left if side == 'left' else right).insert(local, inserted)
            with self.subTest(index=index):
                self.assertEqual(left + [old[pivot]] + right, sorted(old + [inserted]))
                self.assertEqual((len(left), len(right)), (left_count, right_count))
                self.assertEqual(len(left) + 1 + len(right), len(old) + 1)
        with self.assertRaises(ValueError):
            m.split_cases({**c, 'full_node_keys': 10})
        with self.assertRaises(ValueError):
            m.split_cases({**c, 'small_pivot': 3})

    def test_tag_uses_bind_width_and_immediate(self):
        rows = m.tag_uses(self.image)
        self.assertEqual([(row[0], row[4], row[5]) for row in rows], [
            ('append_head_byte', 8, 0), ('leaf_split_qword', 64, 2),
            ('parent_split_qword', 64, 2), ('first_field_dword', 32, 1),
            ('first_payload_byte', 8, 0), ('last_field_dword', 32, 1),
            ('last_payload_byte', 8, 0)])
        for _, site, _, raw, _, _ in rows:
            address = int(site, 16)
            size = len(bytes.fromhex(raw))
            with self.subTest(site=site):
                self.flip(address, lambda: m.tag_uses(self.image))
                self.flip(address + size - 1, lambda: m.tag_uses(self.image))

    def test_formatter_pointer_handoff(self):
        expected = ((0x4a987ce, '4989cd'), (0x4a9884b, '4c896c2410'),
                    (0x4a988c7, '4c8b6c2410'), (0x4a98901, '4983c518'),
                    (0x4a98905, '4c896c2410'), (0x4a98987, '488b7c2410'),
                    (0x4a40828, '4c8b7b08'), (0x4a40831, '4c897c2438'),
                    (0x4a40aac, '4c8b6c2438'))
        for address, raw in expected:
            with self.subTest(address=address):
                self.assertEqual(self.image.read(address, len(bytes.fromhex(raw)), True)[1].hex(), raw)

    def test_field_literals_are_bound_to_lea_and_lengths(self):
        rows = m.literal_rows(self.image)
        self.assertEqual([r[-1] for r in rows], ['halfs', 'levels', 'f', 'l'])
        self.flip(0x431e748, lambda: m.literal_rows(self.image))
        off, _ = self.image.read(0x704287, 1)
        self.image.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                m.literal_rows(self.image)
        finally:
            self.image.data[off] ^= 1

    def test_formatter_uses_32_bit_tag_tests(self):
        self.assertEqual(self.image.read(0x4a40b20, 5, True)[1].hex(), '41837d0001')
        self.assertEqual(self.image.read(0x4a40bff, 5, True)[1].hex(), '41837d1001')
        self.assertEqual(self.image.read(0x4a40b7e, 5, True)[1].hex(), '41807d0000')
        self.assertEqual(self.image.read(0x4a40c5a, 5, True)[1].hex(), '41807d1000')
        for tag in (0, 1, 2, 255, 256, (1 << 32) + 1, (1 << 64) - 1):
            with self.subTest(tag=tag):
                is_one = (tag & 0xffffffff) == 1
                if is_one:
                    self.assertNotEqual(tag & 0xff, 0)
        self.flip(0x4a40b20, lambda: m.verify_window(self.image, 0x4a40aa0, 0x4a40b2e,
                  next(w[3] for w in m.WINDOWS if w[0] == 'level_tags')))

    def test_relocation_binding_and_plt_corruption(self):
        rows, plt_bytes = m.relocation_rows(self.image)
        self.assertEqual(len(rows), 4)
        self.assertTrue(any(row[7] == '_Unwind_Resume' for row in rows))
        self.assertEqual(bytes.fromhex(plt_bytes)[:2], b'\xff\x25')
        off = int(rows[0][3], 16)
        self.image.data[off + 8] ^= 1
        try:
            with self.assertRaises(ValueError):
                m.relocation_rows(self.image)
        finally:
            self.image.data[off + 8] ^= 1
        self.flip(0x5660110, lambda: m.relocation_rows(self.image))

    def test_lsda_ranges_and_corruption(self):
        frame = self.image.fdes[0x1a94920]
        rows = m.lsda_rows(self.image, frame)
        self.assertEqual(len(rows), 10)
        self.assertIn(('0x1a95595', '0x1a955ac', '0x1a95632', 0, 'f51817921a00'), rows)
        off, _ = self.image.read(frame['lsda'], 1)
        self.image.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                m.lsda_rows(self.image, frame)
        finally:
            self.image.data[off] ^= 1
        self.image.data[off + 6] ^= 1
        try:
            with self.assertRaises(ValueError):
                m.lsda_rows(self.image, frame)
        finally:
            self.image.data[off + 6] ^= 1

    def test_moved_full_qword_not_only_low_byte(self):
        # The exact REX.W comparison is part of the checked instruction bytes.
        _, raw = self.image.read(0x1a94cac, 9, True)
        self.assertEqual(raw.hex(), '488b4c24284883f902')
        self.assertNotEqual(0x100000000000002, m.constants(self.image)['promoted_marker_test'])
        self.assertEqual(0x100000000000002 & 0xff, 2)


if __name__ == '__main__':
    unittest.main()
