import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import staking_csigner_input94 as target


class CSignerInputTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(target.BINARY.read_bytes())
        cls.image = target.Image(cls.data)

    def test_hash_and_corrupted_input(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), target.SHA256)
        offset = self.image.offset(0x219d9e7)
        self.data[offset] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                target.authenticate(self.data)
        finally:
            self.data[offset] ^= 1

    def test_unbacked_and_invalid_ranges(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        for address, size in ((bss['address'], 1), (-1, 1), (0, 0), (2**64 - 1, 4)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(ValueError):
                    self.image.offset(address, size)

    def test_fde_functions_are_independently_bounded(self):
        _, rows = target.eh_frame_records(self.data, self.image.sections)
        by_start = {row['start']: row for row in rows}
        for _, start in target.FUNCTIONS:
            with self.subTest(start=hex(start)):
                f = by_start[start]
                self.assertGreater(f['end'], start)
                self.image.offset(start, f['end'] - start, executable=True)

    def test_name_extraction_from_comparison_immediates(self):
        boxed = target.extract_names(self.image, 'boxed_name')
        inline = target.extract_names(self.image, 'inline_name')
        fields = target.extract_names(self.image, 'field_name')
        self.assertEqual(boxed, ((b'unjailSelf', 0), (b'jailSelf', 0x100), (b'voteJail', 0x200)))
        self.assertEqual(inline, ((b'unjailSelf', 9), (b'jailSelf', 0x109), (b'voteJail', 0x209)))
        self.assertEqual(fields, ((b'signer', 0), (b'jail_until', 0x100)))
        for name, word in boxed:
            self.assertEqual(target.run_selector(self.image, False, name), word)
        for name, word in inline:
            self.assertEqual(target.run_selector(self.image, True, name), word)
        for name, word in fields:
            self.assertEqual(target.run_field_selector(self.image, name), word)
        with self.assertRaises(ValueError):
            target.extract_names(self.image, 'boxed_vote_map')

    def test_target_name_stores_and_near_misses(self):
        expected = ((b'unjailSelf', 0), (b'jailSelf', 1), (b'voteJail', 2))
        for inline in (False, True):
            for name, tag in expected:
                result = target.run_selector(self.image, inline, name)
                self.assertEqual(result, (tag << 8) | (9 if inline else 0))
                for i in range(len(name)):
                    for replacement in range(256):
                        if replacement == name[i]:
                            continue
                        changed = name[:i] + bytes([replacement]) + name[i + 1:]
                        self.assertIsNone(target.run_selector(self.image, inline, changed))
                    self.assertIsNone(target.run_selector(self.image, inline, name[:i] + name[i + 1:]))
                self.assertIsNone(target.run_selector(self.image, inline, name + b'x'))
        for value in (b'', b'UNJAILSELF', b'votejail', b'signer', b'jail_until'):
            self.assertIsNone(target.run_selector(self.image, False, value))
            self.assertIsNone(target.run_selector(self.image, True, value))

    def test_field_string_helper_near_misses(self):
        for value, word in ((b'signer', 0), (b'jail_until', 0x100)):
            self.assertEqual(target.run_field_selector(self.image, value), word)
            for i in range(len(value)):
                for replacement in range(256):
                    if replacement == value[i]:
                        continue
                    changed = value[:i] + bytes([replacement]) + value[i + 1:]
                    self.assertIsNone(target.run_field_selector(self.image, changed))
                self.assertIsNone(target.run_field_selector(self.image, value[:i] + value[i + 1:]))
            self.assertIsNone(target.run_field_selector(self.image, value + b'x'))

    def test_dispatch_matrix_against_independent_rules(self):
        for variant in (0, 1, 2):
            for tag in range(256):
                for length in (0, 1, 100):
                    if variant in (0, 1):
                        stem = 'unjail' if variant == 0 else 'jail'
                        accepted = tag in (0x12, 0x16) or (tag == 0x15 and length == 0)
                        expected = stem + ('_unit' if accepted else '_invalid')
                    else:
                        expected = {0x14: 'vote_sequence', 0x15: 'vote_map',
                                    0x16: 'vote_missing'}.get(tag, 'vote_invalid')
                    with self.subTest(variant=variant, tag=tag, length=length):
                        self.assertEqual(target.run_value_dispatch(self.image, variant, tag, length), expected)
        for args in ((3, 0, 0), (-1, 0, 0), (0, 256, 0), (0, 0, -1)):
            with self.assertRaises(ValueError):
                target.run_value_dispatch(self.image, *args)

    def test_field_names_and_projected_map_cases(self):
        image = self.image
        self.assertEqual(target.field_names(image), ('signer', 'jail_until'))
        def row(field, word=1, result='ok'):
            return field, result, word
        cases = (
            ([], 'missing_signer'),
            ([row('signer')], 'missing_jail_until'),
            ([row('jail_until')], 'missing_signer'),
            ([row('signer'), row('jail_until')], 'constructed_before_cleanup'),
            ([row('jail_until'), row('signer')], 'constructed_before_cleanup'),
            ([row('signer'), row('signer')], 'duplicate_signer'),
            ([row('signer'), row('signer', result='error')], 'duplicate_signer'),
            ([row('jail_until'), row('jail_until')], 'duplicate_jail_until'),
            ([row('jail_until'), row('jail_until', result='error')], 'duplicate_jail_until'),
            ([row('other')], 'unknown_field'),
            ([row('signer', result='error')], 'signer_error'),
            ([row('jail_until', result='error')], 'jail_until_error'),
            ([row('signer'), row('jail_until', 0)], 'missing_jail_until'),
            ([row('jail_until', 0), row('jail_until', 1), row('signer')], 'constructed_before_cleanup'),
        )
        for rows, expected in cases:
            with self.subTest(rows=rows):
                self.assertEqual(target.project_map(image, rows), expected)
        with self.assertRaises(ValueError):
            target.project_map(image, [row('jail_until', 2**32)])

    def test_envelope_projected_boundaries(self):
        cases = (
            ((0x0c, 0, 0, 0), 'direct_key'),
            ((0x0d, 0, 0, 0), 'direct_key'),
            ((0x14, 0, 0, 0), 'invalid_outer_content'),
            ((0x15, 0, 0, 0), 'missing_outer_key'),
            ((0x15, 1, 0x16, 0), 'missing_outer_key'),
            ((0x15, 1, 0x0c, 0), 'one_outer_entry'),
            ((0x15, 2, 0x0c, 0x0c), 'extra_outer_entry'),
            ((0x15, 2, 0x0c, 0x16), 'one_outer_entry'),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(target.project_envelope(self.image, *args), expected)
        with self.assertRaises(ValueError):
            target.project_envelope(self.image, 0x15, -1)

    def test_sequence_projected_helper_outcomes(self):
        cases = (
            (('ok', 'ok', 1, False), 'constructed_if_cleanup_returns'),
            (('missing', 'ok', 1, False), 'missing_first'),
            (('ok', 'missing', 1, False), 'missing_second'),
            (('error', 'ok', 1, False), 'first_helper_error'),
            (('ok', 'error', 1, False), 'second_helper_error'),
            (('ok', 'ok', 0, False), 'missing_second'),
            (('ok', 'ok', 1, True), 'extra_elements_path'),
        )
        for args, expected in cases:
            trace = []
            with self.subTest(args=args):
                self.assertEqual(target.project_sequence(self.image, *args, trace), expected)
                self.assertTrue(trace)
        with self.assertRaises(ValueError):
            target.project_sequence(self.image, 'bad', 'ok')

    def test_outer_action_handoff(self):
        for label, call_site, reader, error_site, store_site in (
            ('inline', 0x282ae59, 0x21b1c10, 0x282ae67, 0x282c164),
            ('boxed', 0x282d72d, 0x21b28d0, 0x282d73b, 0x282e9cd),
        ):
            with self.subTest(label=label):
                _, raw = self.image.window(label + '_handoff')
                self.assertEqual(target.branch(self.image, call_site, 'call')[1], reader)
                self.assertGreater(target.branch(self.image, error_site, 'jne')[1], error_site)
                self.assertEqual(raw[13:22], bytes.fromhex('488d4308807c242000'))
                self.assertEqual(raw[28:35], bytes.fromhex('8b4c2444894820'))
                self.assertEqual(raw[35:52], bytes.fromhex('0f104424240f104c24340f1148100f1100'))
                self.assertEqual(raw[52:57], bytes.fromhex('b8b0000000'))
                self.assertEqual(target.branch(self.image, call_site + 49, 'jmp')[1], store_site)
                self.assertEqual(self.image.window(label + '_store_action_tag')[1], bytes.fromhex('488903'))

    def test_calls_and_failure_branches(self):
        expected = {
            0x21b2b61: ('call', 0x219d9e0),
            0x21b1ee8: ('call', 0x219db60),
            0x21b2f46: ('call', 0x1f24320),
            0x21b2f88: ('call', 0x1f4ea40),
            0x1f244b4: ('call', 0x2162820),
            0x1f244d6: ('jne', 0x1f24723),
            0x1f24555: ('jne', 0x1f2476b),
            0x1f245bd: ('je', 0x1f24626),
            0x1f245c5: ('je', 0x1f246be),
            0x1f4ec34: ('jne', 0x1f4ec48),
        }
        for site, (kind, destination) in expected.items():
            with self.subTest(site=hex(site)):
                self.assertEqual(target.branch(self.image, site, kind)[1], destination)
        with self.assertRaises(ValueError):
            target.branch(self.image, 0x21b2f46, 'jne')

    def test_jump_table_corruption_is_out_of_range(self):
        base = 0x3cfa0c
        start, end = 0x21b28d0, 0x21b31b3
        rows = target.jump_table(self.image, base, start, end)
        self.assertEqual(len(rows), 15)
        self.assertEqual(rows[0][3], 0x21b2ac0)
        with self.assertRaises(ValueError):
            target.jump_table(self.image, base, end, start)
        offset = self.image.offset(base, 4)
        original = self.data[offset:offset + 4]
        self.data[offset:offset + 4] = bytes.fromhex('ffffff7f')
        try:
            with self.assertRaisesRegex(ValueError, 'outside associated FDE'):
                target.jump_table(self.image, base, start, end)
        finally:
            self.data[offset:offset + 4] = original

    def test_instruction_corruption_fails_closed(self):
        for window_name, addr in (('boxed_name', 0x219d9e7),
                                  ('boxed_value_dispatch', 0x21b2e6a),
                                  ('boxed_vote_map', 0x1f244d6),
                                  ('boxed_field_reader', 0x21628a5)):
            offset = self.image.offset(addr)
            self.data[offset] ^= 1
            try:
                with self.subTest(window=window_name):
                    with self.assertRaisesRegex(ValueError, 'window mismatch'):
                        self.image.window(window_name)
            finally:
                self.data[offset] ^= 1
        offset = self.image.offset(0x1f244d6)
        self.data[offset] = 0x90
        try:
            with self.assertRaisesRegex(ValueError, 'unexpected branch'):
                target.branch(self.image, 0x1f244d6, 'jne')
        finally:
            self.data[offset] = 0x0f


if __name__ == '__main__':
    unittest.main()
