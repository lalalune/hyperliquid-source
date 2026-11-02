"""Static, target-grounded controls for the node #94 staking-link evidence."""
import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import staking_link_wire94 as wire


class StakingLinkEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = wire.BINARY.read_bytes()
        cls.image = wire.Image(cls.data)
        cls.result = wire.collect(cls.data)

    def test_target_digest_and_selected_fde_ranges(self):
        self.assertEqual(wire.verify_digest(self.data), wire.SHA256)
        rows = self.result['functions']
        self.assertEqual(len(rows), 21)
        self.assertEqual(len({row['start_va'] for row in rows}), len(rows))
        for row in rows:
            self.assertGreater(int(row['end_va_exclusive'], 16), int(row['start_va'], 16))
            self.assertEqual(row['size'], int(row['end_va_exclusive'], 16) - int(row['start_va'], 16))

    def test_reject_wrong_artifact_digest(self):
        self.assertRaisesRegex(ValueError, 'SHA-256', wire.verify_digest, b'wrong node')
        broken = bytearray(self.data)
        broken[0] ^= 1
        self.assertRaisesRegex(ValueError, 'SHA-256', wire.verify_digest, broken)

    def test_fde_body_hash_rejects_changed_byte(self):
        row = self.result['functions'][0]
        body = bytearray(self.image.read(int(row['start_va'], 16), row['size'], True))
        self.assertEqual(wire.verify_body(body, row['sha256']), row['sha256'])
        body[len(body) // 2] ^= 1
        self.assertRaisesRegex(ValueError, 'body mismatch', wire.verify_body, body, row['sha256'])

    def test_tree_collector_size_guard_boundaries(self):
        guard = self.result['collector_allocation_guard']
        self.assertEqual(guard['item_size'], 16)
        self.assertEqual(guard['max_allocation'], 0x7ffffffffffffff8)
        largest = guard['largest_count']
        self.assertTrue(wire.collector_count_passes(0, guard))
        self.assertTrue(wire.collector_count_passes(largest, guard))
        self.assertFalse(wire.collector_count_passes(largest + 1, guard))
        self.assertFalse(wire.collector_count_passes(1 << 60, guard))
        self.assertFalse(wire.collector_count_passes((1 << 64) - 1, guard))
        self.assertRaises(ValueError, wire.collector_count_passes, -1, guard)
        self.assertRaises(ValueError, wire.collector_count_passes, 1 << 64, guard)

    def test_static_variant_names_and_payloads(self):
        self.assertEqual([(r['tag'], r['name'], r['payload_field']) for r in self.result['variants']], [
            (0, 'Requested', 'staking_user'),
            (1, 'TradingUser', 'staking_user'),
            (2, 'StakingUser', 'trading_user'),
        ])
        self.assertEqual([r['comparisons'] for r in self.result['variants']], [9, 11, 11])
        self.assertEqual([r['success_status'] for r in self.result['variants']], [9, 9, 9])
        self.assertEqual({r['unknown_target_va'] for r in self.result['variants']}, {'0x22f979f'})

    def test_reported_counts_are_selected_evidence_counts(self):
        counts = self.result['selected_record_counts']
        for key in ('functions', 'pins', 'calls', 'branches', 'references', 'indirect_calls', 'variants'):
            self.assertEqual(counts[key], len(self.result[key]))
        self.assertEqual(counts['variant_character_comparisons'], 31)

    def test_all_single_character_classifier_corruptions_are_detected(self):
        refs = self.result['references']
        for first, rest, _ in wire.CLASSIFIER:
            for address in (first,) + rest:
                char_offset = 2 if address == first else 3
                def mutated_read(va, size, executable=False, *, site=address, offset=char_offset):
                    original = self.image.read(va, size, executable)
                    if va == site:
                        changed = bytearray(original)
                        changed[offset] ^= 1
                        return bytes(changed)
                    return original
                with self.subTest(address=hex(address)):
                    altered = wire.classifier_rows(mutated_read)
                    self.assertRaisesRegex(ValueError, 'names differ', wire.check_variant_names, altered, refs)

    def test_classifier_wrong_opcode_and_short_or_extra_variant_list(self):
        def broken_opcode(va, size, executable=False):
            data = self.image.read(va, size, executable)
            if va == wire.CLASSIFIER[0][1][0]:
                return bytes([data[0] ^ 1]) + data[1:]
            return data
        self.assertRaisesRegex(ValueError, 'comparison mismatch', wire.classifier_rows, broken_opcode)
        refs, rows = self.result['references'], self.result['variants']
        self.assertRaises(ValueError, wire.check_variant_names, rows[:-1], refs)
        self.assertRaises(ValueError, wire.check_variant_names, rows + [rows[0]], refs)

    def test_classifier_every_compared_byte_is_significant(self):
        names = {row['name'].encode() for row in self.result['variants']}
        for name in names:
            for i in range(len(name)):
                variant = bytearray(name)
                variant[i] ^= 0x20
                self.assertNotIn(bytes(variant), names)
            self.assertNotIn(name[:-1], names)
            self.assertNotIn(name + b'x', names)
        self.assertNotIn(b'', names)

    def test_two_decoder_paths_and_duplicate_key_diagnostics(self):
        calls = {row['role']: row['target_va'] for row in self.result['calls']}
        self.assertEqual(calls['collection_map'], '0x264d420')
        self.assertEqual(calls['collection_sequence'], '0x2689420')
        self.assertEqual(calls['map_insert'], calls['sequence_insert'])
        self.assertEqual(self.result['duplicate_key_literals'], ['duplicate key', 'duplicate key'])
        self.assertEqual(wire.duplicate_literal(self.image.read, 0x264d5cf, 0x264d5dd), 'duplicate key')

    def test_tree_comparator_relocation_and_duplicate_branch(self):
        import_info = self.result['tree_comparator_import']
        self.assertEqual(import_info['symbol'], 'memcmp')
        self.assertEqual(import_info['slot_va'], '0x576e488')
        self.assertEqual(import_info['relocation_type'], 6)
        self.assertEqual(import_info, wire.imported_symbol(self.image, 0x576e488))
        self.assertRaisesRegex(ValueError, 'relocation slot', wire.imported_symbol, self.image, 0x576e489)
        edges = {row['role']: row['target_va'] for row in self.result['branches']}
        self.assertEqual(edges['tree_equal_key'], '0x2860ea2')

    def test_address_converter_relocation_and_slot_agree(self):
        converter = self.result['converter_relocation']
        self.assertEqual(converter['slot_va'], '0x5773120')
        self.assertEqual(converter['relocation_type'], 8)
        self.assertEqual(converter['addend_va'], '0x29ed380')
        uses = [entry for entry in self.result['indirect_calls'] if entry['role'].endswith('_converter')]
        self.assertEqual(len(uses), 2)
        self.assertTrue(all(entry['slot_va'] == converter['slot_va'] for entry in uses))
        self.assertRaises(ValueError, wire.relative_slot, self.image, 0x5773121)

    def test_each_payload_checks_names_width_and_error_branches(self):
        refs = {row['role']: row['text'] for row in self.result['references']}
        calls = {row['role']: row['target_va'] for row in self.result['calls']}
        branches = {row['role']: row['target_va'] for row in self.result['branches']}
        for name, base, _, _, field in wire.PAYLOAD_PATHS:
            with self.subTest(variant=name):
                self.assertEqual(refs[name + '_compare_prefix'] + refs[name + '_compare_suffix'], field)
                self.assertEqual(refs[name + '_missing_field'], field)
                self.assertEqual(refs[name + '_duplicate_field'], field)
                self.assertEqual(calls[name + '_payload_map_address'], calls[name + '_payload_sequence_address'])
                self.assertEqual(branches[name + '_payload_missing'], hex(base + 0xdfe))
                self.assertEqual(branches[name + '_payload_duplicate'], hex(base + 0x1a75))
                self.assertEqual(branches[name + '_payload_sequence_bad_size'], hex(base + 0x16c4))

    def test_payload_literal_pointer_corruption_is_rejected(self):
        for _, base, field_va, _, _ in wire.PAYLOAD_PATHS:
            site = base + 0x698
            def bad_pointer(va, size, executable=False, *, address=site):
                value = self.image.read(va, size, executable)
                if va == address:
                    changed = bytearray(value)
                    changed[-1] ^= 1
                    return bytes(changed)
                return value
            with self.subTest(address=hex(site)):
                self.assertRaisesRegex(ValueError, 'target mismatch', wire.checked_relative,
                                       bad_pointer, site, b'\x48\x33\x0d', field_va)

    def test_duplicate_key_message_corruption_is_rejected(self):
        for bad_offset in (2, 5, 9):
            def bad_immediate(va, size, executable=False, *, offset=bad_offset):
                value = self.image.read(va, size, executable)
                if va == 0x264d5cf:
                    altered = bytearray(value)
                    altered[offset] ^= 1
                    return bytes(altered)
                return value
            with self.subTest(offset=bad_offset):
                self.assertRaises(ValueError, wire.duplicate_literal, bad_immediate, 0x264d5cf, 0x264d5dd)

    def test_relative_calls_branches_and_corrupt_targets(self):
        for _, address, target in wire.CALLS:
            raw = wire.checked_relative(self.image.read, address, b'\xe8', target)
            self.assertEqual(len(raw), 5)
            self.assertRaises(ValueError, wire.checked_relative, self.image.read, address, b'\xe8', target + 1)
        for _, address, prefix, target in wire.BRANCHES:
            op = bytes.fromhex(prefix)
            size = 1 if len(op) == 1 else 4
            wire.checked_relative(self.image.read, address, op, target, size)
            self.assertRaises(ValueError, wire.checked_relative, self.image.read, address, op, target - 1, size)
        self.assertRaisesRegex(ValueError, 'opcode mismatch', wire.relative, self.image.read, wire.CALLS[0][1], b'\x90')

    def test_pin_corruption_is_rejected(self):
        _, address, text = wire.PINS[0]
        expected = bytes.fromhex(text)
        def bad_pin(va, size, executable=False):
            return b'\x00' + self.image.read(va, size, executable)[1:]
        self.assertRaisesRegex(ValueError, 'pin mismatch', wire.verify_pin, bad_pin, address, expected)

    def test_unmapped_negative_and_non_executable_addresses_are_rejected(self):
        self.assertRaises(ValueError, self.image.read, 0, 1)
        self.assertRaises(ValueError, self.image.read, -1, 1)
        self.assertRaises(ValueError, self.image.read, 0x3e0b6a, 21, True)
        self.assertRaises(ValueError, self.image.read, 0x3e0b6a, 0)

    def test_nobits_and_ambiguous_sections_are_never_read(self):
        fake = wire.Image.__new__(wire.Image)
        fake.data = b'0123456789'
        region = dict(type=8, flags=2, address=0x100, offset=0, size=10)
        fake.sections = [region]
        self.assertRaises(ValueError, fake.read, 0x100, 1)
        file_region = dict(region, type=1)
        fake.sections = [file_region, dict(file_region)]
        self.assertRaises(ValueError, fake.read, 0x100, 1)
        fake.sections = [file_region]
        self.assertEqual(fake.read(0x100, 10), b'0123456789')
        self.assertRaises(ValueError, fake.read, 0x109, 2)

    def test_writer_reader_name_agreement_rejects_mutations(self):
        refs = copy.deepcopy(self.result['references'])
        next(row for row in refs if row['role'] == 'tag_zero')['text'] = 'requested'
        self.assertRaisesRegex(ValueError, 'names differ', wire.check_variant_names, self.result['variants'], refs)
        outer = [r['text'] for r in self.result['references'] if r['role'] in ('outer_field', 'duplicate_field_name')]
        self.assertEqual(outer, ['user_to_staking_link2', 'user_to_staking_link2'])

    def test_deterministic_render_and_only_expected_files(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            wire.write_outputs(self.result, Path(first))
            wire.write_outputs(self.result, Path(second))
            left, right = Path(first), Path(second)
            names = sorted(p.name for p in left.iterdir())
            self.assertEqual(names, ['evidence.json', 'variants.tsv'])
            self.assertEqual(names, sorted(p.name for p in right.iterdir()))
            for name in names:
                self.assertEqual(hashlib.sha256((left / name).read_bytes()).digest(),
                                 hashlib.sha256((right / name).read_bytes()).digest())


if __name__ == '__main__':
    unittest.main()
