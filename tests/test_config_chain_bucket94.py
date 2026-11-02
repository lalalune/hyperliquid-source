"""Controls for the digest-bound chain-keyed configuration collector."""
import copy
import struct
import tempfile
import unittest
from pathlib import Path

from tools import config_chain_bucket94 as subject


class PatchedImage:
    """An in-memory view; never modify the pinned binary or shared sections."""

    def __init__(self, base, patches=(), relocations=None, fde_ends=None, symbols=None):
        self.base = base
        self.patches = tuple(patches)
        self.relocation_overrides = relocations or {}
        self.fde_ends = fde_ends or {}
        if symbols is not None:
            self.symbols = dict(base.symbols)
            self.symbols.update(symbols)

    def __getattr__(self, name):
        return getattr(self.base, name)

    def read(self, address, size):
        data = bytearray(self.base.read(address, size))
        for patch_address, patch in self.patches:
            first = max(address, patch_address)
            end = min(address + size, patch_address + len(patch))
            if first < end:
                data[first - address:end - address] = patch[first - patch_address:end - patch_address]
        return bytes(data)

    def relative(self, slot):
        if slot in self.relocation_overrides:
            if self.relocation_overrides[slot] is None:
                raise subject.EvidenceError('missing test relocation')
            return self.relocation_overrides[slot]
        return self.base.relative(slot)

    def fde(self, address):
        fde = dict(self.base.fde(address))
        if address in self.fde_ends:
            fde['end'] = self.fde_ends[address]
        return fde


class ChainBucketEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.Image(subject.TARGET.read_bytes())
        cls.result = subject.collect(cls.image)

    def test_authenticated_identity_is_mandatory(self):
        with self.assertRaisesRegex(subject.EvidenceError, 'digest mismatch'):
            subject.Image(b'not the pinned node')

    def test_corrupted_full_sized_identity_is_rejected(self):
        # Change one byte without copying the target to a writable fixture.
        original = self.image.data
        corrupted = original[:-1] + bytes([original[-1] ^ 1])
        with self.assertRaisesRegex(subject.EvidenceError, 'digest mismatch'):
            subject.Image(corrupted)

    def test_all_selected_extents_and_instruction_partitions(self):
        self.assertEqual(len(self.result['functions']), 12)
        self.assertEqual(len(self.result['instructions']), 2393)
        for function in self.result['functions']:
            rows = [r for r in self.result['instructions'] if r['function'] == function['entry']]
            cursor = function['entry']
            for row in rows:
                self.assertEqual(row['va'], cursor)
                self.assertEqual(bytes.fromhex(row['bytes']), self.image.read(cursor, row['size']))
                cursor += row['size']
            self.assertEqual(cursor, function['end'])
            self.assertEqual(function['end'], self.image.fde(function['entry'])['end'])

    def test_file_range_requires_allocated_file_backing(self):
        bss = next(section for section in self.image.sections if section['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        for address, size in ((bss['address'], 1), (-1, 1), (0, 0), (1 << 50, 1)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(subject.EvidenceError):
                    self.image.offset(address, size)

    def test_range_crossing_a_section_end_is_rejected(self):
        section = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(section['address'] + section['size'] - 1, 2)

    def test_changed_fde_end_is_rejected(self):
        altered = PatchedImage(self.image, fde_ends={0x14ba930: 0x14baf86})
        with self.assertRaisesRegex(subject.EvidenceError, 'FDE extent'):
            subject.collect(altered, check_body_hashes=False)

    def test_closed_decoder_rejects_truncation_and_interior_target(self):
        for body in (b'\xe8\x01', b'\x75\xff', b'\x0f'):
            with self.subTest(body=body.hex()):
                with self.assertRaises(subject.EvidenceError):
                    subject.decode(body, 0x1000)

    def test_rip_relative_target_uses_instruction_end(self):
        row = subject.decode(bytes.fromhex('488d05fbffffff'), 0x1000)[0]
        self.assertEqual(row['memory_va'], 0x1002)
        self.assertEqual(row['size'], 7)

    def test_classifier_exact_names_and_codes(self):
        names = [row['text'].encode('ascii') for row in self.result['names']]
        self.assertEqual(names, [b'Local', b'Sandbox', b'Testnet', b'Mainnet'])
        for index, name in enumerate(names):
            self.assertEqual(subject.classify_name(names, name), index)
            self.assertIsNone(subject.classify_name(names, name + b'x'))
            self.assertIsNone(subject.classify_name(names, name[:-1]))
        with self.assertRaises(ValueError):
            subject.classify_name(names, 'Local')

    def test_classifier_rejects_every_single_bit_name_mutation(self):
        names = [row['text'].encode('ascii') for row in self.result['names']]
        checked = 0
        for name in names:
            for pos in range(len(name)):
                for bit in range(8):
                    changed = name[:pos] + bytes([name[pos] ^ (1 << bit)]) + name[pos + 1:]
                    self.assertIsNone(subject.classify_name(names, changed))
                    checked += 1
        self.assertEqual(checked, 208)

    def test_classifier_immediate_and_descriptor_must_agree(self):
        patched = PatchedImage(self.image, patches=((0x13f41b0, b'Z'),))
        with self.assertRaisesRegex(subject.EvidenceError, 'classifier immediates'):
            subject.collect(patched, check_body_hashes=False)

    def test_name_descriptor_relocation_is_checked(self):
        descriptor = self.result['names'][0]
        patched = PatchedImage(self.image, relocations={descriptor['slot_va']: 1 << 50})
        with self.assertRaises(subject.EvidenceError):
            subject.collect(patched, check_body_hashes=False)

    def test_full_name_slice_and_length_are_checked(self):
        descriptor = self.result['names'][0]
        raw = self.image.read(descriptor['slot_va'], 16)
        self.assertEqual(raw.hex(), descriptor['slot_bytes'])
        self.assertEqual(struct.unpack_from('<Q', raw, 8)[0], len(b'Local'))
        relocation = bytes.fromhex(descriptor['rela_bytes'])
        self.assertEqual(struct.unpack('<QQq', relocation),
                         (descriptor['slot_va'], 8, descriptor['text_va']))
        bad_length = PatchedImage(self.image, patches=((descriptor['slot_va'] + 8, b'\x00'),))
        with self.assertRaisesRegex(subject.EvidenceError, 'invalid string slice length'):
            subject.collect(bad_length, check_body_hashes=False)
        bad_text = PatchedImage(self.image, patches=((descriptor['text_va'], b'X'),))
        with self.assertRaisesRegex(subject.EvidenceError, 'classifier immediates'):
            subject.collect(bad_text, check_body_hashes=False)

    def test_fresh_marker_classes_cover_byte_boundaries(self):
        cases = {0x00: 0x00, 0x7f: 0x00, 0x80: 0x80, 0x8f: 0x80,
                 0x90: 0x90, 0x9f: 0x90, 0xa0: 0xa0, 0xbf: 0xa0,
                 0xc0: 0xc0, 0xc1: 0xc1, 0xdf: 0xdf, 0xe0: 0xe0, 0xff: 0xe0}
        for raw, expected in cases.items():
            self.assertEqual(subject.normalized_marker(raw), expected)
        self.assertEqual(len(self.result['marker_cases']), 256)
        null = self.result['marker_cases'][0xc0]
        self.assertTrue(null['option_null'])
        self.assertIsNone(null['map_table_target'])
        self.assertEqual(null['payload_mode'], 'unused_null')
        for raw, mode, value in ((0x7f, 'raw_byte', 0x7f),
                                 (0x8f, 'low_four_bits', 0x0f),
                                 (0x9f, 'low_four_bits', 0x0f),
                                 (0xbf, 'low_five_bits', 0x1f),
                                 (0xc1, 'previous_cached_byte', None),
                                 (0xdf, 'previous_cached_byte', None),
                                 (0xe0, 'raw_byte', 0xe0)):
            row = self.result['marker_cases'][raw]
            self.assertEqual((row['payload_mode'], row['payload_value']), (mode, value))
        for raw in (-1, 256, True, '1'):
            with self.assertRaises(ValueError):
                subject.normalized_marker(raw)

    def test_marker_threshold_byte_corruption_is_rejected(self):
        patched = PatchedImage(self.image, patches=((0x13aa550, b'\xde'),))
        with self.assertRaisesRegex(subject.EvidenceError, 'marker-high-threshold'):
            subject.collect(patched, check_body_hashes=False)

    def test_jump_tables_use_only_selected_instruction_starts(self):
        tables = self.result['tables']
        counts = {}
        for row in tables:
            counts[row['table']] = counts.get(row['table'], 0) + 1
        self.assertEqual(counts, {'binary-marker': 225, 'binary-marker-secondary': 18,
                                  'binary-value-marker': 225, 'binary-value-secondary': 18,
                                  'binary-value-normalized': 32,
                                  'json-quoted-name': 4, 'json-unit': 4, 'binary-unit': 4})
        patched = PatchedImage(self.image, patches=((self.result['marker_base'], struct.pack('<i', 4)),))
        with self.assertRaisesRegex(subject.EvidenceError, 'table target'):
            subject.collect(patched, check_body_hashes=False)

    def test_quote_table_must_preserve_classifier_codes(self):
        slots = [r for r in self.result['tables'] if r['table'] == 'json-quoted-name']
        base = slots[0]['slot']
        wrong_but_aligned = struct.pack('<i', slots[1]['target'] - base)
        patched = PatchedImage(self.image, patches=((base, wrong_but_aligned),))
        with self.assertRaisesRegex(subject.EvidenceError, 'quote dispatch'):
            subject.collect(patched, check_body_hashes=False)

    def test_global_policy_boundaries(self):
        policy = self.result['policy']
        self.assertEqual(policy, {5: 2, 17: 3})
        for byte in range(256):
            expected = 2 if byte == 5 else 3 if byte == 17 else None
            self.assertEqual(subject.selected_key(policy, byte), expected)
        for value in (-1, 256, True, '5'):
            with self.assertRaises(ValueError):
                subject.selected_key(policy, value)

    def test_global_compare_corruption_is_rejected(self):
        patched = PatchedImage(self.image, patches=((0x1404f0f, b'\x06'),))
        with self.assertRaisesRegex(subject.EvidenceError, 'global-name-test-first'):
            subject.collect(patched, check_body_hashes=False)

    def test_global_miss_branches_share_absent_target(self):
        rows = {row['va']: row for row in self.result['instructions']}
        for address, kind in ((0x1404f15, 'jne'), (0x1404f84, 'jne'),
                              (0x1404f91, 'je'), (0x1405007, 'jb')):
            self.assertEqual((rows[address]['kind'], rows[address]['target']), (kind, 0x14050ac))
        patched = PatchedImage(self.image, patches=((0x1404f85, b'\x84'),))
        with self.assertRaisesRegex(subject.EvidenceError, 'global-map-absent-branch'):
            subject.collect(patched, check_body_hashes=False)

    def test_missing_and_retargeted_global_relocations_fail(self):
        for target in (None, 0x577b289):
            patched = PatchedImage(self.image, relocations={0x576e928: target})
            with self.subTest(target=target):
                with self.assertRaises(subject.EvidenceError):
                    subject.collect(patched, check_body_hashes=False)

    def test_lookup_entry_slot_binding_is_checked(self):
        patched = PatchedImage(self.image, relocations={0x576efe8: 0x1404ef1})
        with self.assertRaisesRegex(subject.EvidenceError, 'lookup entry addend'):
            subject.collect(patched, check_body_hashes=False)

    def test_copy_import_and_allocator_boundary_are_checked(self):
        copy = next(r for r in self.result['indirect_slots'] if r['site'] == 0x140504c)
        self.assertEqual((copy['relocation_type'], copy['symbol']), ('GLOB_DAT', 'memcpy'))
        patched = PatchedImage(self.image, symbols={0x576dfe0: (0, 'wrong_name')})
        with self.assertRaisesRegex(subject.EvidenceError, 'copy import binding'):
            subject.collect(patched, check_body_hashes=False)
        patched = PatchedImage(self.image, relocations={0x576dfd8: 0x54c06b1})
        with self.assertRaisesRegex(subject.EvidenceError, 'allocation boundary'):
            subject.collect(patched, check_body_hashes=False)

    def test_duplicate_cleanup_target_and_common_slot_are_checked(self):
        patched = PatchedImage(self.image, relocations={0x576e010: 0x54c8cb1})
        with self.assertRaisesRegex(subject.EvidenceError, 'duplicate-value cleanup target'):
            subject.collect(patched, check_body_hashes=False)

    def test_binary_key_map_lengths_and_truncation(self):
        for marker in range(0x80, 0x90):
            row = subject.model_binary_key_gate(bytes([marker]))
            self.assertEqual(row['count'], marker & 15)
            self.assertEqual(row['outcome'], 'call_unit_reader' if marker == 0x81 else 'length_error_tag_4')
        for prefix in (b'\xde\x00\x01', b'\xdf\x00\x00\x00\x01'):
            row = subject.model_binary_key_gate(prefix)
            self.assertEqual((row['count'], row['prefix_consumed'], row['outcome']),
                             (1, len(prefix), 'call_unit_reader'))
        for prefix, expected in ((b'\xde\x01\x00', 256),
                                 (b'\xdf\x00\x01\x00\x00', 65536)):
            row = subject.model_binary_key_gate(prefix)
            self.assertEqual((row['count'], row['outcome']), (expected, 'length_error_tag_4'))
        for prefix in (b'\xde', b'\xde\x00', b'\xdf', b'\xdf\x00',
                       b'\xdf\x00\x00', b'\xdf\x00\x00\x00'):
            row = subject.model_binary_key_gate(prefix)
            self.assertEqual(row['prefix_consumed'], len(prefix))
            self.assertEqual(row['outcome'], 'truncated_delegate_scalar')
        self.assertEqual(subject.model_binary_key_gate(b'')['outcome'], 'eof_tag_0')
        self.assertEqual(subject.model_binary_key_gate(b'\xc0')['outcome'], 'delegate_scalar')
        with self.assertRaises(ValueError):
            subject.model_binary_key_gate('not bytes')

    def test_binary_value_prefix_boundaries_and_cursor(self):
        cases = ((b'', 'fresh_eof', 0, None, 'eof_tag_0'),
                 (b'\xa0', 'fixed_string', 1, 0, 'slice_check_boundary'),
                 (b'\xa2a', 'fixed_string', 1, 2, 'short_payload_tag_1'),
                 (b'\xa2ab', 'fixed_string', 3, 2, 'slice_check_boundary'),
                 (b'\xd9\x01a', 'string', 3, 1, 'slice_check_boundary'),
                 (b'\xda\x00', 'string', 2, None, 'short_length_tag_1'),
                 (b'\xda\x01\x00', 'string', 3, 256, 'short_payload_tag_1'),
                 (b'\xdb\xff\xff\xff\xff', 'string', 5, 4294967295, 'short_payload_tag_1'),
                 (b'\xc4\x01a', 'bytes', 3, 1, 'value_builder_boundary'),
                 (b'\xc5\x00\x02a', 'bytes', 3, 2, 'short_payload_tag_1'),
                 (b'\xc5\x00\x02ab', 'bytes', 5, 2, 'value_builder_boundary'))
        for data, form, cursor, length, outcome in cases:
            with self.subTest(data=data):
                row = subject.model_binary_value_prefix(data)
                self.assertEqual((row['form'], row['cursor'], row['length'], row['outcome']),
                                 (form, cursor, length, outcome))
        with self.assertRaises(ValueError):
            subject.model_binary_value_prefix('not bytes')

    def test_binary_value_table_and_short_branch_corruption_fail(self):
        patched = PatchedImage(self.image, patches=((0x214054, struct.pack('<i', 4)),))
        with self.assertRaisesRegex(subject.EvidenceError, 'table target'):
            subject.collect(patched, check_body_hashes=False)
        patched = PatchedImage(self.image, patches=((0x13bdeef, b'\x83'),))
        with self.assertRaises(subject.EvidenceError):
            subject.collect(patched, check_body_hashes=False)

    def test_json_key_guard_corruption_is_rejected(self):
        patched = PatchedImage(self.image, patches=((0x14baad2, b"'"),))
        with self.assertRaisesRegex(subject.EvidenceError, 'json-map-key-quote'):
            subject.collect(patched, check_body_hashes=False)

    def test_json_optional_null_and_failures(self):
        for data, outcome, cursor, tag in (
                (b'null', 'null', 4, 0), (b' \tnullx', 'null', 6, 0),
                (b'n', 'truncated_null_code_5', 1, 2),
                (b'nu', 'truncated_null_code_5', 2, 2),
                (b'nul', 'truncated_null_code_5', 3, 2),
                (b'nX', 'invalid_null_code_9', 2, 2),
                (b'nuX', 'invalid_null_code_9', 3, 2),
                (b'nulX', 'invalid_null_code_9', 4, 2),
                (b'  {}', 'delegate_map', 2, None),
                (b'\vnull', 'delegate_map', 0, None)):
            with self.subTest(data=data):
                row = subject.model_json_option_prefix(data)
                self.assertEqual((row['outcome'], row['cursor'], row['local_tag']),
                                 (outcome, cursor, tag))
        with self.assertRaises(ValueError):
            subject.model_json_option_prefix('null')

    def test_json_optional_literal_byte_corruption_is_rejected(self):
        patched = PatchedImage(self.image, patches=((0x1441c3e, b'v'),))
        with self.assertRaisesRegex(subject.EvidenceError, 'json-option-second-u'):
            subject.collect(patched, check_body_hashes=False)

    def test_local_cfg_distinguishes_binary_and_json_error_paths(self):
        paths = {r['label']: r for r in self.result['control_flow']}
        self.assertTrue(paths['binary_key_error_bypasses_depth_restore']['reachable'])
        self.assertTrue(paths['binary_value_error_bypasses_depth_restore']['reachable'])
        self.assertFalse(paths['json_key_error_requires_depth_restore']['reachable'])
        self.assertFalse(paths['json_value_error_requires_depth_restore']['reachable'])
        self.assertFalse(paths['binary_key_error_requires_map_drop']['reachable'])
        self.assertFalse(paths['binary_value_error_requires_map_drop']['reachable'])

    def test_cfg_rejects_changed_error_and_duplicate_jumps(self):
        for address, target in ((0x13b8b61, 0x13b8be6), (0x14cbc31, 0x14cbd07)):
            changed = copy.deepcopy(self.result)
            row = next(r for r in changed['instructions'] if r['va'] == address)
            row['target'] = target
            with self.subTest(address=address):
                with self.assertRaisesRegex(subject.EvidenceError, 'CFG proposition'):
                    subject.control_flow(changed)

    def test_exception_ranges_and_changed_header(self):
        sites = self.result['exception_sites']
        self.assertEqual(len(sites), 42)
        self.assertEqual(len(self.result['lsda_headers']), 5)
        self.assertEqual({r['function'] for r in sites},
                         {0x13aa2f0, 0x13b8610, 0x13bdcd0, 0x14ba930, 0x14cbb80})
        patched = PatchedImage(self.image, patches=((0x91ea18, b'\x00'),))
        with self.assertRaisesRegex(subject.EvidenceError, 'LSDA landing-pad base'):
            subject.collect(patched, check_body_hashes=False)

    def test_exception_callsite_outside_extent_is_rejected(self):
        # The first map call-site starts at offset zero. Increase it so that it
        # cannot describe a valid in-FDE, ordered instruction range.
        patched = PatchedImage(self.image, patches=((0x91ea1d, b'\x01'),))
        with self.assertRaises(subject.EvidenceError):
            subject.collect(patched, check_body_hashes=False)

    def test_generated_files_are_stable_and_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / 'a', Path(temporary) / 'b'
            one = subject.write_outputs(self.result, first)
            two = subject.write_outputs(self.result, second)
            self.assertEqual(one, two)
            expected = {'functions.tsv', 'instructions.tsv', 'branches.tsv', 'calls.tsv',
                        'stores.tsv', 'contracts.tsv', 'tables.tsv', 'names.tsv',
                        'relocations.tsv', 'marker-cases.tsv', 'lookup-cases.tsv',
                        'binary-key-prefix-cases.tsv', 'indirect-slots.tsv',
                        'json-option-prefix-cases.tsv', 'binary-value-prefix-cases.tsv',
                        'cfg-propositions.tsv', 'exception-sites.tsv', 'lsda-headers.tsv',
                        'evidence.json'}
            self.assertEqual({p.name for p in first.iterdir()}, expected)
            for name in expected:
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
