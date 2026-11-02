import hashlib
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from tools import validator_config94 as research


class Overlay:
    """Present modified bytes to a selected byte reader, without copying the ELF."""
    def __init__(self, view, changes):
        self.base = view
        self.changes = changes
        self.sections = view.sections
        self.data = view.data

    def offset(self, va, size):
        return self.base.offset(va, size)

    def read(self, va, size):
        raw = bytearray(self.base.read(va, size))
        for address, replacement in self.changes.items():
            if va <= address < va + size:
                raw[address - va] = replacement
        return bytes(raw)


class ValidatorConfig94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = research.TARGET.read_bytes()
        research.verify_identity(cls.data)
        cls.view = research.View(cls.data)
        _, fdes = research.eh_frame_records(cls.data, cls.view.sections)
        cls.fdes = {row['start']: row for row in fdes}
        cls.groups = {}
        cls.decoded = {}
        for role, begin, end in research.FUNCTIONS:
            rows = research.decode_body(cls.view.read(begin, end - begin), begin)
            cls.groups[begin] = rows
            cls.decoded.update({row['va']: row for row in rows})
        cls.spec = research.field_spec(cls.view, cls.decoded)
        cls.loader = research.load_spec(cls.view, cls.decoded)
        cls.result = research.collect(cls.data)

    def test_authentic_target_hash_and_size(self):
        self.assertEqual(len(self.data), 91774280)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), research.DIGEST)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.verify_identity(self.data, '0' * 64)

    def test_corrupted_target_byte_rejected(self):
        damaged = bytearray(self.data)
        damaged[12345] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.verify_identity(damaged)

    def test_truncated_target_rejected(self):
        with self.assertRaisesRegex(ValueError, 'size'):
            research.verify_identity(self.data[:4096])

    def test_fde_extents_are_exact(self):
        for _, begin, end in research.FUNCTIONS:
            self.assertEqual(self.fdes[begin]['end'], end)

    def test_missing_fde_rejected(self):
        with patch.object(research, 'eh_frame_records', return_value=({}, [])):
            with self.assertRaisesRegex(ValueError, 'FDE extent'):
                research.collect(self.data)

    def test_body_partition_is_contiguous(self):
        for _, begin, end in research.FUNCTIONS:
            rows = self.groups[begin]
            self.assertEqual(rows[0]['va'], begin)
            self.assertEqual(rows[-1]['end'], end)
            for previous, current in zip(rows, rows[1:]):
                self.assertEqual(previous['end'], current['va'])

    def test_truncated_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, 'truncated'):
            research.decode_body(b'\xe8\x01', 0x1000)

    def test_branch_to_middle_of_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, 'branch into'):
            research.decode_body(b'\x75\xff', 0x1000)

    def test_unsupported_encoding_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            research.decode_body(b'\x0f\x0f', 0x1000)

    def test_cfg_queries_and_exclusion_controls(self):
        rows = {row['label']: row for row in research.checked_cfg(self.groups)}
        self.assertEqual(len(rows), 24)
        self.assertEqual(rows['loader_text_parse']['reachable'], 1)
        self.assertEqual(rows['text_without_reader']['reachable'], 0)
        self.assertEqual(rows['fresh_binary_without_key']['reachable'], 0)

    def test_cfg_rejects_non_instruction_boundary(self):
        rows = research.decode_body(b'\x75\x01\x90\xc3', 0x1000)
        with self.assertRaisesRegex(ValueError, 'instruction boundary'):
            research.reachable(rows, 0x1001, 0x1003)

    def test_contracts_cover_all_selected_witnesses(self):
        self.assertEqual(len(research.checked_spans(self.view, self.decoded)), 52)

    def test_changed_branch_bytes_rejected(self):
        address = 0x1cfddfa
        changed = Overlay(self.view, {address: self.view.read(address, 1)[0] ^ 1})
        with self.assertRaisesRegex(ValueError, 'witness bytes'):
            research.checked_spans(changed, self.decoded)

    def test_changed_key_buffer_contract_rejected(self):
        address = 0x1cfdfc0
        changed = Overlay(self.view, {address: self.view.read(address, 1)[0] ^ 1})
        with self.assertRaisesRegex(ValueError, 'witness bytes'):
            research.checked_spans(changed, self.decoded)

    def test_changed_prior_handoff_rejected(self):
        address = 0x222dbf4
        changed = Overlay(self.view, {address: self.view.read(address, 1)[0] ^ 1})
        with self.assertRaisesRegex(ValueError, 'witness bytes'):
            research.checked_spans(changed, self.decoded)

    def test_unbacked_nobits_mapping_rejected(self):
        row = {'name': '.bss', 'type': 8, 'flags': 2, 'address': 0x1000, 'offset': 0, 'size': 32}
        view = research.View(bytes(32), [row])
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            view.read(0x1000, 1)

    def test_ambiguous_mapping_rejected(self):
        row = {'name': 'a', 'type': 1, 'flags': 2, 'address': 0x1000, 'offset': 0, 'size': 32}
        view = research.View(bytes(32), [row, dict(row, name='b')])
        with self.assertRaisesRegex(ValueError, 'unique'):
            view.read(0x1000, 1)

    def test_range_edges_rejected(self):
        for address, size in ((-1, 1), (0, 0), ((1 << 64) - 1, 2), (0, 1)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(ValueError):
                    self.view.read(address, size)

    def test_duplicate_relocation_is_rejected(self):
        record = struct.pack('<QQq', 0x1000, 8, 0x1234)
        data = record + record + bytes(24) + b'\0'
        fake = type('Fake', (), {'data': data, 'sections': [
            {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 48},
            {'name': '.dynsym', 'type': 11, 'offset': 48, 'size': 24},
            {'name': '.dynstr', 'type': 3, 'offset': 72, 'size': 1},
        ]})()
        with patch.object(research, 'REQUIRED_RELOCS', {}):
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                research.parse_relocations(fake, {0x1000})

    def test_relocation_target_change_rejected(self):
        record = struct.pack('<QQq', 0x1000, 8, 0x1235)
        fake = type('Fake', (), {'data': record + bytes(24) + b'\0', 'sections': [
            {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 24},
            {'name': '.dynsym', 'type': 11, 'offset': 24, 'size': 24},
            {'name': '.dynstr', 'type': 3, 'offset': 48, 'size': 1},
        ]})()
        with patch.object(research, 'REQUIRED_RELOCS', {0x1000: (8, 0x1234)}):
            with self.assertRaisesRegex(ValueError, 'required relocation'):
                research.parse_relocations(fake, {0x1000})

    def test_bad_lsda_encoding_rejected(self):
        row = {'name': '.gcc_except_table', 'type': 1, 'flags': 2, 'address': 0x2000, 'offset': 0, 'size': 4}
        fake = research.View(b'\x00\xff\x01\x00', [row])
        with self.assertRaisesRegex(ValueError, 'unsupported LSDA'):
            research.parse_lsda(fake, 0x1000, 0x1005, 0x2000)

    def test_template_is_complete(self):
        self.assertEqual(self.loader['template'], bytes.fromhex(
            'c0222f68797065726c69717569645f646174612f6e6f64655f636f6e6669672e6a736f6e00'))
        self.assertEqual([part['kind'] for part in self.loader['template_parts']], ['argument', 'literal'])

    def test_malformed_template_rejected(self):
        for value in (b'\xc0\x03ab', b'\xc0\x01x\x00z', b'\x80\x00'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    research.parse_template(value)

    def test_changed_limit_diagnostic_rejected(self):
        changed = Overlay(self.view, {0x70693e: ord('s')})
        with self.assertRaisesRegex(ValueError, 'data anchor changed'):
            research.data_records(changed, self.spec, self.loader)

    def test_validator_sequence_metadata_has_relocated_length_pair(self):
        self.assertEqual(self.view.read(0x568a3c0, 8), struct.pack('<Q', 38))
        relocs = research.parse_relocations(self.view, set(research.REQUIRED_RELOCS))
        self.assertEqual(int(relocs[0x568a3b8]['addend'], 16), 0x3b8af9)
        self.assertEqual(self.decoded[0x1cfe5db]['target'], 0x568a3b8)

    def test_full_pool_and_field_bytes(self):
        self.assertEqual((self.spec['key'], self.spec['sentry']), (b'key', b'sentry_ips'))
        self.assertEqual(research.classify_field(b'key', self.spec), 'key')
        self.assertEqual(research.classify_field(b'sentry_ips', self.spec), 'sentry_ips')
        self.assertEqual(research.classify_field(b'node_ip', self.spec), 'unknown')

    def test_all_single_bit_field_mutations_are_unknown(self):
        for value in (b'key', b'sentry_ips'):
            for position in range(len(value)):
                for bit in range(8):
                    changed = bytearray(value)
                    changed[position] ^= 1 << bit
                    self.assertEqual(research.classify_field(bytes(changed), self.spec), 'unknown')

    def test_field_length_and_case_negatives(self):
        for value in (b'', b'Key', b'keyx', b'ke', b'sentry_ip', b'sentry_ipsx', b'Sentry_ips'):
            with self.subTest(value=value):
                self.assertEqual(research.classify_field(value, self.spec), 'unknown')

    def test_changed_field_comparison_bytes_rejected(self):
        changed = Overlay(self.view, {0x3d2871: ord('K')})
        with self.assertRaisesRegex(ValueError, 'field comparison'):
            research.field_spec(changed, self.decoded)

    def test_changed_field_length_rejected(self):
        changed = Overlay(self.view, {0x1cfddc8: 4})
        with self.assertRaisesRegex(ValueError, 'field comparison'):
            research.field_spec(changed, self.decoded)

    def test_event_order_and_duplicate_controls(self):
        cases = [([], 'missing_key'), ([b'sentry_ips'], 'missing_key'),
                 ([b'key'], 'selected'), ([b'sentry_ips', b'key'], 'selected'),
                 ([b'key', b'sentry_ips'], 'selected'),
                 ([b'key', b'key'], 'duplicate_key'),
                 ([b'key', b'sentry_ips', b'sentry_ips'], 'duplicate_sentry_ips'),
                 ([b'other', b'key'], 'selected')]
        for values, expected in cases:
            with self.subTest(values=values):
                self.assertEqual(research.model_field_events(values, self.spec), expected)

    def test_sentry_count_boundaries(self):
        for count in (0, 1, 2):
            self.assertEqual(research.model_sentry_count(count, self.spec), 'accepted_by_count_gate')
        for count in (3, 4, 100):
            self.assertEqual(research.model_sentry_count(count, self.spec), 'too_many')

    def test_invalid_sentry_counts_rejected(self):
        for count in (-1, True, 1.0, '2'):
            with self.subTest(count=count):
                with self.assertRaises(ValueError):
                    research.model_sentry_count(count, self.spec)

    def test_changed_sentry_cap_rejected(self):
        changed = Overlay(self.view, {0x21c28ee: 4})
        with self.assertRaisesRegex(ValueError, 'comparison limit'):
            research.field_spec(changed, self.decoded)

    def test_json_sequence_cap_matches_object_and_corruption_rejected(self):
        self.assertEqual(self.spec['sequence_cap'], self.spec['cap'])
        self.assertEqual(self.decoded[0x1cfe3f0]['target'], 0x1cfe546)
        changed = Overlay(self.view, {0x1cfe3ef: 4})
        with self.assertRaisesRegex(ValueError, 'comparison limit'):
            research.field_spec(changed, self.decoded)

    def test_exact_extension_routes(self):
        examples = [(b'x.rmp', 9, 'binary'), (b'x.RmP', 9, 'binary'),
                    (b'.rmp', 9, 'text'), (b'..', 9, 'text'),
                    (b'x.rmpx', 9, 'text'), (b'x.rm', 9, 'text'),
                    (b'x.y.rmp', 9, 'binary'), (b'x.rmp', 8, 'text')]
        for value, tag, expected in examples:
            with self.subTest(value=value, tag=tag):
                self.assertEqual(research.model_extension(value, tag, self.loader['extension']), expected)

    def test_invalid_component_type_or_tag_rejected(self):
        for value, tag in (('x.rmp', 9), (b'x.rmp', -1), (b'x.rmp', 256), (b'x.rmp', True)):
            with self.subTest(value=value, tag=tag):
                with self.assertRaises(ValueError):
                    research.model_extension(value, tag, b'rmp')

    def test_changed_extension_immediate_rejected(self):
        changed = Overlay(self.view, {0x28ea57b: ord('s')})
        with self.assertRaisesRegex(ValueError, 'extension'):
            research.load_spec(changed, self.decoded)

    def test_ascii_whitespace_domain(self):
        accepted = [n for n in range(256) if n <= 32 and (self.spec['whitespace_mask'] >> n) & 1]
        self.assertEqual(accepted, [9, 10, 13, 32])

    def test_ip_length_limit_and_external_parser(self):
        self.assertEqual(self.spec['ip_max'], 15)
        call = self.decoded[0x1be9874]
        self.assertEqual((call['kind'], call['target']), ('call', 0x1573af0))
        self.assertEqual(self.decoded[0x1be9863]['target'], 0x1be989b)

    def test_fresh_binary_marker_slot(self):
        self.assertEqual(self.loader['fresh_marker_table_base'], 0x307bd4)
        displacement = int.from_bytes(self.loader['fresh_marker_slot'], 'little', signed=True)
        self.assertEqual(self.loader['fresh_marker_table_base'] + displacement, 0x185bbcf)

    def test_corrupt_binary_marker_slot_rejected(self):
        address = 0x307bd8
        changed = Overlay(self.view, {address: self.view.read(address, 1)[0] ^ 1})
        with self.assertRaisesRegex(ValueError, 'dispatch slot'):
            research.load_spec(changed, self.decoded)

    def test_corrupt_binary_marker_bounds_rejected(self):
        changed = Overlay(self.view, {0x185bda0: 0x91})
        with self.assertRaisesRegex(ValueError, 'marker bounds'):
            research.load_spec(changed, self.decoded)

    def test_binary_fixed_array_marker_boundaries(self):
        cases = [(0x8f, 'other_marker'), (0x90, 'missing_first'),
                 (0x91, 'default_sentry'), (0x92, 'read_sentry'),
                 (0x93, 'extra_sequence_values'), (0x9f, 'extra_sequence_values'),
                 (0xa0, 'other_marker')]
        for marker, expected in cases:
            with self.subTest(marker=marker):
                self.assertEqual(research.model_binary_array_marker(marker, self.loader), expected)

    def test_binary_marker_input_validation(self):
        for marker in (-1, 256, True, '145'):
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError):
                    research.model_binary_array_marker(marker, self.loader)

    def test_binary_count_cap_matches_json(self):
        self.assertEqual(self.spec['binary_cap'], self.spec['cap'])
        self.assertEqual(self.decoded[0x21c2970]['target'], 0x21c29a7)

    def test_changed_binary_cap_rejected(self):
        changed = Overlay(self.view, {0x21c296f: 4})
        with self.assertRaisesRegex(ValueError, 'comparison limit'):
            research.field_spec(changed, self.decoded)

    def test_selected_summary_matches_fde_counts(self):
        summary = self.result['summary.json']
        self.assertEqual(summary['selected_fde_count'], 11)
        self.assertEqual(summary['selected_fde_bytes'], 15167)
        self.assertEqual(summary['selected_instruction_count'], 3339)
        self.assertEqual(summary['field_mutation_probes'], 104)
        self.assertEqual(summary['post_parse_sentry_count_reject_at'], 3)

    def test_exact_calls_and_branches(self):
        self.assertEqual(self.decoded[0x28ea817]['target'], 0x1b2cfd0)
        self.assertEqual(self.decoded[0x1b2d01a]['target'], 0x1cfdbf0)
        self.assertEqual(self.decoded[0x1cfe038]['target'], 0x21c28b0)
        self.assertEqual(self.decoded[0x21c28ef]['target'], 0x21c2907)
        self.assertEqual(self.decoded[0x1cfe2b7]['target'], 0x1cfe4ae)


if __name__ == '__main__':
    unittest.main()
