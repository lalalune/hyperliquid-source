"""Static controls for the digest-bound configuration-to-command evidence."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re015_build_selection_115 as subject


class BuildSelection115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.secs = subject.sections(cls.data)
        cls.result = subject.collect(cls.data)
        cls.modified = bytearray(cls.data)
        cls.constants = subject.selector_constants(cls.data, cls.secs)

    @classmethod
    @contextmanager
    def altered_offset(cls, offset, replacement):
        original = bytes(cls.modified[offset:offset + len(replacement)])
        cls.modified[offset:offset + len(replacement)] = replacement
        try:
            yield cls.modified
        finally:
            cls.modified[offset:offset + len(replacement)] = original

    @classmethod
    @contextmanager
    def altered_va(cls, va, replacement):
        with cls.altered_offset(subject.file_offset(cls.secs, va, len(replacement)), replacement) as data:
            yield data

    def test_authenticated_identity(self):
        self.assertEqual(subject.authenticate(self.data), subject.SHA115)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.SHA115)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.authenticate(b'wrong input')
        with self.altered_offset(4096, bytes((self.data[4096] ^ 1,))) as changed:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.authenticate(changed)

    def test_wrong_legacy_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.historical_compare(b'not the historical capture', self.data)

    def test_real_sections_and_out_of_range_addresses(self):
        self.assertEqual(subject.get(self.data, self.secs, 0x467729, 10), b'run-client')
        with self.assertRaises(ValueError):
            subject.file_offset(self.secs, -1, 1)
        with self.assertRaises(ValueError):
            subject.file_offset(self.secs, 0, 0)
        with self.assertRaises(ValueError):
            subject.file_offset(self.secs, 1 << 63, 1)
        section = next(s for s in self.secs if s['name'] == '.rodata')
        with self.assertRaises(ValueError):
            subject.file_offset(self.secs, section['address'] + section['size'] - 1, 2)

    def test_nobits_has_no_file_bytes(self):
        bss = next(s for s in self.secs if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            subject.file_offset(self.secs, bss['address'], 1)
        with self.assertRaises(ValueError):
            subject.file_offset([{'name': 'zero', 'type': 8, 'flags': 2,
                                  'address': 32, 'size': 16, 'offset': 0}], 32, 1)

    def test_ambiguous_sections_rejected(self):
        fake = {'name': 'a', 'type': 1, 'flags': 2, 'address': 32, 'size': 8, 'offset': 0}
        with self.assertRaises(ValueError):
            subject.file_offset([fake, dict(fake, name='b')], 32, 1)

    def test_selected_fde_extents_are_indexed(self):
        by_role = {f['role']: f for f in self.result['functions']}
        self.assertEqual(len(by_role), 19)
        self.assertEqual(by_role['entry']['start_va'], '0x155f8d0')
        self.assertEqual(by_role['prelude_dispatch']['end_va_exclusive'], '0x5c90b47')
        self.assertEqual(by_role['select_build_path']['end_va_exclusive'], '0x1564b2b')
        self.assertEqual(by_role['dispatch_loop']['end_va_exclusive'], '0x15677fe')
        self.assertTrue(all(len(f['body_sha256']) == 64 for f in by_role.values()))

    def test_prelude_tls_routes_and_vector_boundary(self):
        constants = subject.prelude_constants(self.data, self.secs)
        self.assertEqual(constants, {'ready_byte': 1, 'error_byte': 2})
        self.assertEqual(subject.prelude_route(constants, 0), 'tls_initialize_then_swap')
        self.assertEqual(subject.prelude_route(constants, 1), 'tls_swap')
        self.assertEqual(subject.prelude_route(constants, 2), 'error_call_then_ud2')
        self.assertEqual(subject.prelude_route(constants, 255), 'tls_initialize_then_swap')
        for site, target in ((0x5c908e5, 0x5c9091f), (0x5c908ee, 0x5c908ff),
                             (0x5c90977, 0x5c909e9), (0x5c9099f, 0x5c909de)):
            raw = subject.get(self.data, self.secs, site, 6)
            self.assertEqual(int(subject.checked_branch(raw, site, target)['taken_va'], 16), target)
        with self.assertRaises(ValueError):
            subject.prelude_route(constants, -1)
        with self.assertRaises(ValueError):
            subject.prelude_route(constants, 256)

    def test_prelude_rejects_changed_gate_and_indirect_call(self):
        with self.altered_va(0x5c908ed, b'\x03') as changed:
            with self.assertRaisesRegex(ValueError, 'prelude TLS'):
                subject.prelude_constants(changed, self.secs)
        with self.altered_va(0x5c909af, b'\x19') as changed:
            with self.assertRaises(ValueError):
                subject.prelude_constants(changed, self.secs)

    def test_name_display_from_packed_word_and_jump_table(self):
        rows = self.result['name_rows']
        self.assertEqual([r['input_byte'] for r in rows], [0, 1, 2, 3])
        self.assertEqual([r['packed_word'] for r in rows], [6, 4, 3, 2])
        self.assertEqual([r['text'] for r in rows], ['Local', 'XyzSandbox', 'XyzTestnet', 'Xyz'])

    def test_name_display_rejects_changed_jump_leaf(self):
        with self.altered_va(0x155166b, b'\x90') as changed:
            with self.assertRaises(ValueError):
                subject.make_name_rows(changed, self.secs)

    def test_name_display_rejects_changed_text(self):
        with self.altered_va(0x467067, b'Z') as changed:
            with self.assertRaises(ValueError):
                subject.make_name_rows(changed, self.secs)

    def test_name_byte_wraparound_and_x86_shift_mask(self):
        rows = self.result['name_cases']
        self.assertEqual(len(rows), 256)
        for value, row in enumerate(rows):
            self.assertEqual(row['input_byte'], value)
            self.assertEqual(row['text'], ['Local', 'XyzSandbox', 'XyzTestnet', 'Xyz'][value & 3])
        self.assertEqual((rows[4]['shift_byte'], rows[4]['shift_count']), (64, 0))
        self.assertEqual((rows[16]['shift_byte'], rows[16]['shift_count']), (0, 0))
        self.assertEqual((rows[255]['shift_byte'], rows[255]['shift_count']), (240, 48))

    def test_name_byte_model_rejects_changed_shift_instructions(self):
        with self.altered_va(0x155f8de, b'\x03') as changed:
            with self.assertRaisesRegex(ValueError, 'byte shift'):
                subject.make_name_cases(changed, self.secs, self.result['name_rows'])
        with self.altered_va(0x155f8eb, b'\xe0') as changed:
            with self.assertRaises(ValueError):
                subject.make_name_cases(changed, self.secs, self.result['name_rows'])

    def test_selected_relative_and_imported_relocations(self):
        rows = subject.relocations(self.data, self.secs, (0x64e1170, 0x64df508))
        self.assertEqual(rows[0x64e1170]['addend_va'], '0x1564b30')
        self.assertEqual(rows[0x64e1170]['type'], 8)
        self.assertEqual(rows[0x64df508]['type'], 6)
        self.assertEqual(rows[0x64df508]['symbol'], 'memcpy')
        self.assertIsNone(rows[0x64df508]['addend_va'])

    def test_native_process_imports_and_mutation(self):
        slots = (0x64eb078, 0x64ec740, 0x64ec738, 0x64ec7b8, 0x64ec7c0, 0x64ec810, 0x64dffc8)
        rows = subject.relocations(self.data, self.secs, slots)
        subject.validate_native_imports(rows)
        self.assertEqual(rows[0x64ec740]['symbol'], 'fork')
        self.assertEqual(rows[0x64ec7b8]['symbol'], 'posix_spawnp')
        self.assertEqual(rows[0x64ec810]['symbol'], 'execvp')
        self.assertEqual(rows[0x64ec738]['symbol_metadata']['binding'], 2)
        self.assertEqual(rows[0x64ec738]['symbol_metadata']['section_index'], 0)
        fork = rows[0x64ec740]
        offset = int(fork['record_file_offset'], 16) + 8
        with self.altered_offset(offset, struct.pack('<Q', (17 << 32) | 6)) as changed:
            changed_rows = subject.relocations(changed, self.secs, slots)
            with self.assertRaisesRegex(ValueError, 'native import'):
                subject.validate_native_imports(changed_rows)

    def test_weak_pidfd_symbol_corruption(self):
        slots = (0x64eb078, 0x64ec740, 0x64ec738, 0x64ec7b8, 0x64ec7c0, 0x64ec810, 0x64dffc8)
        rows = subject.relocations(self.data, self.secs, slots)
        index = rows[0x64ec738]['symbol_index']
        dyn = next(s for s in self.secs if s['name'] == '.dynsym')
        offset = dyn['offset'] + index * 24 + 4
        with self.altered_offset(offset, bytes((0x12,))) as changed:
            changed_rows = subject.relocations(changed, self.secs, slots)
            with self.assertRaisesRegex(ValueError, 'native import'):
                subject.validate_native_imports(changed_rows)

    def test_process_error_and_child_branches(self):
        for site, target in ((0x5c85eb3, 0x5c860a2), (0x5c85f0b, 0x5c860ec),
                             (0x5c85f16, 0x5c86b24), (0x5c865a1, 0x5c85e8c),
                             (0x5c868bb, 0x5c8690e)):
            raw = subject.get(self.data, self.secs, site, 6)
            self.assertEqual(int(subject.checked_branch(raw, site, target)['taken_va'], 16), target)
        self.assertEqual(subject.get(self.data, self.secs, 0x5c860ba, 6), bytes.fromhex('c70001000000'))
        self.assertEqual(subject.get(self.data, self.secs, 0x5c865d5, 6), bytes.fromhex('c70100000000'))

    def test_missing_relocation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            subject.relocations(self.data, self.secs, (0x123,))

    def test_changed_relocation_type_rejected(self):
        row = subject.relocations(self.data, self.secs, (0x64e1170,))[0x64e1170]
        offset = int(row['record_file_offset'], 16) + 8
        with self.altered_offset(offset, struct.pack('<Q', 7)) as changed:
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                subject.relocations(changed, self.secs, (0x64e1170,))

    def test_duplicate_relocation_rejected(self):
        row = subject.relocations(self.data, self.secs, (0x64e1178,))[0x64e1178]
        offset = int(row['record_file_offset'], 16)
        with self.altered_offset(offset, struct.pack('<Q', 0x64e1170)) as changed:
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                subject.relocations(changed, self.secs, (0x64e1170,))

    def test_out_of_range_dynamic_symbol_rejected(self):
        row = subject.relocations(self.data, self.secs, (0x64df508,))[0x64df508]
        offset = int(row['record_file_offset'], 16) + 8
        with self.altered_offset(offset, struct.pack('<Q', (0xffffffff << 32) | 6)) as changed:
            with self.assertRaisesRegex(ValueError, 'symbol outside'):
                subject.relocations(changed, self.secs, (0x64df508,))

    def test_rip_relative_control(self):
        raw = subject.get(self.data, self.secs, 0x1564a2a, 7)
        self.assertEqual(subject.decode_rip(raw, 0x1564a2a), 0x4366ce)
        self.assertNotEqual(subject.decode_rip(raw[:3] + b'\0\0\0\0', 0x1564a2a), 0x4366ce)
        with self.assertRaises(ValueError):
            subject.decode_rip(b'\x90' + raw[1:], 0x1564a2a)
        with self.assertRaises(ValueError):
            subject.decode_rip(raw[:3], 0x1564a2a)

    def test_direct_and_indirect_calls(self):
        raw = subject.get(self.data, self.secs, 0x1565f92, 6)
        self.assertEqual(subject.decode_transfer(raw, 0x1565f92)[:2], ('direct', 0x1565460))
        raw = subject.get(self.data, self.secs, 0x1564c0d, 6)
        self.assertEqual(subject.decode_transfer(raw, 0x1564c0d)[:2], ('slot', 0x64e1238))
        with self.assertRaises(ValueError):
            subject.decode_transfer(b'\x90' * 6, 0x1564c0d)

    def test_branch_target_and_corruption(self):
        raw = subject.get(self.data, self.secs, 0x15648b0, 6)
        self.assertEqual(subject.checked_branch(raw, 0x15648b0, 0x1564a02)['taken_va'], '0x1564a02')
        broken = bytearray(raw)
        broken[2] ^= 1
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            subject.checked_branch(bytes(broken), 0x15648b0, 0x1564a02)
        with self.assertRaises(ValueError):
            subject.decode_branch(b'\x90\x90', 0x15648b0)
        with self.assertRaises(ValueError):
            subject.decode_branch(b'\x0f', 0x15648b0)

    def test_selector_immediate_and_output_tag_corruption(self):
        self.assertEqual(self.constants['program'], b'run-client')
        with self.altered_va(0x1564897, b'R') as changed:
            with self.assertRaisesRegex(ValueError, 'disagree'):
                subject.selector_constants(changed, self.secs)
        with self.altered_va(0x15649b0, b'\x00') as changed:
            with self.assertRaises(ValueError):
                subject.selector_constants(changed, self.secs)

    def test_selector_priority_and_mode_boundaries(self):
        choose = lambda a, b, p: subject.select_mode(self.constants, a, b, p)
        self.assertEqual(choose(0, 0, b'run-client'), ('local_copy', 0))
        self.assertEqual(choose(0, 1, b'run-client'), ('client_template', 0))
        self.assertEqual(choose(255, 0, b'run-client'), ('client_template', 0))
        self.assertEqual(choose(1, 0, b'other'), ('debug_template', 1))
        self.assertEqual(choose(2, 255, b'other'), ('release_template', 1))
        self.assertEqual(choose(0, 1, b'other'), ('mode_error', None))
        self.assertEqual(choose(3, 0, b'other'), ('mode_error', None))
        self.assertEqual(choose(1, 1, b'run-client2'), ('debug_template', 1))
        with self.assertRaises(ValueError):
            choose(256, 0, b'run-client')
        with self.assertRaises(ValueError):
            choose(0, -1, b'run-client')

    def test_all_single_bit_program_mutations(self):
        program = self.constants['program']
        for bit in range(len(program) * 8):
            candidate = bytearray(program)
            candidate[bit // 8] ^= 1 << (bit % 8)
            self.assertEqual(subject.select_mode(self.constants, 3, 0, bytes(candidate)), ('mode_error', None))
        self.assertEqual(subject.select_mode(self.constants, 3, 0, program), ('client_template', 0))

    def test_exhaustive_mode_counts(self):
        counts = self.result['exhaustive']
        self.assertEqual(counts['exact']['cases'], 65536)
        self.assertEqual(counts['exact']['decisions'], {'client_template': 65535, 'local_copy': 1})
        self.assertEqual(counts['other']['cases'], 65536)
        self.assertEqual(counts['other']['decisions'], {'debug_template': 256, 'release_template': 256,
                                                        'local_copy': 1, 'mode_error': 65023})

    def test_ascii_trim_and_space_split(self):
        split = lambda b: subject.ascii_trim_split(b, 32)
        self.assertEqual(split(b''), [b''])
        self.assertEqual(split(b' '), [b''])
        self.assertEqual(split(b' a  b '), [b'a', b'', b'b'])
        self.assertEqual(split(b'\ta\tb\n'), [b'a\tb'])
        self.assertEqual(split(b'a b'), [b'a', b'b'])
        with self.assertRaises(ValueError):
            split(b'\xc2\xa0')
        with self.assertRaises(ValueError):
            subject.ascii_trim_split(b'a', 256)

    def test_short_nul_scan_boundaries(self):
        constants = subject.short_nul_constants(self.data, self.secs)
        self.assertEqual(constants['maximum_short_length'], 15)
        for length in range(16):
            self.assertEqual(subject.short_nul_model(b'A' * length, constants), ('success_sentinel', None))
            for index in range(length):
                sample = b'A' * index + b'\x00' + b'A' * (length - index - 1)
                self.assertEqual(subject.short_nul_model(sample, constants), ('nul_result', index))
        with self.assertRaises(ValueError):
            subject.short_nul_model(b'A' * 16, constants)

    def test_nul_scan_and_terminator_corruption(self):
        with self.altered_va(0x141e9c5, b'\x01') as changed:
            with self.assertRaises(ValueError):
                subject.short_nul_constants(changed, self.secs)
        with self.altered_va(0x141e192, b'\x01') as changed:
            with self.assertRaises(ValueError):
                subject.short_nul_constants(changed, self.secs)

    def test_native_status_model_boundaries(self):
        model = subject.native_result_model
        self.assertEqual(model('pidfd', 0), 'pidfd_success_path')
        self.assertEqual(model('pidfd', 37), 'error_result_path')
        self.assertEqual(model('pidfd', 38), 'cache_two_then_fork_path')
        self.assertEqual(model('pidfd', 39), 'error_result_path')
        self.assertEqual(model('posix', 0), 'posix_success_cleanup')
        self.assertEqual(model('posix', 38), 'error_result_path')
        self.assertEqual(model('fork', -1), 'error_result_path')
        self.assertEqual(model('fork', 0), 'child_setup')
        self.assertEqual(model('fork', 1), 'parent_path')
        with self.assertRaises(ValueError):
            model('pidfd', -1)
        with self.assertRaises(ValueError):
            model('other', 0)

    def test_counter_after_selected_process_outcomes(self):
        model = subject.counter_model
        maximum = (1 << 64) - 1
        self.assertEqual(model(0, 7, False, True), 7)
        self.assertEqual(model(1, 7, False, True), 8)
        self.assertEqual(model(2, maximum, False, True), maximum)
        self.assertEqual(model(3, 7, False, True), 7)
        self.assertEqual(model(1, 7, True, True), 1)
        self.assertEqual(model(1, 7, True, False), 0)
        self.assertEqual(model(1, 7, False, False), 7)
        with self.assertRaises(ValueError):
            model(256, 0, False, True)
        with self.assertRaises(ValueError):
            model(0, -1, False, True)
        with self.assertRaises(ValueError):
            model(0, 0, 1, True)

    def test_context_preserves_name_discriminant_drift(self):
        context = self.result['anchors']
        self.assertEqual(context['name_bytes'], b'NvTestnet'.hex())
        self.assertEqual(context['name_index'], 33)
        self.assertEqual(context['name_bound'], 79)
        self.assertEqual(context['directory_field_offset'], 24)
        self.assertEqual([r['index'] for r in context['selected_name_anchors']], [0, 32, 33, 34, 78])
        self.assertEqual(context['selected_name_anchors'][-1]['text'], 'EbHlPerp')

    def test_corrupt_name_descriptor_rejected(self):
        slot = 0x63f8998
        rows = subject.relocations(self.data, self.secs, (slot,))
        off = int(rows[slot]['record_file_offset'], 16) + 16
        with self.altered_offset(off, struct.pack('<q', 0x464717)) as changed:
            changed_rows = subject.relocations(changed, self.secs, (slot,))
            with self.assertRaisesRegex(ValueError, 'descriptor'):
                subject.selected_name_anchors(changed, self.secs, changed_rows, 0x63f8788, ((33, b'NvTestnet'),))

    def test_emit_creates_all_expected_deterministic_files(self):
        expected = {'summary.json', 'functions.json', 'relocations.json', 'name-dispatch.json',
                    'mode-exhaustive.json', 'context-anchors.json', 'bodies.tsv', 'transfers.tsv',
                    'references.tsv', 'branches.tsv', 'literals.tsv', 'windows.tsv', 'mode-cases.tsv',
                    'equality-probes.tsv', 'ascii-arguments.tsv', 'state-cases.tsv', 'native-cases.tsv',
                    'short-nul-cases.tsv', 'prelude-cases.tsv', 'name-byte-cases.tsv'}
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            subject.emit(self.result, out)
            self.assertEqual({p.name for p in out.iterdir()}, expected)
            self.assertEqual(json.loads((out / 'summary.json').read_text())['target_sha256'], subject.SHA115)
            before = {p.name: p.read_bytes() for p in out.iterdir()}
            subject.emit(self.result, out)
            self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})


if __name__ == '__main__':
    unittest.main()
