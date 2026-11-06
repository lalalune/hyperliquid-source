import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from shared_insert_return_static import (
    PACKET,
    TARGET,
    analyze,
    authenticate,
    effective_mode,
    generate,
    saturating_add,
    slot_decision,
)
from elf_index import sections


def file_offset(data, va):
    for section in sections(data):
        if (section['type'] != 8 and section['address'] <= va
                < section['address'] + section['size']):
            return section['offset'] + va - section['address']
    raise AssertionError(f'VA not mapped: {va:#x}')


class SharedInsertReturnStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists():
            raise unittest.SkipTest('node 115 target is not materialized')
        cls.data = TARGET.read_bytes()
        authenticate(cls.data)
        cls.report = analyze(cls.data)

    def test_native_regeneration_matches_retained_packet(self):
        retained = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(
            self.report,
            {key: value for key, value in retained.items()
             if key not in ('source_exports', 'twin_difference')},
        )
        self.assertEqual(
            self.report['scope']['measured_denominator_bytes'], 2_134)
        self.assertEqual(
            sum(self.report['frames'][name]['bytes'] for name in
                ('shared_a', 'shared_b')),
            2_134,
        )
        twin = self.report.get('twin_difference')
        self.assertIsNone(twin)  # analyze() alone does not decode the diff
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'packet'
            generated = generate(TARGET, output)
            self.assertEqual(generated['twin_difference']
                             ['instructions_per_routine'], 236)
            self.assertEqual(generated['twin_difference']
                             ['identical_instructions'], 205)
            self.assertEqual(generated['twin_difference']
                             ['differing_instructions'], 31)
            self.assertEqual(generated['twin_difference']
                             ['differing_bytes'], 57)
            retained_files = sorted(
                path.name for path in PACKET.iterdir()
                if path.is_file() and path.name not in ('MANIFEST.sha256', 'README.md')
            )
            self.assertEqual(
                retained_files,
                sorted(path.name for path in output.iterdir()),
            )
            for name in retained_files:
                self.assertEqual(
                    (PACKET / name).read_bytes(),
                    (output / name).read_bytes(),
                    name,
                )

    def test_trace_facts(self):
        trace = self.report['trace']
        contract = trace['return_contract']
        self.assertEqual(contract['register'], 'rax')
        self.assertEqual(len(contract['cases']), 3)
        self.assertEqual(
            [case['case'] for case in contract['cases']],
            ['append', 'reuse', 'panic'],
        )
        self.assertEqual(
            self.report['owners']['shared_a']['direct_e8_call_sites'],
            ['0x59119d1', '0x5911a3f'],
        )
        self.assertEqual(
            self.report['owners']['shared_b']['direct_e8_call_sites'],
            ['0x5911c71', '0x5911cdf'],
        )
        locations = self.report['source_locations']
        self.assertEqual(locations['vacant_entry_panic']['file'],
                         'l1/src/slab/slab.rs')
        self.assertEqual(locations['vacant_entry_panic']['line'], 78)
        self.assertEqual(locations['overflow_entry']['file'],
                         'l1/src/qtys/mod.rs')
        self.assertEqual(locations['link_assertion_1']['line'], 81)
        self.assertEqual(locations['link_assertion_2']['line'], 89)
        self.assertEqual(
            locations['vacant_message']['text'], 'expected vacant entry ')
        self.assertEqual(locations['vacant_message']['length_byte'], 0x16)
        detail = trace['owners_detail']
        self.assertEqual(detail['shared_a']['event_element_bytes'], 0x2B8)
        self.assertEqual(detail['shared_b']['event_element_bytes'], 0x2C8)
        self.assertEqual(
            detail['shared_a']['slab_grow_target'],
            detail['shared_b']['slab_grow_target'],
        )
        self.assertNotEqual(
            detail['shared_a']['event_grow_target'],
            detail['shared_b']['event_grow_target'],
        )
        self.assertEqual(
            self.report['slot_bindings']['0x64df508'], None)

    def test_saturating_add_cases(self):
        self.assertEqual(saturating_add(3, 4), 7)
        self.assertEqual(saturating_add(0, 0), 0)
        max_u64 = (1 << 64) - 1
        self.assertEqual(saturating_add(max_u64, 1), max_u64)
        self.assertEqual(saturating_add(max_u64 - 1, 1), max_u64)
        self.assertEqual(saturating_add(1 << 63, 1 << 63), max_u64)

    def test_event_word_reaching_definitions(self):
        # These are raw frame-word sources, not an inferred Option payload.
        event = self.report['trace']['event_record']
        fresh = self.report['trace']['mode_selection']['fresh_mode_sources']
        self.assertNotEqual(fresh['event_+0x10'], 'the qword at order + 0xe0')
        self.assertEqual(event['word_0x10_sources'], [
            {'condition': 'stack_1 != 1', 'source': 'stack_1'},
            {'condition': 'stack_1 == 1 and stack_2 >= slab_length',
             'source': '1'},
            {'condition': 'stack_1 == 1 and stack_2 < slab_length and linked_first_qword == 2',
             'source': 'low64(stack_2 * 0x110)'},
            {'condition': 'stack_1 == 1 and stack_2 < slab_length and linked_first_qword != 2',
             'source': 'the qword at slab buffer[stack_2] + 0xf0'},
        ])
        fields = {row['offset']: row for row in event['fields']}
        self.assertEqual(fields[24]['source'], 'the qword at order + 0xe0')
        self.assertIn('word_0x10_sources', fields[16]['source'])
        for owner, base in [('shared_a', 0x58DF360), ('shared_b', 0x58DF790)]:
            witnesses = self.report['trace']['owners_detail'][owner]['event_word_witnesses']
            self.assertEqual(witnesses['selector_loads'], [hex(base + 0x44), hex(base + 0xD1)])
            self.assertEqual(witnesses['scaled_index'], hex(base + 0x70))
            self.assertEqual(witnesses['linked_word_load'], hex(base + 0xA0))
            self.assertEqual(witnesses['raw_word_store'], hex(base + 0x13E))
            self.assertEqual(witnesses['quantity_store'], hex(base + 0x143))

    def test_event_copy_extent_is_not_initialized_prefix(self):
        event = self.report['trace']['event_record']
        self.assertNotIn('written_span_bytes', event)
        self.assertEqual(event['initialized_source_prefix_bytes'], 77)
        self.assertEqual(event['copy_requested_bytes'], {'shared_a': 0x2B8, 'shared_b': 0x2C8})
        self.assertIn('not established', event['tail'])
        self.assertIn('exact-copy', event['destination_premise'])

    def test_event_provenance_instruction_corruptions(self):
        # In-memory static byte checks below the outer artifact authentication.
        # No mutated capture is executed or evaluated.
        for base in (0x58DF360, 0x58DF790):
            for offset in (0x46, 0xD3, 0x72, 0xA3, 0x140, 0x145, 0x54, 0x6A, 0x84):
                with self.subTest(base=hex(base), offset=hex(offset)):
                    with self.assertRaisesRegex(ValueError, 'Pinned instruction changed'):
                        analyze(self.mutate_va_byte(base + offset))

    def test_effective_mode_cases(self):
        # Selector other than 1 is always fresh.
        self.assertEqual(effective_mode(0, 0, 10, 7), 0)
        self.assertEqual(effective_mode(2, 0, 10, 7), 0)
        # In-range index whose slot qword is not 2 links.
        self.assertEqual(effective_mode(1, 3, 10, 7), 1)
        self.assertEqual(effective_mode(1, 3, 10, 0), 1)
        # Out-of-range index falls back to fresh.
        self.assertEqual(effective_mode(1, 10, 10, 7), 0)
        self.assertEqual(effective_mode(1, 11, 10, 7), 0)
        # A vacant (2) slot qword falls back to fresh.
        self.assertEqual(effective_mode(1, 3, 10, 2), 0)

    def test_slot_decision_cases(self):
        self.assertEqual(slot_decision(0, 0, 0), ('append', 0))
        self.assertEqual(slot_decision(5, 5, 2), ('append', 5))
        self.assertEqual(slot_decision(5, 5, 9), ('append', 5))
        self.assertEqual(slot_decision(3, 5, 2), ('reuse', 3))
        self.assertEqual(slot_decision(0, 5, 2), ('reuse', 0))
        self.assertEqual(slot_decision(3, 5, 1), ('panic', None))
        self.assertEqual(slot_decision(3, 5, 0), ('panic', None))
        self.assertEqual(slot_decision(6, 5, 2), ('panic', None))

    def mutate_va_byte(self, va, mask=0x01):
        changed = bytearray(self.data)
        changed[file_offset(self.data, va)] ^= mask
        return bytes(changed)

    def test_counterfactual_pinned_bytes_and_records(self):
        shared_a = 0x58DF360
        shared_b = 0x58DF790
        cases = (
            # The entry accumulator add (rax += rcx).
            (shared_a + 0x40, 'Pinned instruction changed'),
            # The mode selector immediate: == 1 becomes == 0.
            (shared_a + 0x53, 'Pinned instruction changed'),
            # The head load displacement +0x20 in the return decision.
            (shared_a + 0x1DE, 'Pinned instruction changed'),
            # The return move (rax = r13).
            (shared_a + 0x363, 'Pinned instruction changed'),
            # shared_b's per-twin event element size immediate.
            (shared_b + 0x197, 'Pinned instruction changed'),
            # shared_a's event grow slot displacement.
            (shared_a + 0x17B, 'Resolved target changed'),
            # The panic message length byte.
            (0x4339B2, 'Vacant-entry panic message changed'),
            # The panic location line field (record + 16).
            (0x64B6630 + 16, 'Vacant-entry panic location changed'),
            # The caller census: twin A's registration E8 opcode.
            (0x59119D1, 'shared_a direct caller census changed'),
        )
        for va, message in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, message):
                    analyze(self.mutate_va_byte(va))


if __name__ == '__main__':
    unittest.main()
