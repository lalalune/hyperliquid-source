import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rmp_signable_layout_static as layout
from elf_index import sections


def materialized():
    target = ROOT / 'artifacts/node/115/hl-node'
    return (target.exists() and target.stat().st_size == layout.TARGET_SIZE
            and hashlib.sha256(target.read_bytes()).hexdigest() == layout.TARGET_SHA256)


def va_offset(data, va):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            return sec['offset'] + va - sec['address']
    raise AssertionError(f'unmapped {va:#x}')


class RmpSignableLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not materialized():
            raise unittest.SkipTest('materialized node115 required')
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.packet = ROOT / 'research/work-items/RE-005-node115-rmp-signable-layout'
        cls.records = json.loads((cls.packet / 'records.json').read_text())
        cls.result = layout.analyze(cls.data)

    def test_native_regeneration_matches_the_retained_packet(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            layout.generate(ROOT / 'artifacts/node/115/hl-node', out)
            for name in ('frames.txt', 'serializer.objdump.txt', 'caller_a.objdump.txt',
                         'caller_b.objdump.txt', 'records.json'):
                self.assertEqual((out / name).read_bytes(), (self.packet / name).read_bytes(), name)

    def test_write_order_is_complete(self):
        steps = self.records['write_order']
        self.assertEqual([s['width'] for s in steps], [8, 1, 20, 1, 8])
        self.assertEqual([s['source_offset'] for s in steps], ['0x10', '0x18', '0x19', None, '0x08'])
        self.assertTrue(all(s['evidence'] for s in steps))
        self.assertEqual(steps[2]['condition'],
                         {'source_offset': '0x18', 'width': 1, 'equals': 1})

    def test_suffix_lengths_follow_both_independent_conditions(self):
        suffix = self.records['suffix_bytes']
        self.assertEqual(suffix['option_byte_other'],
                         {'variant_other': 9, 'variant_one': 18})
        self.assertEqual(suffix['option_byte_one'],
                         {'variant_other': 29, 'variant_one': 38})
        self.assertEqual(suffix['variant_delta'], 9)
        self.assertIn('unresolved helper-produced prefix', suffix['scope'])
        self.assertNotIn('payload_bytes', self.records)

    def test_constructor_equality_continues_to_the_append_path(self):
        writer = self.records['writer']
        self.assertEqual(writer['continue_head'], '0x8000000000000004')
        self.assertNotIn('error_sentinel', writer)
        self.assertEqual(self.records['branches']['writer_head'], {
            'site': '0x36aaa0d', 'condition': 'not_equal',
            'target': '0x36aad04', 'fallthrough': '0x36aaa13',
            'bytes_hex': '0f85f1020000'})

    def test_optional_and_variant_branches_have_the_measured_rejoins(self):
        branches = self.records['branches']
        for name, condition, target, fallthrough in [
            ('optional_field', 'not_equal', '0x36aaab7', '0x36aaa5a'),
            ('variant_after_present_option', 'equal', '0x36aaadf', '0x36aaab5'),
            ('variant_after_absent_option', 'not_equal', '0x36aab2a', '0x36aaadf'),
        ]:
            with self.subTest(branch=name):
                self.assertEqual(branches[name]['condition'], condition)
                self.assertEqual(branches[name]['target'], target)
                self.assertEqual(branches[name]['fallthrough'], fallthrough)

    def test_tag_byte_rule(self):
        self.assertEqual(layout.tag_byte(3), 0x61)
        for tag in (0, 1, 2, 4, 5, 255):
            self.assertEqual(layout.tag_byte(tag), 0x62)
        self.assertEqual(self.records['tag_byte']['byte_if_equal'], '0x61')
        self.assertEqual(self.records['tag_byte']['byte_otherwise'], '0x62')

    def test_result_record_constants(self):
        record = self.records['result_record']
        self.assertEqual(record['word_at_0x00'], 1)
        self.assertEqual(record['string_length_at_0x10'], 1)
        self.assertEqual(record['mark_at_0x38'], '0x539')
        self.assertEqual(self.records['unwrap_site']['line'], 14)
        self.assertEqual(self.records['unwrap_site']['column'], 55)
        self.assertEqual(len(self.records['direct_callers']), 2)

    def mutated(self, va, delta=1):
        data = bytearray(self.data)
        off = va_offset(self.data, va)
        data[off] ^= delta
        return bytes(data)

    def test_counterfactual_bswap_byte_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            layout.analyze(self.mutated(0x36aaa3e))

    def test_counterfactual_tag_immediate_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            layout.analyze(self.mutated(0x36aac3a))

    def test_counterfactual_variant_compare_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            layout.analyze(self.mutated(0x36aaaaf + 3))

    def test_deciding_branch_polarities_and_destinations_are_load_bearing(self):
        # Mutate real deciding edges, including both independently emitted
        # variant tests. Static analysis must reject each changed relation.
        for name, opcode_va, displacement_va in [
            ('constructor', 0x36aaa0e, 0x36aaa0f),
            ('optional_field', 0x36aaa58, 0x36aaa59),
            ('present_variant', 0x36aaab3, 0x36aaab4),
            ('absent_variant', 0x36aaadd, 0x36aaade),
        ]:
            for kind, va in [('polarity', opcode_va), ('destination', displacement_va)]:
                with self.subTest(branch=name, mutation=kind):
                    with self.assertRaisesRegex(ValueError, 'branch relation'):
                        layout.analyze(self.mutated(va))

    def test_prefix_and_cursor_dependencies_are_load_bearing(self):
        for va in [0x36aaa05 + 3, 0x36aaa13 + 4, 0x36aaad0 + 3,
                   0x36aaaa6 + 3, 0x36aaad9 + 3, 0x36aab21 + 3,
                   0x36aaab5 + 1]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, 'byte pin'):
                    layout.analyze(self.mutated(va))

    def test_branch_encoding_width_preserves_the_fallthrough(self):
        data = bytearray(self.data)
        off = va_offset(self.data, 0x36aaa58)
        # Same JNE condition and taken destination, but a six-byte encoding
        # moves the fallthrough and overwrites the capacity-check prefix.
        data[off:off + 6] = bytes.fromhex('0f8559000000')
        with self.assertRaisesRegex(ValueError, 'branch relation'):
            layout.analyze(bytes(data))

    def test_counterfactual_location_line_is_load_bearing(self):
        data = bytearray(self.data)
        off = va_offset(self.data, layout.LOC_VA + 16)
        data[off] = 15
        with self.assertRaisesRegex(ValueError, 'location line/column'):
            layout.analyze(bytes(data))

    def test_wrong_public_identity_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as td:
            wrong = Path(td) / 'wrong'
            wrong.write_bytes(b'not the pinned node')
            out = Path(td) / 'packet'
            with self.assertRaisesRegex(ValueError, 'expected pinned node115'):
                layout.generate(wrong, out)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
