"""Controls for static trigger tuple quantity extraction."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tools import trigger_tuple_quantity94 as q


class TriggerTupleEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(q.load_binary())
        cls.image = q.Image(cls.data)
        cls.facts = q.inspect(cls.image)

    def test_identity_and_full_fdes(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), q.DIGEST)
        self.assertEqual(len(self.facts['functions']), 12)
        for row in self.facts['functions']:
            self.assertGreater(row['bytes'], 0)
            self.assertEqual(len(row['sha256']), 64)

    def test_wrong_digest_rejected_before_output(self):
        bad = bytearray(self.data)
        bad[0] ^= 1
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'not-created'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                q.generate(bad, dest)
            self.assertFalse(dest.exists())

    def test_changed_instruction_rejected(self):
        off = self.image.offset(0x20b3f50, 1, True)
        saved = self.data[off]
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'function bytes'):
                q.inspect(self.image)
        finally:
            self.data[off] = saved

    def test_changed_classifier_byte_rejected(self):
        off = self.image.offset(0x2165e5e, 1, True)
        saved = self.data[off]
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'function bytes'):
                q.inspect(self.image)
        finally:
            self.data[off] = saved

    def test_changed_fde_extent_rejected(self):
        row = self.image.fdes[0x20b3c70][0]
        saved = row['end']
        try:
            row['end'] -= 1
            with self.assertRaisesRegex(ValueError, 'FDE mismatch'):
                q.inspect(self.image)
        finally:
            row['end'] = saved

    def test_duplicate_fde_rejected(self):
        rows = self.image.fdes[0x2198670]
        try:
            rows.append(dict(rows[0]))
            with self.assertRaisesRegex(ValueError, 'FDE mismatch'):
                q.inspect(self.image)
        finally:
            rows.pop()

    def test_changed_dispatch_entry_rejected(self):
        off = self.image.offset(0x3c7000, 4)
        saved = self.data[off:off + 4]
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'map dispatch'):
                q.inspect(self.image)
        finally:
            self.data[off:off + 4] = saved

    def test_changed_name_data_rejected(self):
        off = self.image.offset(0x3d6cf2, 1)
        saved = self.data[off]
        try:
            self.data[off] ^= 1
            with self.assertRaises(ValueError):
                q.inspect(self.image)
        finally:
            self.data[off] = saved

    def test_relative_relocation_and_corruption(self):
        self.assertEqual(self.image.relocation(0x5773898), 0x3330210)
        rel = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
        loc = None
        for pos in range(rel['offset'], rel['offset'] + rel['size'], 24):
            if struct.unpack_from('<Q', self.data, pos)[0] == 0x5773898:
                loc = pos
                break
        self.assertIsNotNone(loc)
        before = self.data[loc + 16:loc + 24]
        try:
            self.data[loc + 16] ^= 1
            with self.assertRaisesRegex(ValueError, 'converter slot'):
                q.inspect(self.image)
        finally:
            self.data[loc + 16:loc + 24] = before

    def test_duplicate_relocation_rejected(self):
        rel = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
        location = next(pos for pos in range(rel['offset'], rel['offset'] + rel['size'], 24)
                        if struct.unpack_from('<Q', self.data, pos)[0] != 0x5773898)
        before = self.data[location:location + 24]
        try:
            struct.pack_into('<QQq', self.data, location, 0x5773898, 8, 0x3330210)
            with self.assertRaisesRegex(ValueError, 'duplicated'):
                self.image.relocation(0x5773898)
        finally:
            self.data[location:location + 24] = before

    def test_ambiguous_section_mapping_rejected(self):
        text_section = next(s for s in self.image.sections if s['name'] == '.text')
        try:
            self.image.sections.append(dict(text_section))
            with self.assertRaisesRegex(ValueError, 'one file-backed mapping'):
                self.image.read(0x20b3c70, 1, True)
        finally:
            self.image.sections.pop()

    def test_invalid_and_nobits_address(self):
        with self.assertRaises(ValueError):
            self.image.read(-1, 1)
        with self.assertRaises(ValueError):
            self.image.read(0xffffffffffffffff, 2)
        with self.assertRaises(ValueError):
            self.image.read(0x20a590, 8, True)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)

    def test_branch_decoder_refuses_non_branch(self):
        with self.assertRaises(ValueError):
            self.image.branch(0x20b3c70)
        cc, target, raw = self.image.branch(0x20b3c96)
        self.assertEqual((cc, target, len(raw)), (4, 0x20b3eb4, 6))

    def test_copy_windows_and_fields(self):
        self.assertEqual(self.facts['field_names'], ['isMarket', 'triggerPx', 'tpsl'])
        self.assertEqual(self.facts['map_dispatch'], ['0x20b3d8b', '0x20b3ddd', '0x20b3e54'])
        self.assertEqual(len(self.facts['paired_windows']), 26)
        self.assertEqual(len(self.facts['descriptions']), 2)

    def test_parent_all_byte_tags(self):
        for tag in range(256):
            for adapter in range(256):
                if tag == 2:
                    expected = 'classifier_error'
                elif tag & 1 == 0:
                    expected = 'other_variant'
                elif adapter == 2:
                    expected = 'adapter_error'
                else:
                    expected = 'adapter_success'
                self.assertEqual(q.parent_case(tag, adapter), expected)
        with self.assertRaises(ValueError):
            q.parent_case(256, 0)
        with self.assertRaises(ValueError):
            q.parent_case(1, -1)

    def test_variant_name_corruption(self):
        self.assertEqual(self.facts['variant_names'], ['limit', 'trigger'])
        self.assertEqual(self.facts['order_type_name'], 'OrderTypeWire')
        off = self.image.offset(0x3dff83, 1)
        before = self.data[off]
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'variant classifier'):
                q.inspect(self.image)
        finally:
            self.data[off] = before

    def test_cursor_marker_and_counter(self):
        self.assertEqual(q.first_advance(False, False, 0, 0), ('absent', 0, 0))
        self.assertEqual(q.first_advance(True, True, 0, 0), ('absent', 0, 0))
        for marker in range(256):
            expected = ('absent', 32, 0) if marker == 0x16 else ('present', 32, 1)
            self.assertEqual(q.first_advance(True, False, marker, 0), expected)
        self.assertEqual(q.first_advance(True, False, 0x16, q.TOP), ('absent', 32, q.TOP))
        self.assertEqual(q.first_advance(True, False, 0, q.TOP), ('overflow', 32, q.TOP))
        self.assertEqual(q.first_advance(True, False, 0, q.TOP - 1), ('present', 32, q.TOP))
        with self.assertRaises(ValueError):
            q.first_advance(True, False, 256, 0)

    def test_cursor_interpreter_and_branch_corruption(self):
        fixtures = ((False, False, 0, 0), (True, True, 0, 0),
                    (True, False, 0x16, q.TOP), (True, False, 0, q.TOP),
                    (True, False, 0, q.TOP - 1))
        for fixture in fixtures:
            self.assertEqual(q.walk_first_cursor(self.image, *fixture), q.first_advance(*fixture))
        offset = self.image.offset(0x1ee4184, 1, True)
        saved = self.data[offset]
        try:
            self.data[offset] = 0x74  # Change JNE to JE without changing the target.
            fixture = (True, False, 0, 0)
            self.assertNotEqual(q.walk_first_cursor(self.image, *fixture), q.first_advance(*fixture))
            with self.assertRaisesRegex(ValueError, 'function bytes'):
                q.inspect(self.image)
        finally:
            self.data[offset] = saved

    def test_first_failure_precedes_price(self):
        for length in range(6):
            outcome, calls = q.sequence_case(length, 0, False, 0, False, False, 0xa8)
            self.assertEqual(outcome, 'missing_0' if length == 0 else 'first_error')
            self.assertEqual(calls, ['first_reader'])

    def test_price_failure_precedes_third_and_converter(self):
        outcome, calls = q.sequence_case(3, 0, True, 1, False, False, q.SUCCESS)
        self.assertEqual(outcome, 'price_error')
        self.assertEqual(calls, ['first_reader', 'price_reader'])

    def test_missing_and_marker_boundaries(self):
        for length, expected in ((0,'missing_0'), (1,'missing_1'), (2,'missing_2'), (3,'success'), (4,'trailing_elements'), (5,'trailing_elements')):
            self.assertEqual(q.sequence_case(length, 0, True, 1, True, True, q.SUCCESS)[0], expected)
        for bit, outcome in ((1,'missing_0'), (2,'missing_1'), (4,'missing_2')):
            self.assertEqual(q.sequence_case(3, bit, True, 1, True, True, q.SUCCESS)[0], outcome)
        self.assertEqual(q.sequence_case(3, 0, True, 2, True, True, q.SUCCESS)[0], 'missing_0')

    def test_third_failure_and_trailing_precede_converter(self):
        a = q.sequence_case(3, 0, True, 0, True, False, q.SUCCESS)
        b = q.sequence_case(4, 0, True, 0, True, True, q.SUCCESS)
        self.assertEqual(a[0], 'third_error')
        self.assertEqual(b[0], 'trailing_elements')
        self.assertNotIn('converter', a[1])
        self.assertNotIn('converter', b[1])

    def test_all_converter_tag_values(self):
        for tag in range(65536):
            outcome, calls = q.sequence_case(3, 0, True, 0, True, True, tag)
            self.assertEqual(outcome, 'success' if tag == 0x186 else 'converter_error')
            self.assertEqual(calls[-1], 'converter')

    def test_model_rejects_bad_domains(self):
        with self.assertRaises(ValueError):
            q.sequence_case(6, 0, True, 0, True, True, 0x186)
        with self.assertRaises(ValueError):
            q.sequence_case(3, 8, True, 0, True, True, 0x186)
        with self.assertRaises(ValueError):
            q.sequence_case(3, 0, 1, 0, True, True, 0x186)
        with self.assertRaises(ValueError):
            q.sequence_case(3, 0, True, 0, True, True, 65536)

    def test_retained_evidence_matches_generation(self):
        retained = q.ROOT / 'research/work-items/RE-004-trigger-tuple-scale-94'
        expected = {'branches.tsv', 'calls.tsv', 'cursor-cases.tsv', 'evidence.json', 'fields.tsv',
                    'function-bytes.tsv', 'key-cases.tsv', 'parent-cases.tsv', 'sequence-cases.tsv'}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out'
            q.generate(self.data, out)
            self.assertEqual({p.name for p in out.iterdir()}, expected)
            self.assertEqual({p.name for p in retained.iterdir()} - {'README.md', 'MANIFEST.sha256'}, expected)
            for name in sorted(expected):
                self.assertEqual((out / name).read_bytes(), (retained / name).read_bytes(), name)

    def test_repeated_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'a', Path(tmp) / 'b'
            q.generate(self.data, a)
            q.generate(self.data, b)
            self.assertEqual(sorted(p.name for p in a.iterdir()), sorted(p.name for p in b.iterdir()))
            for p in a.iterdir():
                self.assertEqual(p.read_bytes(), (b / p.name).read_bytes(), p.name)


if __name__ == '__main__':
    unittest.main()
