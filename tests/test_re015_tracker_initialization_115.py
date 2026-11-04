"""Controls for the node-115 alert-tracker static evidence collector."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from contextlib import contextmanager

from tools import re015_tracker_initialization_115 as tracker


class TrackerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(tracker.BINARY.read_bytes())
        cls.image = tracker.Image(cls.data)

    @contextmanager
    def changed(self, va, replacement):
        _, offset = tracker.locate(self.image.secs, va, len(replacement))
        before = bytes(self.data[offset:offset + len(replacement)])
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(replacement)] = before

    @contextmanager
    def changed_offset(self, offset, replacement):
        before = bytes(self.data[offset:offset + len(replacement)])
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(replacement)] = before

    def test_target_digest(self):
        self.assertEqual(tracker.digest_check(self.data, tracker.TARGET), tracker.TARGET)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tracker.TARGET)

    def test_bad_digest_rejected(self):
        with self.changed(0x43ec01, b'\x00'):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                tracker.digest_check(self.data, tracker.TARGET)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tracker.digest_check(b'not an ELF', tracker.TARGET)

    def test_unmapped_empty_negative_and_nobits_rejected(self):
        for va, size in ((0, 1), (-1, 1), (0x43ec01, 0)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                tracker.locate(self.image.secs, va, size)
        fake = [{'type': 8, 'size': 8, 'address': 0x1000, 'offset': 4}]
        with self.assertRaises(ValueError):
            tracker.locate(fake, 0x1000, 1)

    def test_unambiguous_file_span_and_nobits_overlap(self):
        fake = [{'type': 1, 'size': 8, 'address': 0x1000, 'offset': 4},
                {'type': 8, 'size': 8, 'address': 0x1000, 'offset': 90}]
        self.assertEqual(tracker.locate(fake, 0x1001, 2)[1], 5)
        with self.assertRaises(ValueError):
            tracker.locate(fake, 0x1007, 2)
        fake.append({'type': 1, 'size': 8, 'address': 0x1000, 'offset': 22})
        with self.assertRaises(ValueError):
            tracker.locate(fake, 0x1001, 1)

    def test_selected_fdes_are_digest_bound_and_distinct(self):
        rows = [self.image.function(spec) for spec in tracker.FUNCTIONS]
        self.assertEqual(len(rows), 7)
        self.assertEqual(sum(row[3] for row in rows), 7120)
        self.assertEqual(len({row[1] for row in rows}), 7)
        self.assertTrue(all(row[5] == '.text' for row in rows))

    def test_function_body_corruption_rejected(self):
        with self.changed(0x150c020, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'body hash'):
                self.image.function(tracker.FUNCTIONS[0])

    def test_fde_and_index_mismatch_rejected(self):
        start = tracker.FUNCTIONS[0][1]
        entry = self.image.index[start]
        original = entry['fde']
        try:
            entry['fde'] += 1
            with self.assertRaisesRegex(ValueError, 'unwind index'):
                self.image.function(tracker.FUNCTIONS[0])
        finally:
            entry['fde'] = original
        spec = list(tracker.FUNCTIONS[0])
        spec[2] += 1
        with self.assertRaisesRegex(ValueError, 'FDE range'):
            self.image.function(spec)

    def test_missing_and_wrong_relocation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.image.relative(0x63fbf71)
        with self.assertRaisesRegex(ValueError, 'addend'):
            self.image.relative(0x63fbf70, 0x465873)
        off, _ = self.image.relative(0x63fbf70)
        with self.changed_offset(off + 8, bytes(8)):
            with self.assertRaisesRegex(ValueError, 'RELATIVE'):
                self.image.relative(0x63fbf70)
        with self.changed_offset(off + 16, (0x465873).to_bytes(8, 'little')):
            with self.assertRaisesRegex(ValueError, 'addend'):
                self.image.relative(0x63fbf70, 0x465872)

    def test_descriptor_names_and_location(self):
        row = tracker.slice_descriptor(self.image, 'ack', 0x63fbf70, b'bug_alert_ack')
        self.assertEqual((row[3], row[4]), ('0x465872', 13))
        location = tracker.location_descriptor(self.image, 'ignore', 0x63fc1b8)
        self.assertEqual(location[-2:], [766, 13])
        with self.changed(0x63fbf78, (14).to_bytes(8, 'little')):
            with self.assertRaisesRegex(ValueError, 'descriptor'):
                tracker.slice_descriptor(self.image, 'ack', 0x63fbf70, b'bug_alert_ack')

    def test_literal_corruption_rejected(self):
        with self.changed(0x465872, b'B'):
            with self.assertRaisesRegex(ValueError, 'literal'):
                tracker.slices(self.image)

    def test_name_descriptor_boundaries(self):
        row = tracker.name_descriptor(self.image, 0x63f8998, 0x63f8788, 0x464716)
        self.assertEqual(row[4:6], [9, 33])
        with self.assertRaises(ValueError):
            tracker.name_descriptor(self.image, 0x63f8998, 0x63f8789, 0x464716)
        with self.changed(0x63f89a0, (8).to_bytes(8, 'little')):
            with self.assertRaisesRegex(ValueError, 'name descriptor'):
                tracker.name_descriptor(self.image, 0x63f8998, 0x63f8788, 0x464716)
        with self.changed(0x63f8998, (1).to_bytes(8, 'little')):
            with self.assertRaisesRegex(ValueError, 'name descriptor'):
                tracker.name_descriptor(self.image, 0x63f8998, 0x63f8788, 0x464716)

    def test_compact_template_and_corruption(self):
        rows = tracker.tracker_template(self.image)
        self.assertEqual([row[0] for row in rows],
                         ['argument', 'argument', 'literal', 'argument', 'literal', 'terminator'])
        self.assertEqual([row[2] for row in rows if row[0] == 'literal'], [23, 5])
        with self.changed(0x43ec03, b'\x7f'):
            with self.assertRaises(ValueError):
                tracker.tracker_template(self.image)
        with self.changed(0x43ec22, b'\x01'):
            with self.assertRaises(ValueError):
                tracker.tracker_template(self.image)

    def test_rip_reference_target_and_opcode_controls(self):
        spec = tracker.REFERENCES[0]
        self.assertEqual(self.image.reference(*spec)[-1], '0x63fc1b8')
        with self.changed(spec[1], b'\x90'):
            with self.assertRaisesRegex(ValueError, 'opcode'):
                self.image.reference(*spec)
        with self.changed(spec[1] + 3, b'\x00'):
            with self.assertRaisesRegex(ValueError, 'target'):
                self.image.reference(*spec)

    def test_branch_condition_and_target_controls(self):
        spec = tracker.CONSTRUCTOR_BRANCHES[1]
        row = self.image.branch(*spec)
        self.assertEqual(row[-1], '0x1549efc')
        with self.changed(spec[1], b'\x75'):
            with self.assertRaisesRegex(ValueError, 'opcode'):
                self.image.branch(*spec)
        with self.changed(spec[1] + 1, b'\x31'):
            with self.assertRaisesRegex(ValueError, 'target'):
                self.image.branch(*spec)
        with self.assertRaises(ValueError):
            self.image.branch('bad', 0x1549ec8, '74', 0x154a89d)

    def test_transfer_controls(self):
        direct = tracker.TRANSFERS[0]
        slot = tracker.INIT_TRANSFERS[0]
        self.assertEqual(self.image.transfer(*direct)[-1], '0x154a360')
        self.assertEqual(self.image.transfer(*slot)[-1], '0x141e3a0')
        with self.changed(direct[1], b'\xe9'):
            with self.assertRaisesRegex(ValueError, 'opcode'):
                self.image.transfer(*direct)
        with self.changed(slot[1] + 2, b'\x00'):
            with self.assertRaisesRegex(ValueError, 'slot'):
                self.image.transfer(*slot)

    def test_witness_corruption_rejected(self):
        spec = tracker.WITNESSES[0]
        with self.changed(spec[1], b'\x90'):
            with self.assertRaisesRegex(ValueError, 'instruction bytes'):
                self.image.witness(*spec)

    def test_exception_call_sites_and_owner_cleanup(self):
        header, rows = self.image.exception_sites(tracker.FUNCTIONS[0])
        self.assertEqual(header[-1], 6)
        selected = [r for r in rows if int(r[4], 16) <= 0x150c046 < int(r[5], 16)]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0][6], '0x150c1c5')

    def test_exception_encoding_and_range_corruption(self):
        with self.changed(0x17623f, b'\x02'):
            with self.assertRaisesRegex(ValueError, 'call-site encoding'):
                self.image.exception_sites(tracker.FUNCTIONS[0])
        with self.changed(0x176240, b'\x7f'):
            with self.assertRaisesRegex(ValueError, 'bounds'):
                self.image.exception_sites(tracker.FUNCTIONS[0])
        with self.changed(0x176241, b'\x7f'):
            with self.assertRaisesRegex(ValueError, 'range'):
                self.image.exception_sites(tracker.FUNCTIONS[0])

    def test_device_comparison_positive_lengths_and_each_byte(self):
        candidate = bytes.fromhex('2f6465762f6e756c6c')
        self.assertTrue(tracker.device_match(self.image, candidate))
        self.assertFalse(tracker.device_match(self.image, candidate[:-1]))
        self.assertFalse(tracker.device_match(self.image, candidate + bytes(1)))
        for i in range(len(candidate)):
            b = bytearray(candidate)
            b[i] ^= 1
            self.assertFalse(tracker.device_match(self.image, bytes(b)))
        with self.assertRaises(TypeError):
            tracker.device_match(self.image, 'device')

    def test_device_instruction_corruption_rejected(self):
        with self.changed(0x1504369, b'\x00'):
            with self.assertRaises(ValueError):
                tracker.device_match(self.image, bytes(9))

    def test_abstract_routes_and_precedence(self):
        sentinel = 1 << 63
        route = lambda *x: tracker.tracker_route(self.image, *x)
        self.assertEqual(route(False, 1, sentinel, sentinel, 1), 'write_failure_boundary')
        self.assertEqual(route(False, 1, sentinel, sentinel, 0), 'default_after_write')
        self.assertEqual(route(True, 1, sentinel, sentinel, 0), 'fallback_timestamp_error')
        self.assertEqual(route(True, 0, sentinel, sentinel, 0), 'fallback_read_sentinel')
        self.assertEqual(route(True, 0, 0, sentinel, 0), 'fallback_path_sentinel')
        self.assertEqual(route(True, 0, sentinel + 1, sentinel - 1, 1), 'loaded_value_and_timestamp')

    def test_abstract_route_input_controls(self):
        for args in ((1, 0, 0, 0, 0), (True, -1, 0, 0, 0),
                     (True, 2**32, 0, 0, 0), (True, 0, -1, 0, 0),
                     (True, 0, 0, 0, 2**64)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                tracker.tracker_route(self.image, *args)
        with self.changed(0x1549fc8, b'\x02'):
            with self.assertRaises(ValueError):
                tracker.tracker_route(self.image, True, 0, 0, 0, 0)

    def test_historical_digest_control_without_fixture(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tracker.compare_historical(self.image, b'incorrect historical bytes')

    def test_deterministic_generation(self):
        with tempfile.TemporaryDirectory() as parent:
            base = Path(parent)
            first = tracker.generate(self.image, base / 'first')
            second = tracker.generate(self.image, base / 'second')
            self.assertEqual(first, second)
            self.assertEqual(sorted(first), sorted(p.name for p in (base / 'first').iterdir()))
            for name in first:
                self.assertEqual((base / 'first' / name).read_bytes(), (base / 'second' / name).read_bytes())

    def test_failed_generation_writes_nothing(self):
        with tempfile.TemporaryDirectory() as parent:
            destination = Path(parent) / 'output'
            with self.changed(0x150c083, b'\x90'):
                with self.assertRaises(ValueError):
                    tracker.generate(self.image, destination)
            self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
