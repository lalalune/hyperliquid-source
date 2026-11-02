"""Static negative controls and boundary tests for the post-only window packet."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import post_only_window as tool


class PostOnlyWindow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(tool.BINARY.read_bytes())
        cls.image, cls.summary = tool.analyse(cls.data)
        cls.codes = [bytes.fromhex(row['bytes']) for row in cls.summary['selected_fdes'][:2]]

    def test_authentication(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tool.SHA256)
        with self.assertRaises(tool.EvidenceError):
            tool.authenticate(self.data, '0' * 64)

    def test_authentication_rejects_corrupted_artifact(self):
        index = self.image.offset(tool.GATES[0], 1, True)
        self.data[index] ^= 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.authenticate(self.data)
        finally:
            self.data[index] ^= 1

    def test_gate_shapes_and_fde_extents(self):
        self.assertEqual([(r['start'], r['end_exclusive']) for r in self.summary['selected_fdes']],
                         [('0x4d8c270', '0x4d8c2d8'), ('0x4d8c2e0', '0x4d8c348'),
                          ('0x37ecea0', '0x37ececf')])
        self.assertEqual([g['window'] for g in self.summary['gates']], [5000, 5000])
        self.assertEqual([g['height_field'] for g in self.summary['gates']], [0x4408, 0x3988])

    def test_every_synthetic_gate_vector_against_independent_formula(self):
        total = 0
        for code, info in zip(self.codes, self.summary['gates']):
            visited = set()
            outputs = set()
            for current, threshold, height, minimum, start in tool.vectors(info['window']):
                got, steps = tool.evaluate(code, current, threshold, height, minimum, start)
                expected = tool.specification(current, threshold, height, minimum, start, info['window'], info['free_code'])
                self.assertEqual(got, expected)
                visited.update(steps)
                outputs.add(got)
                total += 1
            self.assertEqual(outputs, {0, 1, 2})
            self.assertEqual(visited, {0, 3, 7, 13, 16, 18, 21, 27, 30, 32, 35, 41, 43, 45,
                                       47, 49, 51, 58, 60, 64, 70, 72, 78, 85, 89, 91, 97, 100, 103})
        self.assertEqual(total, 1224)

    def test_both_time_and_height_must_reach_threshold(self):
        for code in self.codes:
            self.assertEqual(tool.evaluate(code, (1, 2, 3), (1, 2, 3), 20, 20, 0)[0], 2)
            self.assertEqual(tool.evaluate(code, (1, 2, 2), (1, 2, 3), 20, 20, 0)[0], 0)
            self.assertEqual(tool.evaluate(code, (1, 2, 3), (1, 2, 3), 19, 20, 0)[0], 0)
            self.assertEqual(tool.evaluate(code, (1, 2, 4), (1, 2, 3), 20, 20, 0)[0], 2)

    def test_signed_first_unsigned_remaining_components(self):
        code = self.codes[0]
        self.assertEqual(tool.evaluate(code, (0xffffffff, 0, 0), (0, 0, 0), 0, 0, 0)[0], 0)
        self.assertEqual(tool.evaluate(code, (0, 0xffffffff, 0), (0, 1, 0), 0, 0, 0)[0], 2)
        self.assertEqual(tool.evaluate(code, (0, 0, 0xffffffff), (0, 0, 1), 0, 0, 0)[0], 2)

    def test_saturating_add_boundary(self):
        code = self.codes[0]
        start = tool.MAX - 4999
        for height, expected in ((tool.MAX - 1, 0), (tool.MAX, 1)):
            self.assertEqual(tool.evaluate(code, (0, 0, 0), (1, 0, 0), height, 0, start)[0], expected)
        self.assertEqual(tool.evaluate(code, (0, 0, 0), (1, 0, 0), 4999, 0, 0)[0], 0)
        self.assertEqual(tool.evaluate(code, (0, 0, 0), (1, 0, 0), 5000, 0, 0)[0], 1)

    def test_gate_code_byte_corruption_is_refused(self):
        for index in (16, 41, 47, 58, 70, 85, 100):
            mutated = bytearray(self.codes[0])
            mutated[index] ^= 1
            with self.assertRaises(tool.EvidenceError):
                tool.gate_info(mutated)

    def test_gate_truncation_and_field_inconsistency_are_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.gate_info(self.codes[0][:-1])
        mutated = bytearray(self.codes[0])
        mutated[23] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.gate_info(mutated)

    def test_instruction_immediate_corruption_is_refused(self):
        mutated = bytearray(self.codes[0])
        mutated[74] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.gate_info(mutated)

    def test_non_file_backed_out_of_range_and_non_executable_are_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.read(1 << 63, 4)
        with self.assertRaises(tool.EvidenceError):
            self.image.read(tool.TABLE, 4, True)
        image = tool.Image(self.data)
        image.sections = [{'type': 8, 'flags': 4, 'address': 123, 'size': 8, 'offset': 0}]
        with self.assertRaises(tool.EvidenceError):
            image.read(123, 1)

    def test_four_caller_windows_and_status_writes(self):
        calls = self.summary['callers']
        self.assertEqual([r['status_tag'] for r in calls], [0x74] * 4)
        self.assertEqual([r['target'] for r in calls], ['0x4d8c2e0', '0x4d8c2e0', '0x4d8c270', '0x4d8c270'])

    def test_caller_predicate_all_byte_pairs(self):
        # Every pair for one caller of each emitted machine-code shape.
        for site in tool.CALLS[:2]:
            for byte9 in range(256):
                for byte0 in range(256):
                    tag, payload = tool.evaluate_caller(self.image, site, 0, byte9, byte0)
                    if byte9 == 2 and byte0 == 0:
                        self.assertIsNone(tag)
                        self.assertIsNone(payload)
                    else:
                        self.assertEqual((tag, payload), (0x74, 0))

    def test_all_four_callers_and_three_gate_values(self):
        for site in tool.CALLS:
            for al in range(3):
                for byte9, byte0 in ((2, 0), (2, 1), (1, 0), (255, 255)):
                    tag, payload = tool.evaluate_caller(self.image, site, al, byte9, byte0)
                    expected = (None, None) if al == 2 or (byte9 == 2 and byte0 == 0) else (0x74, al)
                    self.assertEqual((tag, payload), expected)
        with self.assertRaises(tool.EvidenceError):
            tool.evaluate_caller(self.image, tool.CALLS[0], 3, 2, 0)

    def test_corrupt_caller_rejected(self):
        for address in (tool.CALLS[0], tool.CALLS[1] + 5, 0x4c18acc):
            index = self.image.offset(address, 1, True)
            self.data[index] ^= 1
            try:
                site = tool.CALLS[0] if address == tool.CALLS[0] else tool.CALLS[1]
                with self.assertRaises(tool.EvidenceError):
                    tool.call_info(self.image, site)
            finally:
                self.data[index] ^= 1

    def test_caller_rejection_return_and_corruption(self):
        calls = self.summary['callers']
        self.assertEqual([r['return'] for r in calls],
                         ['0x4c17e1e', '0x4c18534', '0x4c18e14', '0x4c1972e'])
        for address in (0x4c1813c, 0x4c17e1e):
            index = self.image.offset(address, 1, True)
            self.data[index] ^= 1
            try:
                with self.assertRaises(tool.EvidenceError):
                    tool.call_info(self.image, tool.CALLS[0])
            finally:
                self.data[index] ^= 1

    def test_status_formatter_and_serialized_key_context(self):
        status = self.summary['status']
        self.assertEqual(status['prefix'], 'Only post-only orders allowed ')
        self.assertEqual(status['zero']['text'], 'immediately after network upgrade')
        self.assertEqual(status['nonzero']['text'], 'during extreme L1 congestion')
        self.assertEqual([row['key'] for row in self.summary['serializer_key_context']],
                         ['post_only_until_time', 'post_only_until_height'])

    def test_context_fields_from_prior_debug_writer(self):
        rows = self.summary['previous_context_field_evidence']
        self.assertEqual([(row['field'], row['offset']) for row in rows],
                         [('initial_height', '0x10'), ('height', '0x28'), ('time', '0x60')])
        index = self.image.offset(0x4c6985c, 1, True)
        self.data[index] ^= 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.context_fields(self.image)
        finally:
            self.data[index] ^= 1

    def test_formatter_corruption_rejected(self):
        index = self.image.offset(tool.FORMATTER, 1, True)
        self.data[index] ^= 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.status_info(self.image, 0x74)
        finally:
            self.data[index] ^= 1

    def test_modify_context_checks_and_corruption(self):
        self.assertEqual([row['success_word'] for row in self.summary['modify_context']], [0x186] * 4)
        address = 0x4d1c2ad
        index = self.image.offset(address + 10, 1, True)
        self.data[index] ^= 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.modify_context(self.image, address, 0x4c18260)
        finally:
            self.data[index] ^= 1

    def test_modify_rejection_path_and_corruption(self):
        rows = self.summary['modify_rejection_paths']
        self.assertEqual([r['return'] for r in rows], ['0x4d1cc11', '0x4d1ea41'])
        for address in (0x4d1c5fe, 0x4d1c674, 0x4d1c6ec, 0x4d1cc11):
            index = self.image.offset(address, 1, True)
            self.data[index] ^= 1
            try:
                with self.assertRaises(tool.EvidenceError):
                    tool.modify_rejection_path(self.image, self.summary['modify_context'])
            finally:
                self.data[index] ^= 1

    def test_status_dispatch_corruption_rejected(self):
        index = self.image.offset(0x37ffd40, 1, True)
        self.data[index] ^= 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.status_info(self.image, 0x74)
        finally:
            self.data[index] ^= 1

    def test_reproduce_all_generated_files(self):
        folder = ROOT / 'research/work-items/RE-006-post-only-window-94'
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            tool.write(out, self.summary, self.image)
            for name in ('evidence.json', 'cases.tsv', 'admission.tsv'):
                self.assertEqual((out / name).read_bytes(), (folder / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
