import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_execution_projection as subject


class ExecutionProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = subject.produce()
        cls.body = bytes.fromhex(cls.record['body_hex'])

    def test_exact_scope(self):
        self.assertEqual(self.record, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(len(self.body), 1694)
        self.assertEqual(self.record['native_instructions'], 336)
        self.assertEqual([x['line'] for x in self.record['source_locations']],
                         [128, 138, 139, 153, 154, 155])
        self.assertFalse(self.record['gates_changed'])

    def mutate(self, pc, original, altered):
        original, altered = bytes.fromhex(original), bytes.fromhex(altered)
        offset = pc - subject.START
        self.assertEqual(self.body[offset:offset + len(original)], original)
        body = self.body[:offset] + altered + self.body[offset + len(original):]
        with self.assertRaisesRegex(ValueError, 'Projection instruction changed'):
            subject.check_body(body)

    def test_first_empty_must_skip_state_store(self):
        self.mutate(0x2af7445, '741c', '751c')

    def test_second_empty_must_skip_state_store(self):
        self.mutate(0x2af746e, '747e', '757e')

    def test_first_tie_disposition(self):
        self.mutate(0x2af758f, '7fcf', '7dcf')

    def test_second_tie_disposition(self):
        self.mutate(0x2af74cd, '4c0f4efd', '4c0f4cfd')

    def test_projection_fifth_byte(self):
        self.mutate(0x2af7654, '440fb64c3e04', '440fb64c3e05')

    def test_projection_input_stride(self):
        self.mutate(0x2af7665, '4883c750', '4883c740')

    def test_projection_output_stride(self):
        self.mutate(0x2af7661, '4883c205', '4883c204')

    def test_unrolled_input_stride(self):
        self.mutate(0x2af7612, '4881c740010000', '4881c740000000')

    def test_wrong_target(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.produce(b'not node115')

    def test_truncated_decode(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete native decode'):
            subject.check_body(self.body[:-1])


if __name__ == '__main__':
    unittest.main()
