import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_retry_state as subject


class RetryStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = subject.produce()
        cls.body = bytes.fromhex(cls.record['body_hex'])

    def test_exact_target_and_bound_caller(self):
        self.assertEqual(self.record, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(len(self.body), 2727)
        self.assertEqual(self.record['native_instructions'], 544)
        self.assertEqual(self.record['caller_context']['exported_instructions'], 8)
        self.assertEqual([x['line'] for x in self.record['source_locations']], [30, 32, 41])
        self.assertFalse(self.record['gates_changed'])

    def mutate(self, pc, original, altered):
        original, altered = bytes.fromhex(original), bytes.fromhex(altered)
        offset = pc - subject.START
        self.assertEqual(self.body[offset:offset + len(original)], original)
        body = self.body[:offset] + altered + self.body[offset + len(original):]
        with self.assertRaisesRegex(ValueError, 'Retry instruction changed'):
            subject.check_body(body)

    def test_attempt_limit_is_unsigned(self):
        self.mutate(0x2a6471c, '0f835cfbffff', '0f8d5cfbffff')

    def test_attempt_increment_is_one(self):
        self.mutate(0x2a64722, '488d4101', '488d4102')

    def test_pending_persists_outer_state_three(self):
        self.mutate(0x2a64a2e, 'b003', 'b001')

    def test_ready_persists_outer_state_one(self):
        self.mutate(0x2a64ac7, 'b001', 'b003')

    def test_wait_helper_pending_branch(self):
        self.mutate(0x2a646aa, '0f8562030000', '0f8462030000')

    def test_retry_tag_two_is_not_ready(self):
        self.mutate(0x2a6488a, '0f85a5010000', '0f84a5010000')

    def test_old_empty_result_skips_deallocation(self):
        self.mutate(0x2a6493e, '740f', '750f')

    def test_operation_descriptor_has_second_half(self):
        self.mutate(0x2a6474d, '0f118be0000000', '0f118bd0000000')

    def test_every_dispatch_table_entry_rejects_corruption(self):
        starts = {i.address for i in subject.check_body(self.body)}
        for row in self.record['dispatch_tables']:
            raw = bytes.fromhex(row['raw_hex'])
            for offset in range(0, len(raw), 4):
                altered = bytearray(raw)
                altered[offset] ^= 1
                with self.subTest(table=hex(row['va']), entry=offset // 4):
                    with self.assertRaisesRegex(ValueError, 'dispatch table changed'):
                        subject.check_table(row['va'], altered, starts)

    def test_wrong_target(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.produce(b'not node115')

    def test_truncated_decode(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete native decode'):
            subject.check_body(self.body[:-1])


if __name__ == '__main__':
    unittest.main()
