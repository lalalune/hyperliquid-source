import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import async_gate_release_52790_115 as subject


class AsyncGateRelease52790Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = subject.produce()
        cls.body = bytes.fromhex(cls.record['body_hex'])

    def test_exact_target_scope_and_evidence(self):
        self.assertEqual(self.record, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(len(self.body), 126)
        self.assertEqual(self.record['native_instructions'], 38)
        self.assertEqual(self.record['panic_string']['text'],
                         'panic in a destructor during cleanup')
        self.assertEqual(self.record['resume']['symbol'], '_Unwind_Resume')
        self.assertFalse(self.record['gates_changed'])

    def test_census_matches_the_sibling_caller_set(self):
        census = self.record['census']
        self.assertEqual(len(census['direct_call_sites']), 12)
        self.assertEqual(census['direct_tail_jumps'], [])
        self.assertEqual(len(census['caller_fdes']), 10)
        self.assertEqual(census['stored_qwords'], [])
        self.assertEqual(census['relative_addends'], [])
        self.assertTrue(census['sibling']['same_caller_fde_set'])
        self.assertEqual(len(census['sibling']['direct_sites']), 10)

    def test_slots_resolve_to_the_destructor_pair(self):
        resolved = {entry['slot']: entry['resolved']
                    for entry in self.record['indirect_slots']}
        self.assertEqual(resolved[0x64dfdb8], 0x5ce86d0)
        self.assertEqual(resolved[0x64dfdc8], 0x5ce8da0)
        self.assertEqual(resolved[0x64df4c0], 0x1680cab)

    def test_wrong_target(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.produce(b'not node115')

    def mutate(self, pc, original, altered):
        original, altered = bytes.fromhex(original), bytes.fromhex(altered)
        offset = pc - subject.START
        self.assertEqual(self.body[offset:offset + len(original)], original)
        body = self.body[:offset] + altered + self.body[offset + len(original):]
        with self.assertRaisesRegex(ValueError, 'Gate instruction changed'):
            subject.check_body(body)

    def test_first_tag_offset_is_0x90(self):
        self.mutate(0x5a52794, '80bf9000000003', '80bf9100000003')

    def test_first_tag_value_is_three(self):
        self.mutate(0x5a52794, '80bf9000000003', '80bf9000000002')

    def test_second_tag_offset_is_0x88(self):
        self.mutate(0x5a5279d, '80bf8800000003', '80bf8900000003')

    def test_counter_field_offset_is_0x20(self):
        self.mutate(0x5a527a9, '4883c720', '4883c721')

    def test_flag_offset_is_0x18(self):
        self.mutate(0x5a527b0, '80781800', '80781900')

    def test_flag_zero_takes_the_second_destructor_path(self):
        self.mutate(0x5a527b4, '7419', '7519')

    def test_counter_release_is_a_locked_decrement(self):
        self.mutate(0x5a527b9, 'f048ff08', 'f048ff00')

    def test_nonzero_count_skips_the_destructor(self):
        self.mutate(0x5a527bd, '751f', '741f')

    def test_flag_nonzero_calls_through_the_first_slot(self):
        self.mutate(0x5a527bf, 'ff1503d6a800', 'ff1503d6a801')

    def test_tail_field_offset_is_0x28(self):
        self.mutate(0x5a527e1, '4883c728', '4883c729')

    def test_tail_release_target_is_0x5a52490(self):
        self.mutate(0x5a527ec, 'e99ffcffff', 'e99ffcfffe')

    def test_pad_releases_the_same_field_before_resume(self):
        self.mutate(0x5a527fb, 'e890fcffff', 'e88ffcffff')

    def test_truncated_body(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete native decode'):
            subject.check_body(self.body[:-1])


if __name__ == '__main__':
    unittest.main()
