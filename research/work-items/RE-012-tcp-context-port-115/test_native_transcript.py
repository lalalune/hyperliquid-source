"""Controls for the declared native-transcript line-ending comparison."""
import unittest
import collect


class TranscriptComparison(unittest.TestCase):
    def setUp(self):
        collect._NATIVE_PRIOR_COMPARISONS.clear()

    def test_exact_output_remains_raw_equal(self):
        raw = b" 1000: 48 89 f8 mov rax,rdi\n"
        self.assertTrue(collect.compare_prior_native(raw, raw))
        self.assertTrue(collect._NATIVE_PRIOR_COMPARISONS[-1]['raw_equal'])

    def test_line_endings_are_explicitly_qualified(self):
        current = b" 1000: 48 89 f8 mov rax,rdi\n"
        retained = b" 1000: 48 89 f8 mov rax,rdi\r\n"
        self.assertTrue(collect.compare_prior_native(current, retained))
        row = collect._NATIVE_PRIOR_COMPARISONS[-1]
        self.assertFalse(row['raw_equal'])
        self.assertTrue(row['line_ending_only_difference'])
        self.assertNotEqual(row['current_sha256'], row['retained_sha256'])

    def test_changed_instruction_bytes_are_refused(self):
        with self.assertRaises(ValueError):
            collect.compare_prior_native(b"1000: 48 89 f9 mov rax,rdi\n",
                                         b"1000: 48 89 f8 mov rax,rdi\r\n")

    def test_changed_operand_text_is_refused(self):
        with self.assertRaises(ValueError):
            collect.compare_prior_native(b"1000: 48 89 f8 mov rax,rsi\n",
                                         b"1000: 48 89 f8 mov rax,rdi\r\n")


if __name__ == '__main__':
    unittest.main()
