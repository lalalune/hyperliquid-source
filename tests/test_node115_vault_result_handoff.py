"""Real-input static relation replay and structural corruption controls."""
from pathlib import Path
import importlib.util
import unittest

SPEC = importlib.util.spec_from_file_location("vault_handoff", Path("research/work-items/RE-001-node115-vault-result-handoff/verify.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class Handoff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.coordinates.TARGET.read_bytes()
        cls.binding = m.coordinates.structural(cls.data)

    def test_authenticated_native_relation(self):
        result = m.verify()
        self.assertEqual(result["validated_relations"], result["selected_relation_denominator"])
        self.assertEqual(result["location_stack_offset_at_callee_entry"], "0x18")

    def corrupt(self, va, message):
        data = bytearray(self.data)
        data[self.binding["instruction_file_offset"] + va - m.coordinates.XREF] ^= 1
        with self.assertRaisesRegex(ValueError, message):
            m.structural(data)  # Deliberately bypass digest, exercising the relation assertion.

    def test_output_pointer(self): self.corrupt(0x283c6c0, "wrapper prelude")
    def test_result_buffer(self): self.corrupt(0x283c6e7, "argument setup")
    def test_location_push(self): self.corrupt(0x283c6fb, "argument setup")
    def test_push_order(self): self.corrupt(0x283c6fd, "argument setup")
    def test_call_opcode(self): self.corrupt(0x283c6ff, "direct call opcode")
    def test_call_destination(self): self.corrupt(0x283c700, "direct call destination")
    def test_stack_restore(self): self.corrupt(0x283c707, "stack restoration")
    def test_comparison(self): self.corrupt(0x283c70f, "result comparison")
    def test_branch_predicate(self): self.corrupt(0x283c711, "equal branch opcode")
    def test_branch_destination(self): self.corrupt(0x283c712, "equal branch destination")
    def test_payload_source(self): self.corrupt(0x283c717, "payload projection")
    def test_payload_destination(self): self.corrupt(0x283c71e, "payload projection")
    def test_non_equal_tag(self): self.corrupt(0x283c759, "payload projection")
    def test_shared_tag_store(self): self.corrupt(0x283c75b, "shared tag store")


if __name__ == "__main__": unittest.main()
