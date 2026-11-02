import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'research/work-items/RE-001-indexed-create-format-94/verify.py'
SPEC = importlib.util.spec_from_file_location('indexed_format_verify', PATH)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ObjdumpDisplayTests(unittest.TestCase):
    verify = VERIFY

    def test_input_label_only(self):
        a = b'work/node.bin:     file format elf64-x86-64\n'
        b = b'artifacts/node/94/hl-node:     file format elf64-x86-64\n'
        self.assertEqual(self.verify.canonical_objdump_display(a), self.verify.canonical_objdump_display(b))

    def test_default_segment_spelling_for_exact_string_encodings(self):
        for opcode, before, after in [
            (b'a5', b'rep movsq %ds:(%rsi),%es:(%rdi)', b'rep movsq (%rsi),(%rdi)'),
            (b'ab', b'rep stos %rax,%es:(%rdi)', b'rep stos %rax,(%rdi)'),
        ]:
            prefix = b' 540a082:\tf3 48 ' + opcode + b'  \t'
            self.assertEqual(self.verify.canonical_objdump_display(prefix + before),
                             self.verify.canonical_objdump_display(prefix + after))

    def test_changed_bytes_and_addresses_remain_visible(self):
        original = b' 540a082:\tf3 48 a5  \trep movsq %ds:(%rsi),%es:(%rdi)'
        for changed in [original.replace(b'a5', b'a4'), original.replace(b'540a082', b'540a083')]:
            self.assertNotEqual(self.verify.canonical_objdump_display(original),
                                self.verify.canonical_objdump_display(changed))

    def test_other_segment_and_register_changes_remain_visible(self):
        original = b' 540a082:\tf3 48 a5  \trep movsq %ds:(%rsi),%es:(%rdi)'
        for changed in [original.replace(b'%ds:', b'%fs:'), original.replace(b'%rdi', b'%rcx')]:
            self.assertNotEqual(self.verify.canonical_objdump_display(original),
                                self.verify.canonical_objdump_display(changed))

    def test_non_string_instructions_are_not_normalized(self):
        original = b' 12:\t64 48 8b 00 \tmov %fs:(%rax),%rax'
        self.assertEqual(self.verify.canonical_objdump_display(original), original)


def load_verifier(name):
    path = PATH.parents[1] / name / "verify.py"
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SnapshotDisplayTests(ObjdumpDisplayTests):
    verify = load_verifier("RE-001-snapshot-identity-format-94")


class TimedSnapshotDisplayTests(ObjdumpDisplayTests):
    verify = load_verifier("RE-001-timed-snapshot-94")
