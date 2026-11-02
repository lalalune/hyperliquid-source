"""Copied-input rejection checks for this task's ELF evidence, never execution."""
import importlib.util
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tagged_pair_collect', HERE / 'collect.py')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class NativeEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (subject.ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.record = subject.analyze(cls.data)
        cls.image = subject.Elf(cls.data, 3)

    def changed(self, offset, raw, match):
        data = bytearray(self.data)
        data[offset:offset + len(raw)] = raw
        with self.assertRaisesRegex(ValueError, match):
            subject.derive(bytes(data))

    def test_complete_positive_scope(self):
        self.assertEqual(self.record['new_native_denominator'], {'bytes': 318, 'rows': 86})
        self.assertEqual(self.record['RELA_entries'], 80300)

    def test_full_target_hash(self):
        data = bytearray(self.data)
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'Target identity'):
            subject.analyze(bytes(data))

    def test_each_new_complete_body_below_full_hash(self):
        for role in ['primary', 'context-u64-wrapper', 'context-u64-reader', 'context-error']:
            with self.subTest(role=role):
                at = self.record['functions'][role]['mapping']['file_offset']
                self.changed(at, bytes([self.data[at] ^ 1]), 'Complete ' + role)

    def test_actual_literal(self):
        at = self.image.va_bytes(0x6f86ca, 1)[1]['file_offset']
        self.changed(at, b'x', 'literal.*differs')

    def test_cross_start_literal_relocation(self):
        at = self.record['bindings'][0]['record_file_offset']
        self.changed(at, struct.pack('<Q', 0x6f86ca - 4), 'overlap literal')

    def test_cross_start_code_relocation(self):
        at = self.record['bindings'][0]['record_file_offset']
        self.changed(at, struct.pack('<Q', 0x466c770 - 4), 'overlap selected code')

    def test_selected_actual_addend(self):
        item = self.record['bindings'][0]
        self.changed(item['record_file_offset'] + 16, struct.pack('<q', item['addend'] + 1), 'slot binding')

    def test_competing_partial_slot_write(self):
        first, second = self.record['bindings'][:2]
        self.changed(second['record_file_offset'], struct.pack('<Q', first['slot'] + 4), 'slot binding')

    def test_code_executable_permission(self):
        phoff = struct.unpack_from('<Q', self.data, 32)[0]
        phsize, phcount = struct.unpack_from('<HH', self.data, 54)
        base = 0x466c770
        for i in range(phcount):
            at = phoff + i * phsize
            kind, flags, _, address, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', self.data, at)
            if kind == 1 and address <= base < address + size:
                self.changed(at + 4, struct.pack('<I', flags & ~1), 'mapping|executable')
                return
        self.fail('actual code segment missing')

    def test_actual_fde_extent(self):
        va = self.record['functions']['primary']['FDE']['fde']
        at = self.image.va_bytes(va, 16)[1]['file_offset'] + 12
        length = struct.unpack_from('<I', self.data, at)[0]
        self.changed(at, struct.pack('<I', length - 1), 'FDE extent')

    def test_actual_opaque_context(self):
        at = self.image.va_bytes(0x203f40, 16)[1]['file_offset']
        self.changed(at, b'x', 'opaque-context.*differs')

    def test_both_actual_scalar_tables(self):
        for base in [0x6f6ea8, 0x6f6ed8]:
            with self.subTest(base=hex(base)):
                at = self.image.va_bytes(base, 16)[1]['file_offset']
                self.changed(at, bytes([self.data[at] ^ 1]), 'scalar-.*data differs')

    def test_cross_start_context_relocation(self):
        at = self.record['bindings'][0]['record_file_offset']
        self.changed(at, struct.pack('<Q', 0x203f40 - 4), 'overlap opaque-context')

    def test_selected_existing_caller_edge(self):
        at = self.image.va_bytes(0x438b79b, 5)[1]['file_offset']
        self.changed(at, b'\xe9', 'selected direct call')

    def test_unknown_relocation_width(self):
        item = self.record['bindings'][0]
        self.changed(item['record_file_offset'] + 8, struct.pack('<Q', 5), 'Unknown relocation')


if __name__ == '__main__':
    unittest.main()
