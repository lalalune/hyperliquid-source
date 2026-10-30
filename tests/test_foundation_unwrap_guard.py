"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_unwrap_guard as guard
from elf_index import sections


class UnwrapGuardEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not guard.TARGET.is_file() or guard.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = guard.inspect(guard.TARGET)
        cls.data = guard.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def test_retained_record_matches_authenticated_target(self):
        record = guard.ROOT / 'research/work-items/foundation-unwrap-guard-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_sign_test_edges_from_decoded_operands(self):
        sign = self.result['sign_test']
        self.assertEqual(sign['panic_arm_va'], '0x151026d')
        self.assertEqual(sign['non_negative_path'], 'xor edx,edx then tail call')
        # The js displacement is +8 from the branch end; the panic arm starts
        # exactly at the next window instruction after the tail-call jump.
        self.assertEqual(self.result['function']['bytes'], 51)
        self.assertEqual(self.result['function']['padding_bytes'], 13)
        self.assertEqual(self.result['panic_arm']['message_length'], 43)

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                guard.inspect(path)
            path.write_bytes(self.mutated(guard.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                guard.inspect(path)

    def test_instruction_mutations_rejected(self):
        for va in [guard.START, guard.START + 3, guard.START + 5,
                   guard.START + 7, guard.START + 13, guard.START + 40,
                   guard.START + 45]:
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, 'instruction window|Sign test|Panic branch|Non-negative|Tail-call|Panic arm|Message length|Panic helper'):
                    guard.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_fde_extent_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        with self.assertRaisesRegex(ValueError, 'FDE record'):
            guard.analyze(self.mutated(eh['address'] + 0x13ca4 + 12, struct.pack('<I', 52)))

    def test_padding_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'FDE padding'):
            guard.analyze(self.mutated(guard.END, b'\x90'))

    def test_message_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Panic message'):
            guard.analyze(self.mutated(0x21da2e, b'X'))

    def test_path_string_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Argument path'):
            guard.analyze(self.mutated(0x2005f6, b'X'))

    def test_relocation_target_mutations_rejected(self):
        rel = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rel['offset']:rel['offset'] + rel['size']]
        found = set()
        for off in range(0, len(raw), 24):
            address = struct.unpack_from('<Q', raw, off)[0]
            if address in (0x576e010, 0x576e048, 0x5670b58):
                found.add(address)
                with self.subTest(slot=hex(address)):
                    with self.assertRaisesRegex(ValueError, 'Relative relocation'):
                        guard.analyze(self.mutated(rel['address'] + off + 16, struct.pack('<q', 0x1000)))
        self.assertEqual(found, {0x576e010, 0x576e048, 0x5670b58})

    def test_argument_slot_field_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'r8 slot fields'):
            guard.analyze(self.mutated(0x5670b58 + 8, struct.pack('<Q', 92)))
        with self.assertRaisesRegex(ValueError, 'rcx slot fields'):
            guard.analyze(self.mutated(0x56709e8 + 16, struct.pack('<Q', 2)))

    def test_tail_fde_extent_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        with self.assertRaisesRegex(ValueError, 'FDE record'):
            guard.analyze(self.mutated(eh['address'] + 0x2bff84 + 12, struct.pack('<I', 166)))


if __name__ == '__main__':
    unittest.main()
