"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_dealloc_size_generic as dealloc
from elf_index import sections


class GenericDeallocSizeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not dealloc.TARGET.is_file() or dealloc.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = dealloc.inspect(dealloc.TARGET)
        cls.data = dealloc.TARGET.read_bytes()
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
        record = dealloc.ROOT / 'research/work-items/foundation-dealloc-size-generic-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_arithmetic_edges_from_decoded_formula(self):
        edges = self.result['arithmetic']['edges']
        self.assertEqual(edges['count=1,align=16,elem=8'],
                         {'padded': '0x10', 'pad': '0x10', 'size': '0x22', 'flag': 0})
        self.assertEqual(edges['count=1,align=32,elem=8'],
                         {'padded': '0x10', 'pad': '0x20', 'size': '0x32', 'flag': 5})
        self.assertEqual(edges['count=3,align=8,elem=24'],
                         {'padded': '0x60', 'pad': '0x60', 'size': '0x74', 'flag': 0})
        self.assertEqual(edges['count=2,align=24,elem=16'],
                         {'padded': '0x30', 'pad': '0x40', 'size': '0x53', 'flag': 3})
        self.assertEqual(edges['count=5,align=17,elem=4'],
                         {'padded': '0x18', 'pad': '0x28', 'size': '0x3e', 'flag': 0})
        self.assertEqual(edges['count=1,align=64,elem=1'],
                         {'padded': '0x2', 'pad': '0x40', 'size': '0x52', 'flag': 6})

    def test_zero_count_early_return_and_grid_flag_rule(self):
        self.assertIsNone(dealloc.compute(0, 16, 8))
        self.assertEqual(self.result['arithmetic']['nonwrapping_grid_cases'], 4800)
        self.assertEqual(self.result['arithmetic']['nonwrapping_flag_rule'],
                         'tzcnt(align) if align >= 0x11 else 0')

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                dealloc.inspect(path)
            path.write_bytes(self.mutated(dealloc.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                dealloc.inspect(path)

    def test_instruction_mutations_rejected(self):
        cases = [
            (dealloc.START + 3, 'instruction window'),
            (dealloc.START + 12, 'instruction window'),
            (dealloc.START + 21, 'instruction window'),
            (dealloc.START + 44, 'instruction window'),
            (dealloc.START + 55, 'instruction window'),
            (dealloc.START + 75, 'instruction window'),
        ]
        for va, pattern in cases:
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, pattern):
                    dealloc.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_tail_jump_mutation_rejected(self):
        # The tail-jump bytes sit inside the locked 86-byte body, so a
        # displacement mutation is caught by the body lock first.
        va = dealloc.START + 79
        old = self.data[self.offset(va)]
        with self.assertRaisesRegex(ValueError, 'instruction window'):
            dealloc.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_padding_mutation_rejected(self):
        old = self.data[self.offset(dealloc.END)]
        with self.assertRaisesRegex(ValueError, 'FDE padding'):
            dealloc.analyze(self.mutated(dealloc.END, bytes([old ^ 1])))

    def test_fde_extent_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        with self.assertRaisesRegex(ValueError, 'FDE record'):
            dealloc.analyze(self.mutated(eh['address'] + 0x8260 + 12, struct.pack('<I', 0x55)))

    def test_relocation_target_mutation_rejected(self):
        rel = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rel['offset']:rel['offset'] + rel['size']]
        for off in range(0, len(raw), 24):
            if struct.unpack_from('<Q', raw, off)[0] == dealloc.TAIL_SLOT:
                with self.assertRaisesRegex(ValueError, 'Tail-call slot relocation'):
                    dealloc.analyze(self.mutated(rel['address'] + off + 16, struct.pack('<q', dealloc.TAIL_TARGET + 1)))
                return
        self.fail('Expected GOT relocation missing')

    def test_caller_call_mutation_rejected(self):
        site = sorted(dealloc.CALL_SITES)[0]
        with self.assertRaisesRegex(ValueError, 'Call-pattern candidate set'):
            dealloc.analyze(self.mutated(site + 1, b'\x00'))

    def test_retained_disassembly_contains_key_lines(self):
        packet = dealloc.ROOT / 'research/work-items/foundation-dealloc-size-generic-94'
        window = (packet / 'window.objdump.txt').read_text()
        self.assertIn('140e430:', window)
        self.assertIn('imul   0x8(%rdi),%rcx', window)
        self.assertIn('tzcnt  %rax,%rcx', window)
        self.assertIn('jmp    *0x435fb8b(%rip)', window)
        frames = (packet / 'frames.txt').read_text()
        self.assertIn('pc=000000000140e430..000000000140e486', frames)


if __name__ == '__main__':
    unittest.main()
