"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_dealloc_size as dealloc
from elf_index import sections


class DeallocSizeEvidenceTests(unittest.TestCase):
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
        record = dealloc.ROOT / 'research/work-items/foundation-dealloc-size-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_arithmetic_edges_from_decoded_formula(self):
        edges = self.result['arithmetic']['edges']
        self.assertEqual(edges['1'], {'aligned': '0xb0', 'size': '0xc2', 'flag': '0x0'})
        self.assertEqual(edges['15'], {'aligned': '0x580', 'size': '0x5a0', 'flag': '0x0'})
        self.assertEqual(edges['16'], {'aligned': '0x5e0', 'size': '0x601', 'flag': '0x0'})
        self.assertEqual(edges['255'], {'aligned': '0x5800', 'size': '0x5910', 'flag': '0x0'})
        self.assertEqual(edges['4096'], {'aligned': '0x58060', 'size': '0x59071', 'flag': '0x0'})

    def test_flag_always_zero_on_nonwrapping_inputs(self):
        for n in (1, 2, 15, 16, 100, 4096, 10000):
            self.assertEqual(dealloc.flag_of(n), 0)
            self.assertGreaterEqual(dealloc.size_of(n), 0xc2)
        self.assertTrue(self.result['arithmetic']['flag_always_zero_nonwrapping'])
        self.assertEqual(self.result['arithmetic']['checked_nonwrapping_counts'], 10000)

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
            (dealloc.START + 16, 'instruction window'),
            (dealloc.START + 27, 'instruction window'),
            (dealloc.START + 41, 'instruction window'),
            (dealloc.START + 47, 'instruction window'),
        ]
        for va, pattern in cases:
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, pattern):
                    dealloc.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_tail_jump_mutation_rejected(self):
        # The tail-jump bytes sit inside the locked 55-byte body, so a
        # displacement mutation is caught by the body lock first.
        va = dealloc.START + 50
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
            dealloc.analyze(self.mutated(eh['address'] + 0x88e4 + 12, struct.pack('<I', 0x38)))

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
        with self.assertRaisesRegex(ValueError, 'Call-pattern candidate set'):
            dealloc.analyze(self.mutated(dealloc.CALL_SITE + 1, b'\x00'))

    def test_retained_disassembly_contains_key_lines(self):
        packet = dealloc.ROOT / 'research/work-items/foundation-dealloc-size-94'
        window = (packet / 'window.objdump.txt').read_text()
        self.assertIn('1417c40:', window)
        self.assertIn('imul   $0x58', window)
        self.assertIn('jmp    *0x435639a(%rip)', window)
        caller = (packet / 'caller.objdump.txt').read_text()
        self.assertIn('143f645:', caller)
        self.assertIn('call   1417c40', caller)


if __name__ == '__main__':
    unittest.main()
