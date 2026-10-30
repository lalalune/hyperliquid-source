"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_drop_thunk_104 as thunk
from elf_index import sections


class DropThunk104EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not thunk.TARGET.is_file() or thunk.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = thunk.inspect(thunk.TARGET)
        cls.data = thunk.TARGET.read_bytes()
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
        record = thunk.ROOT / 'research/work-items/foundation-drop-thunk-104-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_size_edges_from_decoded_formula(self):
        edges = self.result['behavior']['edges']
        self.assertEqual(edges['1'], '0x68')
        self.assertEqual(edges['2'], '0xd0')
        self.assertEqual(edges['16'], '0x680')
        self.assertEqual(edges['255'], '0x6798')
        self.assertEqual(edges['4096'], '0x68000')

    def test_flag_zero_and_call_order(self):
        self.assertEqual(self.result['behavior']['flag_at_tail_jump'], 'rdx = 0 (xor edx,edx, never set otherwise)')
        self.assertEqual(self.result['behavior']['call_order'],
                         'per-element call 0x13ef560 first, then null guard')
        self.assertEqual(self.result['tail_call']['registers'], 'rdi = field+8, rsi = length * 0x68, rdx = 0')

    def test_two_callers_and_neighbor_distinction(self):
        self.assertEqual(self.result['incoming_pattern_scan']['e8_candidates'], ['0x1453a00', '0x14546a7'])
        self.assertIn('landing_pad', self.result['behavior'])

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                thunk.inspect(path)
            path.write_bytes(self.mutated(thunk.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                thunk.inspect(path)

    def test_instruction_mutations_rejected(self):
        cases = [
            (thunk.START + 0, 'instruction window'),
            (thunk.START + 7, 'instruction window'),
            (thunk.START + 18, 'instruction window'),
            (thunk.START + 27, 'instruction window'),
            (thunk.START + 28, 'instruction window'),
            (thunk.START + 61, 'instruction window'),
        ]
        for va, pattern in cases:
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, pattern):
                    thunk.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_per_element_call_mutation_rejected(self):
        # The per-element call bytes sit inside the locked 86-byte body, so a
        # displacement mutation is caught by the body lock first.
        va = 0x14522b7 + 1
        old = self.data[self.offset(va)]
        with self.assertRaisesRegex(ValueError, 'instruction window'):
            thunk.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_tail_jump_mutation_rejected(self):
        # The tail-jump bytes sit inside the locked 86-byte body, so a
        # displacement mutation is caught by the body lock first.
        va = thunk.START + 40
        old = self.data[self.offset(va)]
        with self.assertRaisesRegex(ValueError, 'instruction window'):
            thunk.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_padding_mutation_rejected(self):
        old = self.data[self.offset(thunk.END)]
        with self.assertRaisesRegex(ValueError, 'FDE padding'):
            thunk.analyze(self.mutated(thunk.END, bytes([old ^ 1])))

    def test_fde_extent_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        with self.assertRaisesRegex(ValueError, 'FDE record'):
            thunk.analyze(self.mutated(eh['address'] + 0x2eed18 + 12, struct.pack('<I', 0x55)))

    def test_relocation_target_mutation_rejected(self):
        rel = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rel['offset']:rel['offset'] + rel['size']]
        for off in range(0, len(raw), 24):
            if struct.unpack_from('<Q', raw, off)[0] == thunk.TAIL_SLOT:
                with self.assertRaisesRegex(ValueError, 'Tail-call slot relocation'):
                    thunk.analyze(self.mutated(rel['address'] + off + 16, struct.pack('<q', thunk.TAIL_TARGET + 1)))
                return
        self.fail('Expected GOT relocation missing')

    def test_caller_call_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Call-pattern candidate set'):
            thunk.analyze(self.mutated(thunk.CALL_SITES[0] + 1, b'\x00'))
        with self.assertRaisesRegex(ValueError, 'Call-pattern candidate set'):
            thunk.analyze(self.mutated(thunk.CALL_SITES[1] + 1, b'\x00'))

    def test_retained_disassembly_contains_key_lines(self):
        packet = thunk.ROOT / 'research/work-items/foundation-drop-thunk-104-94'
        window = (packet / 'window.objdump.txt').read_text()
        self.assertIn('14522b0:', window)
        self.assertIn('call   13ef560', window)
        self.assertIn('imul   $0x68', window)
        self.assertIn('jmp    *0x431bd35(%rip)', window)
        self.assertIn('call   5660110', window)
        caller = (packet / 'caller.objdump.txt').read_text()
        self.assertIn('1453a00:', caller)
        self.assertIn('14546a7:', caller)
        self.assertIn('call   14522b0', caller)
