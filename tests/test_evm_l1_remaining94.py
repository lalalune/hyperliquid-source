import hashlib
from pathlib import Path
import sys
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_l1_remaining94 as subject


class PatchedView(subject.View):
    def __init__(self, data, changes):
        super().__init__(data)
        self.changes = changes

    def read(self, va, length, executable=False):
        data = bytearray(super().read(va, length, executable))
        for address, value in self.changes.items():
            if va <= address < va + length:
                data[address - va] = value
        return bytes(data)


class RemainingLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.view = subject.View(cls.data)
        cls.summary, cls.windows = subject.analyze(cls.data)

    def test_admitted_identity_and_functions(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.SHA256)
        self.assertEqual(len(self.summary['functions']), 18)
        self.assertEqual(len(self.summary['edges']), 18)
        self.assertEqual(self.summary['field']['name'], 'user_to_evm_to_l1_wei_remaining')
        self.assertEqual(self.summary['field']['state_offset'], '0x3a50')
        self.assertEqual(self.summary['field']['alternate_state_offset'], '0x1f30')
        self.assertEqual(self.summary['format_call']['input_bytes'], 20)
        self.assertEqual(self.summary['format_call']['output_capacity'], 42)
        self.assertEqual(self.summary['format_call']['mode'], '4531c0')

    def test_hash_corruption_rejected(self):
        data = bytearray(self.data)
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            subject.verify_identity(data)
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            subject.analyze(data)

    def test_instruction_corruption_rejected(self):
        for label in ('field_context', 'named_gate', 'entry_pointers', 'array_loop', 'pair_error',
                      'key_format_args', 'json_key_args', 'decimal_single', 'u64_threshold_16', 'u64_big_endian_64',
                      'marker_dispatch', 'array_fix_marker', 'str8_length_store',
                      'collector_size_guard', 'collector_null', 'array_large_branch',
                      'array_large_allocation', 'array_header_result', 'pair_header_result',
                      'alternate_field_context', 'alternate_json_context', 'alternate_json_iter'):
            with self.subTest(label=label):
                address, expected = subject.ANCHORS[label]
                changed = int(expected[:2], 16) ^ 1
                with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                    subject.check_windows(PatchedView(self.data, {address: changed}))

    def test_displacements_and_opcode_corruption(self):
        self.assertEqual(subject.rel32(self.view, 0x27b448c, 0xe9), 0x25ebac0)
        self.assertEqual(subject.rel8(self.view, 0x1dd3943, 0x75), 0x1dd396d)
        self.assertEqual(subject.rip_lea(self.view, 0x27b4461), 0x3ef66c)
        with self.assertRaises(ValueError):
            subject.rel32(PatchedView(self.data, {0x27b448c: 0xe8}), 0x27b448c, 0xe9)
        with self.assertRaises(ValueError):
            subject.rel8(PatchedView(self.data, {0x1dd3943: 0x74}), 0x1dd3943, 0x75)
        self.assertEqual(subject.reljcc32(self.view, 0x1e15d25, 0x85), 0x1e15dde)
        with self.assertRaises(ValueError):
            subject.reljcc32(PatchedView(self.data, {0x1e15d26: 0x84}), 0x1e15d25, 0x85)
        self.assertNotEqual(subject.rel32(PatchedView(self.data, {0x27b448d: 0}), 0x27b448c, 0xe9), 0x25ebac0)

    def test_relocation_and_literal_corruption(self):
        slot = 0x5773120
        self.assertEqual(subject.resolve_relative(self.view, slot), 0x29ed380)
        section = next(s for s in self.view.sections if s['name'] == '.rela.dyn')
        positions = [p for p in range(section['offset'], section['offset'] + section['size'], 24)
                     if struct.unpack_from('<Q', self.data, p)[0] == slot]
        self.assertEqual(len(positions), 1)
        duplicate = bytearray(self.data)
        other = positions[0] + 24 if positions[0] + 48 <= section['offset'] + section['size'] else positions[0] - 24
        struct.pack_into('<Q', duplicate, other, slot)
        with self.assertRaisesRegex(ValueError, 'relocation count'):
            subject.resolve_relative(subject.View(duplicate), slot)
        wrong_type = bytearray(self.data)
        struct.pack_into('<Q', wrong_type, positions[0] + 8, 1)
        with self.assertRaisesRegex(ValueError, 'relocation type'):
            subject.resolve_relative(subject.View(wrong_type), slot)
        original = self.view.read(0x3ef66c, 31)
        damaged = PatchedView(self.data, {0x3ef66c: original[0] ^ 1}).read(0x3ef66c, 31)
        with self.assertRaisesRegex(ValueError, 'field mismatch'):
            subject.require_equal(damaged, b'user_to_evm_to_l1_wei_remaining', 'field')

    def test_non_file_backed_and_invalid_addresses_rejected(self):
        bss = next(s for s in self.view.sections if s['name'] == '.bss')
        for address, size in ((bss['address'], 1), (0, 1), (-1, 1), (0x27b4450, 0)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                self.view.read(address, size)
        with self.assertRaises(ValueError):
            self.view.read(self.summary['field']['address'], 1)
        with self.assertRaises(ValueError):
            self.view.read(int(self.summary['field']['address'], 16), 1, executable=True)

    def test_unsigned_boundary_bytes(self):
        expected = {0: '00', 127: '7f', 128: 'cc80', 255: 'ccff', 256: 'cd0100',
                    65535: 'cdffff', 65536: 'ce00010000', (1 << 32) - 1: 'ceffffffff',
                    1 << 32: 'cf0000000100000000', (1 << 64) - 1: 'cfffffffffffffffff'}
        for n, encoded in expected.items():
            with self.subTest(n=n):
                self.assertEqual(subject.encode_u64(n).hex(), encoded)
        for bad in (-1, 1 << 64, True, 1.5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                subject.encode_u64(bad)

    def test_array_header_boundaries(self):
        expected = {0:'90', 1:'91', 15:'9f', 16:'dc0010', 65535:'dcffff',
                    65536:'dd00010000', (1 << 32) - 1:'ddffffffff'}
        for count, encoded in expected.items():
            with self.subTest(count=count):
                self.assertEqual(subject.encode_array_header(count).hex(), encoded)
        for bad in (-1, 1 << 32, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                subject.encode_array_header(bad)

    def test_modeled_row_and_order(self):
        address = bytes(range(20))
        encoded = subject.encode_rows([(address, 128)])
        self.assertEqual(encoded, b'\x91\x92\xd9\x2a' + b'0x' + b'000102030405060708090a0b0c0d0e0f10111213' + b'\xcc\x80')
        self.assertEqual(subject.encode_rows([]), b'\x90')
        addresses = [bytes([i]) + bytes(19) for i in range(16)]
        a = subject.encode_rows([(x, 0) for x in addresses])
        b = subject.encode_rows([(x, 0) for x in reversed(addresses)])
        self.assertEqual(a[:3], b'\xdc\x00\x10')
        self.assertNotEqual(a, b)  # The model consumes its given order; it does not sort.
        for key in (b'', bytes(19), bytes(21), '00' * 20):
            with self.subTest(key=key), self.assertRaises(ValueError):
                subject.encode_rows([(key, 1)])

    def test_generated_boundary_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(self.data, out)
            counts = (out / 'count-headers.tsv').read_text().splitlines()
            self.assertEqual(counts[1:], ['0\t90', '1\t91', '15\t9f', '16\tdc0010',
                                           '65535\tdcffff', '65536\tdd00010000',
                                           '4294967295\tddffffffff'])
            amounts = [int(line.split('\t')[2]) for line in (out / 'examples.tsv').read_text().splitlines()[1:]]
            self.assertEqual(amounts, [0, 127, 128, 255, 256, 65535, 65536,
                                       4294967295, 4294967296, 18446744073709551615])

    def test_recorded_branches(self):
        branch = {r['role']: r for r in self.summary['branches']}
        self.assertEqual(branch['named mode zero bypasses key']['target_va'], '0x27b4481')
        self.assertEqual(branch['key writer failure']['target_va'], '0x27b4491')
        self.assertEqual(branch['pair key failure']['target_va'], branch['pair value failure']['target_va'])
        self.assertEqual(branch['alternate pair key failure']['target_va'], branch['alternate pair value failure']['target_va'])
        self.assertEqual(branch['collector size valid']['target_va'], '0x2566e0c')
        self.assertEqual(branch['collector allocation null']['target_va'], '0x2567093')
        self.assertEqual(branch['array count exceeds u32']['target_va'], '0x1e15e02')
        self.assertEqual(branch['outer header failure']['target_va'], '0x1e15dde')
        self.assertEqual(branch['pair header failure']['target_va'], '0x1dd39be')
        self.assertEqual(branch['JSON invalid field state']['target_va'], '0x295af10')
        self.assertEqual(branch['JSON value success']['target_va'], '0x295af05')
        self.assertEqual(branch['alternate JSON field tag 1']['target_va'], '0x3c87980')
        self.assertEqual(branch['alternate JSON value success']['target_va'], '0x3c87975')


if __name__ == '__main__':
    unittest.main()
