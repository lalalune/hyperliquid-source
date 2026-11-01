"""Actual node94 admission and targeted below-identity corruption controls."""
from pathlib import Path
import struct, sys, unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import fixed_byte_readers_contract as contract
from libcore_fmt_correspondence import Elf

class FixedByteReadersContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (contract.ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.actual = contract.analyze(cls.raw)
        cls.elf = Elf(cls.raw, 3)

    def altered_code(self, address, replacement):
        raw = bytearray(self.raw)
        _, mapping = self.elf.va_bytes(address, len(replacement), executable=True)
        at = mapping['file_offset']
        raw[at:at+len(replacement)] = replacement
        with self.assertRaises(ValueError):
            contract.inspect(bytes(raw))

    def altered_extent(self, index, size):
        raw = bytearray(self.raw)
        at = self.actual['bodies'][index]['frame']['FDE_range_file_offset']
        struct.pack_into('<I', raw, at, size)
        with self.assertRaises(ValueError):
            contract.inspect(bytes(raw))

    def test_actual_complete_family(self):
        self.assertEqual([(b['bytes'], b['certificate']['rows']) for b in self.actual['bodies']],
                         [(102, 32), (115, 37)])
        self.assertEqual(self.actual['all_RELA_records_scanned'], 80300)
        self.assertEqual(self.actual['new_selected_reader_bytes'], 217)
        self.assertEqual(len(self.actual['callers']), 2)

    def test_twenty_byte_mode_comparison_mutation(self):
        # Actual CMP DWORD -> CMP BYTE: high mode bits would be ignored.
        self.altered_code(0x466c143, bytes.fromhex('803e01'))

    def test_thirtytwo_success_layout_mutation(self):
        # Actual XOR ECX,ECX -> MOV CL,1: leading success byte would be wrong.
        self.altered_code(0x466c21e, bytes.fromhex('b101'))

    def test_twenty_charge_width_mutation(self):
        self.altered_code(0x466c156, bytes.fromhex('4883c113'))

    def test_thirtytwo_charge_width_mutation(self):
        self.altered_code(0x466c1c6, bytes.fromhex('4883c11f'))

    def test_twenty_fde_extent_mutation(self):
        self.altered_extent(0, 101)

    def test_thirtytwo_fde_extent_mutation(self):
        self.altered_extent(1, 114)

    def test_twenty_actual_caller_destination_mutation(self):
        self.altered_code(0x4c80b0b, bytes.fromhex('e831b69eff'))

    def test_thirtytwo_actual_caller_destination_mutation(self):
        self.altered_code(0x4779f20, bytes.fromhex('e88c22efff'))

    def test_actual_tpoff64_cross_start_code_writer(self):
        raw = bytearray(self.raw)
        table = next(s for s in self.elf.sections if s['type'] == 4)
        at = table['offset']
        struct.pack_into('<QQq', raw, at, 0x466c140-4, 18, 0)
        with self.assertRaisesRegex(ValueError, 'overlap'):
            contract.inspect(bytes(raw))

    def test_actual_rela_kind_without_admitted_width(self):
        raw = bytearray(self.raw)
        table = next(s for s in self.elf.sections if s['type'] == 4)
        struct.pack_into('<Q', raw, table['offset']+8, 2)
        with self.assertRaisesRegex(ValueError, 'eight-byte width'):
            contract.inspect(bytes(raw))

    def test_whole_target_identity_mutation(self):
        raw = bytearray(self.raw)
        raw[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'Full immutable'):
            contract.analyze(bytes(raw))

if __name__ == '__main__':
    unittest.main()
