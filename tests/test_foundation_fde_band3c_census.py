import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import foundation_fde_band3c_census as census


class InstructionRows(unittest.TestCase):
    def test_byte_only_continuation_row_is_not_an_instruction(self):
        output = '''\
  1000: 48 0f 6e c0        movd   %eax,%mm0
  1004: 01 02 03 04
  1008: cc                 int3
'''
        addresses, byte_count = census.parse_objdump(output)
        self.assertEqual(addresses, [0x1000, 0x1008])
        self.assertEqual(byte_count, 9)

    def test_known_band3b_corrected_instruction_count(self):
        _, count, decoded = census.disassemble(ROOT / 'artifacts/node/115/hl-node',
                                               0x3a7d0d0, 0x3a7d7fc)
        self.assertEqual((count, decoded), (412, 0x72c))


class PacketControls(unittest.TestCase):
    def test_complete_saved_packet_rederives_from_node115(self):
        evidence = census.verify()
        self.assertEqual(evidence['fde_count'], 214)
        self.assertEqual(evidence['band'], {'start': '0x3a80000', 'end': '0x3ac0000',
                                            'rule': 'FDE start in half-open band'})
        self.assertEqual((evidence['fdes'][-1]['start'], evidence['fdes'][-1]['end']),
                         ('0x3abf4c0', '0x3ac0177'))

    def test_manifest_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            packet = Path(temp)
            for name in census.REQUIRED:
                source = census.PACKET / name
                (packet / name).write_bytes(source.read_bytes())
            (packet / 'window.txt').write_text((packet / 'window.txt').read_text().replace(
                'prologue_hex=', 'prologue_hex=00', 1), encoding='utf-8')
            with self.assertRaisesRegex(AssertionError, 'manifest mismatch'):
                census.verify_manifest(packet)


if __name__ == '__main__':
    unittest.main()
