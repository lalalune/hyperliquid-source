"""Target-grounded static checks and corruption controls; no capture execution."""
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_four_slot_exchange as bind

PACKET = ROOT / 'research/work-items/RE-001-node115-four-slot-exchange'


class FourSlotExchange(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((PACKET / 'records.json').read_text())
        cls.body = bytes.fromhex(cls.record['window']['body_hex'])

    def test_records_regenerate(self):
        with tempfile.TemporaryDirectory() as temp:
            subprocess.run([sys.executable, str(ROOT / 'tools/node115_four_slot_exchange.py'), '--out', temp], check=True)
            self.assertEqual((Path(temp) / 'records.json').read_bytes(), (PACKET / 'records.json').read_bytes())

    def test_wrong_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, out = Path(temp) / 'bad', Path(temp) / 'out'
            binary.write_bytes(b'not node 115')
            result = subprocess.run([sys.executable, str(ROOT / 'tools/node115_four_slot_exchange.py'), '--binary', str(binary), '--out', str(out)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'digest mismatch', result.stderr)
            self.assertFalse(out.exists())

    def test_every_instruction_and_branch_corruption(self):
        rows = bind.decode(self.body)
        self.assertEqual(rows, self.record['instructions'])
        for row in rows:
            offset = row['va'] - bind.START
            mutated = bytearray(self.body)
            mutated[offset] ^= 1
            with self.subTest(address=row['va']), self.assertRaises(ValueError):
                bind.decode(mutated)
        mutated = bytearray(self.body)
        mutated[9] ^= 1  # branch displacement
        with self.assertRaises(ValueError):
            bind.decode(mutated)

    def test_shifted_fde_and_wrong_relocation_target(self):
        frame = bytearray(bytes.fromhex(self.record['fde']['bytes_hex']))
        bind.check_frame(frame)
        frame[8] ^= 1
        with self.assertRaises(ValueError):
            bind.check_frame(frame)
        for relocation in self.record['relative_relocations']:
            raw = bytearray.fromhex(relocation['bytes_hex'])
            bind.check_relocation(raw, relocation['slot_va'])
            raw[16] ^= 1
            with self.assertRaises(ValueError):
                bind.check_relocation(raw, relocation['slot_va'])

    def test_rel32_scans_unaligned_candidates_and_tail(self):
        base = bind.START - 100
        data = bytearray(b'\x90' * 100)
        for pos, opcode in ((1, 0xe8), (95, 0xe9)):
            data[pos] = opcode
            struct.pack_into('<i', data, pos + 1, bind.START - (base + pos + 5))
        section = {'address': base, 'offset': 0, 'size': len(data)}
        rows = bind.scan_rel32(bytes(data), section)
        self.assertEqual([(r['site'], r['opcode']) for r in rows], [(base + 1, 'e8'), (base + 95, 'e9')])
        data[2] ^= 1
        self.assertEqual(len(bind.scan_rel32(bytes(data), section)), 1)

    def test_exchange_vectors(self):
        for n in range(8):
            original = [bytes([i]) * 32 for i in range(n)]
            actual, status = bind.model(original)
            if n < 4:
                self.assertEqual((actual, status), (original, 0x2c))
            else:
                expected = original[:n-4] + [original[-1]] + original[n-3:n-1] + [original[-4]]
                self.assertEqual(actual, expected)
                self.assertEqual(status, 0)
                self.assertEqual(original, [bytes([i]) * 32 for i in range(n)])

    def test_readme_counts_match_records(self):
        text = (PACKET / 'README.md').read_text()
        line = re.search(r'\*\*(\d+) instructions; (\d+) callees; (\d+) direct rel32 candidates; (\d+) relative relocations\*\*', text)
        self.assertIsNotNone(line)
        self.assertEqual(tuple(map(int, line.groups())), tuple(len(self.record[key]) for key in ('instructions', 'callees', 'direct_rel32_candidates', 'relative_relocations')))
        self.assertEqual(self.record['window']['size'], len(self.body))
        self.assertEqual(len(self.body), 64)
        self.assertEqual(len(bytes.fromhex(self.record['window']['preceding_padding_hex'])), 4)
        self.assertEqual(self.record['window']['following_padding_hex'], '')
        self.assertEqual(self.record['fde']['next_fde_start'], self.record['window']['end'])


if __name__ == '__main__':
    unittest.main()
