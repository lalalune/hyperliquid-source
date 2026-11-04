import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_four_slot_copy as subject
from elf_index import sections

PACKET = ROOT / 'research/work-items/RE-001-node115-four-slot-copy'


class FourSlotCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = subject.inspect(cls.data)
        cls.secs = sections(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def corrupt(self, offset, value, authenticated=False):
        old = self.data[offset]
        try:
            self.data[offset] = value
            with self.assertRaises(ValueError):
                subject.inspect(self.data, authenticate=authenticated)
        finally:
            self.data[offset] = old

    def test_regeneration(self):
        expected = json.dumps(self.record, indent=2) + '\n'
        self.assertEqual((PACKET / 'records.json').read_text(), expected)
        with tempfile.TemporaryDirectory() as tmp:
            import subprocess
            subprocess.run([sys.executable, str(ROOT / 'tools/node115_four_slot_copy.py'), '--out', tmp], check=True)
            self.assertEqual((Path(tmp) / 'records.json').read_text(), expected)

    def test_wrong_digest(self):
        self.corrupt(self.record['window']['file_offset'], 0x90, authenticated=True)

    def test_mutated_instruction(self):
        off = self.record['window']['file_offset']
        self.corrupt(off + 27, self.data[off + 27] ^ 1)

    def test_shifted_fde(self):
        sec = next(s for s in self.secs if s['name'] == '.eh_frame')
        pos = sec['offset'] + subject.FDE - sec['address'] + 8
        self.corrupt(pos, self.data[pos] ^ 1)

    def test_wrong_relocation_target(self):
        sec = next(s for s in self.secs if s['name'] == '.rela.dyn')
        for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
            if struct.unpack_from('<Q', self.data, p)[0] == subject.SLOT:
                self.corrupt(p + 16, self.data[p + 16] ^ 1)
                return
        self.fail('relocation missing')

    def test_caller_scanner_targets(self):
        sample = b'\x90\xe8\x05\x00\x00\x00\xe9\x00\x00\x00\x00'
        text = {'offset': 0, 'size': len(sample), 'address': 0x100}
        self.assertEqual(subject.direct_refs(sample, text, 0x10b), [
            {'address': 0x101, 'opcode': 'e8', 'target': 0x10b},
            {'address': 0x106, 'opcode': 'e9', 'target': 0x10b}])
        self.assertEqual(subject.direct_refs(sample, text, 0x10c), [])

    def test_boundaries_and_copy(self):
        slots = [bytes([i % 256]) * 32 for i in range(1024)]
        for index in (0, 3, 1024, 2**64 - 1):
            status, updated, result = subject.model(index, slots)
            self.assertEqual((status, updated, result), (45, index, slots))
        for index in (4, 5, 1023):
            status, updated, result = subject.model(index, slots)
            self.assertEqual((status, updated), (0, index + 1))
            self.assertEqual(result[index], slots[index - 4])
            self.assertEqual(result[:index], slots[:index])
            self.assertEqual(result[index + 1:], slots[index + 1:])
        self.assertEqual(slots[4], b'\x04' * 32)

    def test_readme_counts(self):
        readme = (PACKET / 'README.md').read_text()
        match = re.search(r'Packet counts: (\d+) bytes; (\d+) instructions; (\d+) callees; (\d+) direct rel32 candidates; (\d+) padding bytes\.', readme)
        self.assertIsNotNone(match)
        actual = tuple(map(int, match.groups()))
        self.assertEqual(actual, (self.record['window']['size'], len(self.record['instructions']),
                                 len(self.record['callees']), len(self.record['direct_rel32_candidates']),
                                 len(bytes.fromhex(self.record['window']['padding_hex']))))


if __name__ == '__main__':
    unittest.main()
