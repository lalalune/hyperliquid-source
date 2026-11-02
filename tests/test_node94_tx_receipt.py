"""Target-grounded instruction, packet and corruption controls for RE-001."""
import hashlib
import json
import mmap
import struct
from pathlib import Path
import unittest

from tools import node94_tx_receipt as tool

PACKET = tool.ROOT / 'research/work-items/RE-001-tx-receipt-classifier-94'


class BindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = tool.BINARY.open('rb')
        cls.binary = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.records, cls.walk = tool.collect(cls.binary)

    @classmethod
    def tearDownClass(cls):
        cls.binary.close()
        cls.file.close()

    def corrupted(self, offset, byte, message):
        old = self.binary[offset]
        try:
            self.binary[offset] = byte
            changed_digest = hashlib.sha256(self.binary).hexdigest()
            with self.assertRaisesRegex(ValueError, message):
                tool.collect(self.binary, expected_sha=changed_digest)
        finally:
            self.binary[offset] = old

    def test_rule_vectors(self):
        for text, output in [(b'tx', b'\x09\x00'), (b'receipt', b'\x09\x01'),
                             (b'', b'\x09\x02'), (b'Tx', b'\x09\x02'),
                             (b'txx', b'\x09\x02'), (b'receip', b'\x09\x02'),
                             (b'receipts', b'\x09\x02'), (b'\x00'*7, b'\x09\x02')]:
            self.assertEqual(tool.model(text), output)

    def test_every_receipt_byte_must_match(self):
        original = b'receipt'
        for i in range(len(original)):
            changed = bytearray(original)
            changed[i] ^= 1
            self.assertEqual(tool.model(bytes(changed)), b'\x09\x02')

    def test_instruction_walk_is_complete_and_branch_destinations_internal(self):
        self.assertEqual(sum(len(bytes.fromhex(raw)) for _, raw, _ in self.walk), 68)
        self.assertEqual(len(self.records['branches']), 4)
        self.assertEqual(self.records['callees'], [])

    def test_wrong_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest'):
            tool.collect(self.binary, expected_sha='0'*64)

    def test_mutated_body(self):
        offset = int(self.records['window']['file_offset'], 16)
        self.corrupted(offset + 5, self.binary[offset + 5] ^ 1, 'body hash')

    def test_strict_decoder_rejects_changed_branch(self):
        offset = int(self.records['window']['file_offset'], 16)
        body = bytearray(self.binary[offset:offset + 68])
        body[8] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction'):
            tool.decode(body)

    def test_shifted_fde(self):
        sections = tool.sections(self.binary)
        with self.assertRaises(ValueError):
            tool.frame(self.binary, sections['.eh_frame'], 0x3d080, tool.START, tool.END, 0)

    def test_mutated_fde(self):
        offset = 0xce1518 + 0x3d07c + 8
        self.corrupted(offset, self.binary[offset] ^ 1, 'FDE association')

    def test_mutated_neighbor_fde(self):
        offset = 0xce1518 + 0x36d1f0 + 8
        self.corrupted(offset, self.binary[offset] ^ 1, 'FDE association')

    def test_mutated_frame_header_reference(self):
        header = tool.sections(self.binary)['.eh_frame_hdr']
        target_pc = tool.START - header[3]
        target_fde = 0xce1518 + 0x3d07c - header[3]
        entry = struct.pack('<ii', target_pc, target_fde)
        offset = self.binary.find(entry, header[4], header[4] + header[5])
        self.assertGreaterEqual(offset, 0)
        self.corrupted(offset + 4, self.binary[offset + 4] ^ 1, 'frame header associations')

    def test_mutated_padding(self):
        offset = int(self.records['window']['file_offset'], 16) + 68
        self.corrupted(offset, 0x90, 'padding')

    def test_wrong_caller_target(self):
        offset = tool.CALLER - 0x1000 + 1
        self.corrupted(offset, self.binary[offset] ^ 1, 'direct caller scan')

    def test_packet_contents_and_readme_counts(self):
        records = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(records, self.records)
        actual = (PACKET / 'README.md').read_text()
        self.assertEqual(actual, tool.readme(records, self.walk))
        self.assertIn(f"is {records['window']['size']}\nbytes", actual)
        self.assertIn(f"{len(records['callees'])} callees", actual)
        self.assertIn(f"{len(records['direct_incoming']['calls'])} call", actual)
        self.assertIn(f"{len(records['direct_incoming']['jumps'])} jump", actual)
        self.assertIn(f"{len(records['vectors'])} static model vectors", actual)
        self.assertIn(f"{len(records['rule']['receipt_compare_chunks'])} overlapping dword reads", actual)
        self.assertIn(f"the {len(bytes.fromhex(records['rule']['equal_cases'][1]['bytes_hex']))}-byte path", actual)
        self.assertIn(f"{len(bytes.fromhex(records['window']['padding_hex']))} bytes are", actual)

    def test_generated_files_match(self):
        expected = tool.render(self.records, self.walk, (PACKET / 'verify.py').read_bytes())
        self.assertEqual({p.name for p in PACKET.iterdir()}, set(expected))
        for name, data in expected.items():
            self.assertEqual((PACKET / name).read_bytes(), data, name)


if __name__ == '__main__':
    unittest.main()
