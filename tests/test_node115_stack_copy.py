import hashlib
import json
import mmap
from pathlib import Path
import struct
import tempfile
import unittest

from tools import node115_stack_copy as subject

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-stack-copy'


class StackCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = BINARY.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.records = subject.analyze(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def test_packet_is_exact_regeneration_and_readme_counts(self):
        self.assertEqual(json.loads((PACKET / 'records.json').read_text()), self.records)
        readme = (PACKET / 'README.md').read_text()
        self.assertEqual(readme, subject.readme(self.records))
        counts = self.records['counts']
        for phrase in (f"({counts['instructions']} instructions)", f"callee count {counts['callees']}",
                       f"found {counts['direct_rel32_transfers']} candidate direct transfers",
                       f"found {counts['relative_relocations']} `R_X86_64_RELATIVE` records"):
            self.assertIn(phrase, readme)
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / 'verify.py').write_bytes((PACKET / 'verify.py').read_bytes())
            subject.generate(BINARY, out)
            for name in ('records.json', 'README.md', 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes())

    def test_success_boundaries_and_contents(self):
        values = [i.to_bytes(32, 'little') for i in range(1024)]
        for n in (2, 3, 512, 1023):
            with self.subTest(n=n):
                status, length, result = subject.model(n, values)
                self.assertEqual((status, length), (0, n + 1))
                self.assertEqual(result[n], values[n-2])
                self.assertEqual(result[:n], values[:n])
                self.assertEqual(result[n+1:], values[n+1:])

    def test_rejection_and_wrapping_boundaries(self):
        for n in (0, 1, 1024, 1025, (1 << 63), (1 << 64)-1):
            with self.subTest(n=n):
                self.assertEqual(subject.model(n, [b'x'*32]), (45, n, [b'x'*32]))
        for n in range(1026):
            accept = ((n - 2) & ((1 << 64)-1)) <= 0x3fd
            self.assertEqual(accept, 2 <= n <= 1023)

    def test_invalid_model_memory(self):
        with self.assertRaises(ValueError):
            subject.model(2, [b'a'*32])
        with self.assertRaises(ValueError):
            subject.model(2, [b'a'*32, b'b'])
        with self.assertRaises(ValueError):
            subject.model(1 << 64, [])

    def test_wrong_digest_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'wrong'
            path.write_bytes(b'not the target')
            out = Path(temp) / 'output'
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                subject.generate(path, out)
            self.assertFalse(out.exists())

    def test_corrupt_window_rejected_even_if_authentication_bypassed(self):
        pos = 0x2994ab0 + 10
        old = self.data[pos]
        try:
            self.data[pos] ^= 1
            with self.assertRaisesRegex(ValueError, 'target SHA-256 mismatch'):
                subject.analyze(self.data)
            with self.assertRaisesRegex(ValueError, 'body SHA-256 mismatch'):
                subject.analyze(self.data, authenticate=False)
        finally:
            self.data[pos] = old

    def test_shifted_fde_rejected(self):
        pos = subject.FDE + 8
        old = self.data[pos]
        try:
            self.data[pos] ^= 1
            with self.assertRaisesRegex(ValueError, 'unexpected FDE'):
                subject.unwind(self.data)
        finally:
            self.data[pos] = old

    def test_wrong_branch_target_rejected(self):
        body = bytearray(self.data[0x2994ab0:0x2994aea])
        body[16] ^= 1
        with self.assertRaisesRegex(ValueError, 'unexpected instruction'):
            subject.decode(body)

    def test_wrong_relocation_target_rejected(self):
        pos = 0x61c78
        old = self.data[pos]
        try:
            self.data[pos] ^= 1
            with self.assertRaisesRegex(ValueError, 'unexpected relocation references'):
                subject.relocations(self.data, subject.sections(self.data)['.rela.dyn'])
        finally:
            self.data[pos] = old

    def test_synthetic_direct_transfer_census(self):
        data = bytearray(b'\x90' * 32)
        va = subject.START - 100
        for index, opcode in ((0, 0xe8), (10, 0xe9)):
            data[index] = opcode
            struct.pack_into('<i', data, index+1, subject.START - (va + index + 5))
        self.assertEqual(subject.direct_transfers(data, (1, 6, va, 0, len(data))),
                         [{'site': hex(va), 'kind': 'call'}, {'site': hex(va+10), 'kind': 'jmp'}])
        data[11] ^= 1
        self.assertEqual(len(subject.direct_transfers(data, (1, 6, va, 0, len(data)))), 1)

    def test_padding_corruption(self):
        pos = 0x2994aea
        old = self.data[pos]
        try:
            self.data[pos] = 0x90
            with self.assertRaisesRegex(ValueError, 'unexpected padding'):
                subject.analyze(self.data, authenticate=False)
        finally:
            self.data[pos] = old


if __name__ == '__main__':
    unittest.main()
