"""Static target binding and negative controls for the aligned quotient."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from tools import aligned_quotient_94 as b

PACKET = b.ROOT / 'research/work-items/RE-001-aligned-quotient-94'
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('aligned_packet_verify', PACKET / 'verify.py')
verify_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_module)


class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = open(b.BINARY, 'rb')
        cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        cls.record = b.inspect(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.stream.close()

    def test_real_packet_and_counts(self):
        verify_module.verify(PACKET)
        record = json.loads((PACKET/'records.json').read_text())
        self.assertEqual(record, self.record)
        self.assertEqual((PACKET/'README.md').read_text(), b.readme(record))
        self.assertEqual(record['instruction_count'], len(b.decode(self.data[b.START-0x1000:b.END-0x1000])))
        self.assertEqual(record['function']['size'], b.END-b.START)
        self.assertEqual(len(record['callees']), 0)
        self.assertEqual(len(record['direct_callers']), 0)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            b.inspect(self.data, digest='0'*64)

    def test_mutated_binary_fails_digest(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'mutant'
            shutil.copyfile(b.BINARY, path)
            with path.open('r+b') as f:
                f.seek(b.START-0x1000+3)
                f.write(b'\x00')
            with path.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                with self.assertRaisesRegex(ValueError, 'digest'):
                    b.inspect(data)

    def test_mutated_instruction_rejected(self):
        body = bytearray(self.data[b.START-0x1000:b.END-0x1000])
        body[18] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction'):
            b.decode(body)

    def test_shifted_fde_rejected(self):
        with self.assertRaises(ValueError):
            b.inspect(self.data, fde=b.FDE+4)

    def test_injected_call_with_wrong_target_rejected(self):
        # This leaf has no callee. An invented rel32 call cannot pass its decoder.
        body = bytearray(self.data[b.START-0x1000:b.END-0x1000])
        body[4:9] = b'\xe8\x00\x00\x00\x00'
        with self.assertRaisesRegex(ValueError, 'instruction'):
            b.decode(body)

    def test_branch_corruption_rejected(self):
        body = bytearray(self.data[b.START-0x1000:b.END-0x1000])
        body[11] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction'):
            b.decode(body)

    def test_manifest_whitelist_and_generated_counts(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            for f in PACKET.iterdir():
                shutil.copyfile(f, p/f.name)
            (p/'extra').write_text('x')
            with self.assertRaisesRegex(ValueError, 'whitelist'):
                verify_module.verify(p)
            (p/'extra').unlink()
            text = (p/'README.md').read_text().replace('52 bytes', '53 bytes')
            (p/'README.md').write_text(text)
            names = ('README.md', 'records.json', 'verify.py')
            (p/'MANIFEST.sha256').write_text(''.join(hashlib.sha256((p/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names))
            with self.assertRaisesRegex(ValueError, 'README'):
                verify_module.verify(p)

    def test_model_boundaries(self):
        # Static instruction-derived cases: threshold, round-down, cap, sign.
        vectors = [(0,1,0), (4,1,0), (5,1,0), (68,1,0),
                   (69,1,512000), (133,2,512000),
                   (0x100000004,8000,0xffffffc0),
                   ((1<<64)-1,8000,0xffffffc0),
                   (69,0xffffffff,0), (69,0x80000000,0),
                   (69,3,170666)]
        for n,d,want in vectors:
            with self.subTest(n=n,d=d):
                self.assertEqual(b.model(n,d), want)
        for n in (0,69):
            with self.assertRaises(ZeroDivisionError):
                b.model(n,0)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            shutil.copyfile(PACKET/'verify.py', p/'verify.py')
            b.generate(p)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                with self.subTest(name=name):
                    self.assertEqual((p/name).read_bytes(), (PACKET/name).read_bytes())

    def test_scan_finds_rel32_calls_and_jumps(self):
        # Synthetic .text exercises both opcodes, direction and interior matches.
        class Buffer(bytes):
            pass
        import struct
        raw = bytearray(b'\x90'*40)
        for at, op in ((2,0xe8),(12,0xe9)):
            raw[at] = op
            struct.pack_into('<i',raw,at+1, 0x101e-(0x1000+at+5))
        fake = Buffer(raw)
        section = [0,0,4,0x1000,0,len(raw)]
        self.assertEqual(b.scan(fake,section,0x101e),
                         [{'site':'0x1002','opcode':'0xe8'}, {'site':'0x100c','opcode':'0xe9'}])


if __name__ == '__main__':
    unittest.main()
