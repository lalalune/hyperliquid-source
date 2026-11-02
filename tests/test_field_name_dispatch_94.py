"""Static target-backed controls for the RE-001 field-name leaf."""
import hashlib
import importlib.util
import mmap
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from tools import field_name_dispatch_94 as bind

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-field-name-dispatch-94'
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('field_packet_verify', PACKET / 'verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class FieldNameDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = bind.BINARY.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_READ)
        cls.rec, cls.lines = bind.analyze(cls.data)
        cls.sections = bind.sections(cls.data)
        t = cls.sections['.text']
        off = t['offset'] + bind.START - t['va']
        cls.body = cls.data[off:off + bind.END - bind.START]

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def test_verified_packet_and_readme_counts(self):
        self.assertEqual(verify.verify(), self.rec)

    def test_vectors_and_exact_length(self):
        cases = [(b'order_sz', b'\x09\x00'), (b'points', b'\x09\x01'),
                 (b'', b'\x09\x02'), (b'order_sZ', b'\x09\x02'),
                 (b'point', b'\x09\x02'), (b'points\0', b'\x09\x02'),
                 (b'\0' * 8, b'\x09\x02')]
        self.assertEqual(self.rec['vectors'], [{'input_hex': x.hex(), 'result_hex': y.hex()} for x, y in cases])
        for name, expected in cases:
            self.assertEqual(bytes([9, bind.classify(name)]), expected)
        for original in (b'order_sz', b'points'):
            for i in range(len(original)):
                altered = original[:i] + bytes([original[i] ^ 1]) + original[i+1:]
                self.assertEqual(bind.classify(altered), 2)
            self.assertEqual(bind.classify(original + b'x'), 2)
            self.assertEqual(bind.classify(original[:-1]), 2)

    def test_wrong_digest_fails(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            bind.analyze(self.data, '0' * 64)

    def test_mutated_window_byte_fails_decoder(self):
        body = bytearray(self.body)
        body[17] ^= 1
        with self.assertRaises(ValueError): bind.decode(body)
        self.assertNotEqual(hashlib.sha256(body).hexdigest(), bind.BODY_SHA)

    def test_shifted_fde_and_corrupt_extent_fail(self):
        frame = self.sections['.eh_frame']
        with self.assertRaisesRegex(ValueError, 'offset'):
            bind.frame_check(self.data, frame, bind.FDE_OFFSET + 4)
        # Only the small relevant frame prefix and FDE records are copied.
        fake = bytearray(bind.FDE_OFFSET + 40)
        fake[:24] = self.data[frame['offset']:frame['offset'] + 24]
        p = frame['offset'] + bind.FDE_OFFSET
        fake[bind.FDE_OFFSET:] = self.data[p:p + 40]
        synthetic_frame = {'offset': 0, 'va': frame['va']}
        bind.frame_check(fake, synthetic_frame)
        struct.pack_into('<I', fake, bind.FDE_OFFSET + 12, 79)
        with self.assertRaisesRegex(ValueError, 'FDE'):
            bind.frame_check(fake, synthetic_frame)

    def test_wrong_branch_and_call_targets_fail(self):
        body = bytearray(self.body)
        body[8] ^= 1
        with self.assertRaisesRegex(ValueError, 'target'): bind.decode(body)
        with self.assertRaisesRegex(ValueError, 'target'):
            bind.decode_rel(bytes.fromhex('e843c41d00'), bind.CALLER, 0xe8, bind.START + 1)

    def test_manifest_whitelist_and_count_corruption_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            copy = Path(temp)
            for f in PACKET.iterdir(): shutil.copy(f, copy / f.name)
            (copy / 'extra').write_text('x')
            with self.assertRaisesRegex(ValueError, 'whitelist'): verify.verify(copy)
            (copy / 'extra').unlink()
            readme = copy / 'README.md'
            readme.write_text(readme.read_text().replace('| direct_callees | 0 |', '| direct_callees | 1 |'))
            (copy / 'MANIFEST.sha256').write_bytes(bind.manifest_bytes(copy))
            with self.assertRaisesRegex(ValueError, 'counts'): verify.verify(copy)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            for name in ('README.md', 'verify.py'): shutil.copy(PACKET / name, out / name)
            subprocess.run([sys.executable, str(ROOT / 'tools/field_name_dispatch_94.py'), '--out', str(out)], check=True, capture_output=True)
            for name in verify.WHITELIST:
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes(), name)


if __name__ == '__main__': unittest.main()
