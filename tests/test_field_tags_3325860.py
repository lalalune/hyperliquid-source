import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools import field_tags_3325860 as bind

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-field-tags-3325860-94'
spec = importlib.util.spec_from_file_location('packet_verify', PACKET/'verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class TestFieldTags(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = open(ROOT/'artifacts/node/94/hl-node', 'rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.sec = bind.sections(cls.data)
        cls.record, cls.walk = bind.analyze(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def test_packet_reproduces(self):
        self.assertEqual(verify.verify(), self.record)
        self.assertEqual((PACKET/'instructions.txt').read_text(), '\n'.join(self.walk)+'\n')

    def test_generator_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for name in ('README.md', 'verify.py'):
                shutil.copyfile(PACKET/name, out/name)
            subprocess.run([sys.executable, str(ROOT/'tools/field_tags_3325860.py'),
                            '--binary', str(ROOT/'artifacts/node/94/hl-node'),
                            '--out', str(out)], check=True, capture_output=True)
            for name in (*verify.WHITELIST, 'MANIFEST.sha256'):
                self.assertEqual((out/name).read_bytes(), (PACKET/name).read_bytes())

    def test_rule_target_grounded(self):
        self.assertEqual(bind.model(b'app_hash'), b'\x09\x00')
        self.assertEqual(bind.model(b'hot_user_to_signature'), b'\x09\x01')
        for word in (b'app_hash', b'hot_user_to_signature'):
            for i in range(len(word)):
                changed = word[:i] + bytes([word[i] ^ 1]) + word[i+1:]
                self.assertEqual(bind.model(changed), b'\x09\x02')
            for altered in (word[:-1], word+b'x', b'', word.upper()):
                self.assertEqual(bind.model(altered), b'\x09\x02')

    def test_wrong_digest_fails(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            bind.analyze(self.data, expected_digest='0'*64)

    def test_window_byte_corruption_fails(self):
        body = bytearray(bind.view(self.data, self.sec['.text'], bind.START, bind.END-bind.START))
        body[0x30] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction'):
            bind.decode(body)
        off = self.sec['.text']['offset'] + bind.START - self.sec['.text']['va']
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'digest'):
                bind.analyze(self.data)
        finally:
            self.data[off] ^= 1

    def test_shifted_fde_fails(self):
        with self.assertRaises(ValueError):
            bind.read_fde(self.data, self.sec['.eh_frame'], bind.FDE+4)
        off = self.sec['.eh_frame']['offset'] + bind.FDE + 8
        try:
            self.data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'FDE'):
                bind.read_fde(self.data, self.sec['.eh_frame'])
        finally:
            self.data[off] ^= 1

    def test_wrong_reference_target_fails(self):
        # There are no callees; corrupt the RIP-relative data target instead.
        body = bytearray(bind.view(self.data, self.sec['.text'], bind.START, bind.END-bind.START))
        body[0x34] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction'):
            bind.decode(body)

    def test_wrong_caller_target_fails(self):
        raw = bytearray.fromhex('e848526700')
        raw[1] ^= 1
        self.assertNotEqual(bind.decode_call(0x2cb0613, raw), bind.START)
        with self.assertRaisesRegex(ValueError, 'caller'):
            bind.analyze(self.data, target=bind.START+1)

    def test_manifest_whitelist_and_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp)
            for name in (*verify.WHITELIST, 'MANIFEST.sha256'):
                shutil.copyfile(PACKET/name, packet/name)
            with (packet/'MANIFEST.sha256').open('a') as f: f.write('0'*64+'  ../escape\n')
            with self.assertRaisesRegex(ValueError, 'manifest'):
                verify.verify(packet)
            shutil.copyfile(PACKET/'MANIFEST.sha256', packet/'MANIFEST.sha256')
            rec = json.loads((packet/'records.json').read_text())
            rec['rule']['fallback'] = 1
            (packet/'records.json').write_text(json.dumps(rec, indent=2)+'\n')
            # An attacker recomputing the manifest still cannot alter semantics.
            (packet/'MANIFEST.sha256').write_text(''.join(hashlib.sha256((packet/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in verify.WHITELIST))
            with self.assertRaisesRegex(ValueError, 'records mismatch'):
                verify.verify(packet)

    def test_readme_counts_match_records(self):
        readme = (PACKET/'README.md').read_text()
        f = self.record['function']; c = self.record['caller_census']
        self.assertIn('size **%d** bytes' % f['size'], readme)
        self.assertIn('**%d callees**' % len(self.record['callees']), readme)
        self.assertIn('**%d e8 caller candidate**' % len(c['e8']), readme)
        self.assertIn('**%d e9 jump candidates**' % len(c['e9']), readme)
        self.assertIn('**%d branches**' % len(self.record['branches']), readme)
        self.assertIn('**%d constant blocks**' % len(self.record['constants']), readme)
        self.assertIn('**%d** `cc` padding bytes' % f['padding_bytes'], readme)
        self.assertIn('FDE `.eh_frame+%s`, length %#x, CIE `.eh_frame+%s`' % (f['fde']['section_offset'], f['fde']['length'], f['fde']['cie_section_offset']), readme)
        self.assertEqual(f['padding_bytes'], 14)
        self.assertEqual(f['next_fde']['start'], hex(bind.END+f['padding_bytes']))
        self.assertEqual(len(bytes.fromhex(self.record['constants'][0]['bytes_hex'])), 16)
        self.assertEqual(len(next(iter(self.record['rule']['tags']))), 8)
        self.assertEqual(len(list(self.record['rule']['tags'])[1]), 21)

if __name__ == '__main__': unittest.main()
