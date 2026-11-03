"""Static controls for the #115 reverse-and-append instruction certificate."""
import importlib.util
import json
import mmap
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_reverse_word256 as bind
from elf_index import sections

spec = importlib.util.spec_from_file_location('packet_verifier', bind.PACKET / 'verify.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class BindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = bind.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_READ)
        cls.record = bind.evidence(cls.data)
        cls.text = next(s for s in sections(cls.data) if s['name'] == '.text')
        off = cls.record['window']['file_offset']
        cls.body = cls.data[off:off + bind.END - bind.START]

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def test_regeneration_and_readme_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            shutil.copy(bind.PACKET / 'verify.py', out / 'verify.py')
            record = bind.generate(self.data, out)
            for name in ('README.md', 'records.json', 'MANIFEST.sha256', 'verify.py'):
                self.assertEqual((out / name).read_bytes(), (bind.PACKET / name).read_bytes(), name)
            self.assertTrue(verifier.verify(out))
            readme = (out / 'README.md').read_text()
            self.assertIn('**%d callees**' % len(record['callees']), readme)
            self.assertIn('**%d direct-call/jump candidates**' % len(record['direct_rel32_candidates']), readme)
            self.assertIn('**%d relative relocations**' % len(record['relative_relocations']), readme)
            self.assertIn('%d decoded instructions' % len(record['instructions']), readme)
            self.assertIn('(%d bytes)' % record['window']['size'], readme)
            self.assertIn('preceding %d and following %d bytes' % (
                len(bytes.fromhex(record['window']['padding_before'])),
                len(bytes.fromhex(record['window']['padding_after']))), readme)
            self.assertEqual(json.loads((out / 'records.json').read_text()), record)

    def test_success_vectors(self):
        source = bytes(range(32))
        for count in (0, 1, 1022, 1023):
            result = bind.model(count, source)
            self.assertEqual(result, {'count': count + 1, 'cursor_delta': 32,
                                      'slot': bytes.fromhex('1f1e1d1c1b1a19181716151413121110'
                                                            '0f0e0d0c0b0a09080706050403020100'), 'rax': 0})
        source = bytes.fromhex('1122334455667788' * 4)
        self.assertEqual(bind.model(4, source)['slot'], bytes.fromhex('8877665544332211' * 4))

    def test_failure_vectors_and_register_width(self):
        for count, expected in ((1024, 0x42d), (1025, 0x42d), (2**64 - 1, 0xffffffffffffff2d)):
            self.assertEqual(bind.model(count, bytes(32)),
                             {'count': count, 'cursor_delta': 0, 'slot': None, 'rax': expected})

    def test_invalid_model_inputs(self):
        for count, data in ((-1, bytes(32)), (2**64, bytes(32)), (0, bytes(31))):
            with self.assertRaises(ValueError):
                bind.model(count, data)

    def test_wrong_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            shutil.copy(bind.PACKET / 'verify.py', out / 'verify.py')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.generate(b'not node 115', out)
            self.assertEqual(sorted(p.name for p in out.iterdir()), ['verify.py'])

    def test_mutated_instruction_and_branch(self):
        for index in (0, 11, 13, len(self.body) - 2):
            damaged = bytearray(self.body)
            damaged[index] ^= 1
            with self.assertRaises(ValueError):
                bind.decode(damaged)
        with self.assertRaises(ValueError):
            bind.decode(self.body[:-1])

    def test_shifted_fde(self):
        row = dict(self.record['window']['fde'])
        for key in ('start', 'end', 'fde', 'cie'):
            altered = dict(row)
            altered[key] += 1
            with self.assertRaisesRegex(ValueError, 'FDE mismatch'):
                bind.validate_fde(altered)

    def test_scan_detects_calls_and_jumps_at_every_byte(self):
        # Include a hit inside a non-instruction prefix: the census is bytewise.
        start = bind.START - 32
        raw = bytearray(b'\x90' * 48)
        for offset, opcode in ((1, 0xe8), (20, 0xe9)):
            raw[offset] = opcode
            struct.pack_into('<i', raw, offset + 1, bind.START - (start + offset + 5))
        result = bind.direct_scan(raw, {'address': start, 'offset': 0, 'size': len(raw)})
        self.assertEqual(result, [{'va': start + 1, 'opcode': 'e8'},
                                  {'va': start + 20, 'opcode': 'e9'}])
        raw[22] ^= 1
        self.assertEqual(bind.direct_scan(raw, {'address': start, 'offset': 0, 'size': len(raw)}),
                         [{'va': start + 1, 'opcode': 'e8'}])

    def test_wrong_direct_target_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'unexpected scan target'):
            bind.direct_scan(self.data, self.text, bind.START + 1)

    def test_relocation_target_corruption(self):
        secs = sections(self.data)
        rela = next(s for s in secs if s['name'] == '.rela.dyn')
        damaged = bytearray(self.data[rela['offset']:rela['offset'] + rela['size']])
        row = self.record['relative_relocations'][0]
        struct.pack_into('<q', damaged, row['file_offset'] - rela['offset'] + 16, bind.START + 1)
        new_rela = dict(rela, offset=0)
        with self.assertRaisesRegex(ValueError, 'relocation targets mismatch'):
            bind.relocations(damaged, [new_rela, next(s for s in secs if s['name'] == '.data.rel.ro')])

    def test_manifest_corruption_and_whitelist(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for name in ('README.md', 'records.json', 'MANIFEST.sha256', 'verify.py'):
                shutil.copy(bind.PACKET / name, out / name)
            (out / 'records.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                verifier.verify(out)
            manifest = (out / 'MANIFEST.sha256').read_text().replace('README.md', '../README.md')
            (out / 'MANIFEST.sha256').write_text(manifest)
            with self.assertRaisesRegex(ValueError, 'whitelist'):
                verifier.verify(out)


if __name__ == '__main__':
    unittest.main()
