"""Keep export filename normalization narrower than evidence content."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from evidence_exports import comparable_export


class ExportComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, data):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def test_only_header_filename_may_differ(self):
        a = self.write('a.objdump.txt', b'\n/a/node:     file format elf64-x86-64\n10: 90 nop\n')
        b = self.write('b.objdump.txt', b'\n/b/node:     file format elf64-x86-64\n10: 90 nop\n')
        self.assertEqual(comparable_export(a), comparable_export(b))
        for mutation in [b.read_bytes().replace(b'90', b'91'),
                         b.read_bytes().replace(b'elf64', b'elf32')]:
            b.write_bytes(mutation)
            self.assertNotEqual(comparable_export(a), comparable_export(b))

    def test_manifest_is_authenticated_before_normalization(self):
        manifests = []
        for name in ['a', 'b']:
            p = self.write(name + '/body.objdump.txt',
                           ('/' + name + ': file format elf64-x86-64\n10: 90 nop\n').encode())
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            manifests.append(self.write(name + '/MANIFEST.sha256',
                                        (digest + '  body.objdump.txt\n').encode()))
        self.assertEqual(comparable_export(manifests[0]), comparable_export(manifests[1]))
        (manifests[1].parent / 'body.objdump.txt').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            comparable_export(manifests[1])

    def test_non_disassembly_exports_remain_byte_exact(self):
        a = self.write('a.txt', b'/a: file format elf64-x86-64\n')
        self.assertEqual(comparable_export(a), a.read_bytes())


if __name__ == '__main__':
    unittest.main()
