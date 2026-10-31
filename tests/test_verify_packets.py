import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from verify_packets import verify


class PacketManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.packet = self.root / 'research/work-items/packet'
        self.packet.mkdir(parents=True)
        self.file = self.packet / 'file.txt'
        self.file.write_bytes(b'x')
        self.manifest = self.packet / 'MANIFEST.sha256'

    def line(self, path='file.txt', data=b'x'):
        return f'{hashlib.sha256(data).hexdigest()}  {path}\n'

    def write(self, text):
        self.manifest.write_text(text, encoding='utf-8')

    def test_valid_manifest_passes(self):
        self.write(self.line())
        verify(self.root)

    def test_tampered_file_fails(self):
        self.write(self.line())
        self.file.write_bytes(b'evil')
        with self.assertRaises(ValueError) as caught:
            verify(self.root)
        self.assertIn('mismatch', str(caught.exception))

    def test_missing_file_fails(self):
        self.write(self.line('missing.txt'))
        with self.assertRaises(ValueError) as caught:
            verify(self.root)
        self.assertIn('missing', str(caught.exception))

    def test_unlisted_file_fails(self):
        self.write(self.line())
        (self.packet / 'extra.txt').write_bytes(b'x')
        with self.assertRaises(ValueError) as caught:
            verify(self.root)
        self.assertIn('unlisted', str(caught.exception))

    def test_duplicate_entry_fails(self):
        self.write(self.line() + self.line())
        with self.assertRaises(ValueError) as caught:
            verify(self.root)
        self.assertIn('duplicate', str(caught.exception))

    def test_invalid_digest_fails(self):
        self.write('not-a-digest  file.txt\n')
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_path_outside_repository_fails(self):
        outside = self.root.parent / 'outside-packet-file.txt'
        self.addCleanup(outside.unlink, missing_ok=True)
        outside.write_bytes(b'x')
        self.write(self.line('../../../../outside-packet-file.txt'))
        with self.assertRaises(ValueError) as caught:
            verify(self.root)
        self.assertIn('outside repository', str(caught.exception))

    def test_repository_relative_entry_passes(self):
        tool = self.root / 'tools/tool.py'
        tool.parent.mkdir()
        tool.write_bytes(b'x')
        self.write(self.line() + self.line('tools/tool.py'))
        verify(self.root)

    def test_evidence_directory_manifest_uses_packet_root(self):
        evidence = self.packet / 'evidence'
        evidence.mkdir()
        manifest = evidence / 'MANIFEST.sha256'
        manifest.write_text(self.line(), encoding='utf-8')
        verify(self.root)

    def test_generated_bytecode_is_ignored(self):
        self.write(self.line())
        cache = self.packet / '__pycache__'
        cache.mkdir()
        (cache / 'tool.cpython-315.pyc').write_bytes(b'x')
        verify(self.root)


if __name__ == '__main__':
    unittest.main()
