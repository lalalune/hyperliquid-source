import contextlib


import hashlib


import io


from pathlib import Path


import sys


import tempfile


import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


import verify_packets


def sha(data):
    return hashlib.sha256(data).hexdigest()


class VerifyPacketsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.root = base / 'repo'
        self.root.mkdir()
        (self.root / 'research/work-items').mkdir(parents=True)

    def packet(self, relative='pkt-94'):
        directory = self.root / 'research/work-items' / relative
        directory.mkdir(parents=True)
        return directory

    def manifest(self, directory, rows, name='MANIFEST.sha256'):
        (directory / name).write_text(rows)
        return directory / name

    def entry(self, directory, name, body=b'bytes', relative=None):
        (directory / name).write_bytes(body)
        return f'{sha(body)}  {relative or name}\n'

    def run_all(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return verify_packets.verify(self.root)

    def test_valid_packet_passes(self):
        room = self.packet()
        rows = self.entry(room, 'README.md', b'a') + self.entry(room, 'records.json', b'b')
        self.manifest(room, rows)
        self.run_all()

    def test_tampered_bytes_rejected(self):
        room = self.packet()
        rows = self.entry(room, 'README.md', b'a')
        self.manifest(room, rows)
        (room / 'README.md').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.run_all()

    def test_unresolvable_row_grandfathered(self):
        room = self.packet()
        self.manifest(room, self.entry(room, 'kept.txt', b'ok')
                      + f'{sha(b"never committed")}  gone.txt\n')
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            verify_packets.verify(self.root)
        self.assertIn('1 grandfathered', buffer.getvalue())

    def test_malformed_line_rejected(self):
        room = self.packet()
        self.manifest(room, self.entry(room, 'a.txt') + 'notadigest  a.txt\n')
        with self.assertRaisesRegex(ValueError, 'Malformed manifest entry'):
            self.run_all()

    def test_uppercase_digest_rejected(self):
        room = self.packet()
        body = next(bytes([n]) for n in range(256)
                    if any(c in hashlib.sha256(bytes([n])).hexdigest() for c in 'abcdef'))
        self.manifest(room, self.entry(room, 'a.txt', body).upper().replace('  A.TXT', '  a.txt'))
        with self.assertRaisesRegex(ValueError, 'Malformed manifest entry'):
            self.run_all()

    def test_duplicate_entry_rejected(self):
        room = self.packet()
        row = self.entry(room, 'a.txt')
        self.manifest(room, row + row)
        with self.assertRaisesRegex(ValueError, 'Duplicate manifest entry'):
            self.run_all()

    def test_empty_manifest_rejected(self):
        room = self.packet()
        self.manifest(room, '# only a comment\n')
        with self.assertRaisesRegex(ValueError, 'Empty packet manifest'):
            self.run_all()

    def test_path_outside_repository_rejected(self):
        (self.root.parent / 'leak.txt').write_bytes(b'leak')
        room = self.packet()
        self.manifest(room, f'{sha(b"leak")}  ../../../leak.txt\n')
        with self.assertRaisesRegex(ValueError, 'outside the repository'):
            self.run_all()

    def test_repository_relative_entry_resolves(self):
        room = self.packet()
        tools = self.root / 'tools'
        tools.mkdir()
        (tools / 'probe.py').write_bytes(b'probe')
        self.manifest(room, f'{sha(b"probe")}  tools/probe.py\n')
        self.run_all()

    def test_generator_and_review_spellings_are_both_checked(self):
        # MANIFEST.sha256 and manifest.sha256 denote one file on a
        # case-insensitive host, so exercise the two spellings in siblings.
        # Tamper only the lowercase-spelled packet's bytes.
        upper = self.packet('pkt-upper')
        self.manifest(upper, self.entry(upper, 'README.md', b'good'), name='MANIFEST.sha256')
        lower = self.packet('pkt-lower')
        (lower / 'README.md').write_bytes(b'tampered')
        self.manifest(lower, f'{sha(b"good")}  README.md\n', name='manifest.sha256')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.run_all()

    def test_missing_packet_tree_rejected(self):
        (self.root / 'research/work-items').rmdir()
        with self.assertRaisesRegex(ValueError, 'Missing packet tree'):
            self.run_all()


class RepositoryPacketCoverageTests(unittest.TestCase):
    def test_every_committed_manifest_passes(self):
        verify_packets.verify(Path(__file__).resolve().parents[1])


if __name__ == '__main__':
    unittest.main()
