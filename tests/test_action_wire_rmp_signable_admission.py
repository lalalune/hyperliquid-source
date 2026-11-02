"""Packet-directory admission for action-wire-rmp-signable-94 verify.py.

The verifier strictly checks MANIFEST.sha256 entries (unknown name,
duplicate, digest length, incomplete set) and hashes every listed file,
but it never enumerated the packet directory: an extra unlisted file, a
subdirectory, and a listed file replaced by a symlink to identical bytes
outside the packet all verified green. The node-inventory packet
verifiers reject all three and compare the present file set against the
pinned set. The doctored cases below fail at that admission scan, before
the binary is read, so they run without the capture; the genuine case
needs the materialized node94 capture.
"""
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
PACKET = ROOT / 'research/work-items/action-wire-rmp-signable-94'
TARGET = ROOT / 'artifacts/node/94/hl-node'


def load_verify(packet_dir):
    spec = importlib.util.spec_from_file_location(
        f'verify_{packet_dir.name}', packet_dir / 'verify.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PacketAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=PACKET.parent)
        self.dir = Path(self.tmp.name) / 'packet'
        shutil.copytree(PACKET, self.dir, symlinks=True)
        self.verify = load_verify(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_extra_unlisted_file_rejected(self):
        (self.dir / 'smuggled.txt').write_text('x')
        with self.assertRaisesRegex(ValueError, 'packet contents differ'):
            self.verify.verify(self.dir, PACKET / 'README.md')

    def test_subdirectory_rejected(self):
        (self.dir / 'smuggled').mkdir()
        with self.assertRaisesRegex(ValueError, 'unexpected directory'):
            self.verify.verify(self.dir, PACKET / 'README.md')

    def test_symlinked_listed_file_rejected(self):
        outside = Path(self.tmp.name) / 'outside.md'
        outside.write_bytes((self.dir / 'RESULT.md').read_bytes())
        (self.dir / 'RESULT.md').unlink()
        (self.dir / 'RESULT.md').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.verify.verify(self.dir, PACKET / 'README.md')

    @unittest.skipUnless(TARGET.stat().st_size == 91774280,
                         'materialize the pinned node94 capture')
    def test_genuine_packet_accepted(self):
        self.verify.verify(self.dir, TARGET)


if __name__ == '__main__':
    unittest.main()
