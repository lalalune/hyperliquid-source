"""RE-010 gossipPriorityBid path: packet replay, manifest binding and Rust vectors."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-010-gossip-priority-bid-path-94'
COMPONENT = ROOT / 'src/node94-gossip-bid-admission/lib.rs'


class GossipBidPath(unittest.TestCase):
    def test_packet_replays_against_target(self):
        run = subprocess.run([sys.executable, '-I', '-B', str(PACKET / 'verify.py')],
                             capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('"text_mutants_killed": 36', run.stdout)

    def test_manifest_binds_every_packet_file(self):
        rows = dict(reversed(line.split('  ', 1)) for line in
                    (PACKET / 'MANIFEST.sha256').read_text().splitlines())
        names = {path.name for path in PACKET.iterdir() if path.name != 'MANIFEST.sha256'}
        self.assertEqual(set(rows), names)
        for name, digest in rows.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)

    @unittest.skipUnless(shutil.which('rustc'), 'rustc not installed')
    def test_rust_component_matches_vectors(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'gossip-bid-admission'
            subprocess.run(['rustc', '--edition', '2021', '--test', str(COMPONENT), '-o', str(binary)],
                           check=True, capture_output=True, cwd=ROOT)
            run = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertIn('3 passed', run.stdout)


if __name__ == '__main__':
    unittest.main()
