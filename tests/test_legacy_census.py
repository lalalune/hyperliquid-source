import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GROUNDING = ROOT / 'tools/legacy/grounding.py'
DRIFT = ROOT / 'tools/legacy/drift.py'

NORMAL_RS = 'pub const A: &str = "normal crate literal";\n'
HIDDEN_RS = 'pub const U: &str = "zzq unique literal";\n'
# Both literals occur verbatim in the stand-in binaries, so every scanned
# literal is a hit (grounding) / grounded (drift) and counts are exact.
BINARY = b'\x00normal crate literal\x00zzq unique literal\x00'


def build_tree(base, hidden_dir):
    crate = base / 'crate1'
    (crate / hidden_dir).mkdir(parents=True)
    (crate / 'normal.rs').write_text(NORMAL_RS)
    (crate / hidden_dir / 'gen.rs').write_text(HIDDEN_RS)
    return base


class LegacyCensusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.binary = self.work / 'bin'
        self.binary.write_bytes(BINARY)

    def run_grounding(self, src):
        r = subprocess.run(
            [sys.executable, '-I', str(GROUNDING), str(src), str(self.binary)],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def run_drift(self, src):
        out_json = self.work / 'out.json'
        r = subprocess.run(
            [sys.executable, '-I', str(DRIFT), str(src), str(self.binary),
             str(self.binary), str(out_json)],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout, json.loads(out_json.read_text())

    def test_grounding_counts_github_dir(self):
        src = build_tree(self.work / 'src_github', '.github')
        self.assertIn('overall: 2/2', self.run_grounding(src))

    def test_grounding_skips_real_git_dir(self):
        src = build_tree(self.work / 'src_git', '.git')
        self.assertIn('overall: 1/1', self.run_grounding(src))

    def test_grounding_counts_tree_below_dot_github_parent(self):
        # Every walked root sits below a '.github' component, so the old
        # substring guard dropped the whole tree (0/0), not just one file.
        src = build_tree(self.work / '.github' / 'src', 'sub')
        self.assertIn('overall: 2/2', self.run_grounding(src))

    def test_drift_counts_github_dir(self):
        src = build_tree(self.work / 'src_github', '.github')
        stdout, report = self.run_drift(src)
        self.assertIn('2 distinct literals', stdout)
        self.assertEqual(report['counts'].get('grounded'), 2)

    def test_drift_skips_real_git_dir(self):
        src = build_tree(self.work / 'src_git', '.git')
        stdout, report = self.run_drift(src)
        self.assertIn('1 distinct literals', stdout)
        self.assertEqual(report['counts'].get('grounded'), 1)


if __name__ == '__main__':
    unittest.main()
