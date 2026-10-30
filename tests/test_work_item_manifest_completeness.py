"""Work-item packet verifiers must check manifest completeness.

The RE-005/008/009/010/012 verify.py manifest stages used to hash only the
rows listed in MANIFEST.sha256, so deleting a packet file together with its
manifest row — or adding an unlisted file — passed the stage even though
the packet READMEs describe the manifest as pinning the packet's files.
These tests exercise the manifest stage of two representative verifiers
(RE-008, check()-style; RE-010, fail()-style) in fixture packets: a
complete packet gets past the manifest stage, while both tamperings are
rejected by the new file-set comparison.
"""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
PACKETS = REPO / 'research/work-items'

EXCHANGE_DISPATCH_STUB = """\
from pathlib import Path


class EvidenceError(Exception):
    pass


TARGET = Path(__file__).resolve().parents[1] / 'artifacts/node/94/hl-node'


def build(data):
    raise EvidenceError('fixture stop')


def render(result):
    raise AssertionError('unreachable')
"""


class ManifestCompletenessTests(unittest.TestCase):
    def fixture(self, packet):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        here = root / 'research/work-items' / packet
        here.parent.mkdir(parents=True)
        shutil.copytree(PACKETS / packet, here)
        binary = root / 'artifacts/node/94/hl-node'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'fixture binary, not the pinned artifact')
        tools = root / 'tools'
        tools.mkdir()
        (tools / 'exchange_dispatch.py').write_text(EXCHANGE_DISPATCH_STUB)
        return here

    def run_verify(self, here):
        return subprocess.run(
            [sys.executable, '-B', str(here / 'verify.py')],
            capture_output=True, text=True)

    def drop_row_and_file(self, here, name):
        (here / name).unlink()
        lines = (here / 'MANIFEST.sha256').read_text().splitlines()
        kept = [line for line in lines if line.split('  ', 1)[1] != name]
        (here / 'MANIFEST.sha256').write_text('\n'.join(kept) + '\n')

    def check_packet(self, packet, past_manifest_marker):
        here = self.fixture(packet)
        result = self.run_verify(here)
        self.assertIn(past_manifest_marker, result.stdout + result.stderr)
        self.assertNotIn('manifest file set differs',
                         result.stdout + result.stderr)

        here = self.fixture(packet)
        self.drop_row_and_file(here, 'objdump-excerpts.txt')
        result = self.run_verify(here)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('manifest file set differs',
                      result.stdout + result.stderr)

        here = self.fixture(packet)
        (here / 'injected-evidence.txt').write_text('fabricated\n')
        result = self.run_verify(here)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('manifest file set differs',
                      result.stdout + result.stderr)

    def test_re008_manifest_completeness(self):
        # Past the manifest stage, RE-008 stops at the pinned-binary check
        # because the fixture binary is not the retained artifact.
        self.check_packet('RE-008-consensus-wire-state', 'FAIL: binary sha256')

    def test_re010_manifest_completeness(self):
        # Past the manifest stage, RE-010 stops at the stubbed tool gate.
        self.check_packet('RE-010-exchange-handlers', 'fixture stop')


if __name__ == '__main__':
    unittest.main()
