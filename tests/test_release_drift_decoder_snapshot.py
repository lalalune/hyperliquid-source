"""release_drift load_release() must disassemble a private snapshot.

The tool admitted the release binary once (artifacts.check plus the
bytes read into memory: section table, FDE extents and the per-extent
raw hashes all come from those admitted bytes) but then streamed
objdump over the target *path*, and fingerprint() takes each extent's
norm hash, instruction count, masks and callees from that objdump
text with no byte cross-check. A same-size replacement between
admission and disassembly changed one extent row in a live
reproduction while load_release() still returned the pinned digest
and the admitted data -- the drift classification mixes two binaries.
Sibling tools (compact_string_unwind on main, cguard_consistency_static)
already decode a private snapshot of the admitted bytes.

Admission-side helpers (check, sections, fde_extents,
require_pie_without_textrel, gnu_objdump) and fingerprint() are
stubbed here against a synthetic ROOT; what this test verifies is
exactly the defect's surface -- which file the objdump process opens.
The fake Popen swaps the binary file's bytes (same size) before
recording the path it was given plus the bytes at that path.
"""

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import artifacts
import elf_index
import fde_extents
import release_drift as tool

ADMITTED = b'A' * 64
SWAPPED = b'B' * 64
SHA = 'c' * 64


class DecoderSnapshotTests(unittest.TestCase):
    def run_load(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'provenance').mkdir(parents=True)
        (root / 'provenance' / 'artifacts.json').write_text(json.dumps({'files': [
            {'path': 'artifacts/node/94/hl-node', 'sha256': SHA, 'size': len(ADMITTED)}]}))
        binary = root / 'artifacts' / 'node' / '94' / 'hl-node'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(ADMITTED)
        calls = []

        class FakePopen:
            def __init__(self, cmd, stdout=None, text=None, env=None):
                binary.write_bytes(SWAPPED)
                calls.append((cmd[-1], Path(cmd[-1]).read_bytes()))
                self.stdout = io.StringIO('')

            def wait(self):
                return 0

        orig = (tool.ROOT, artifacts.check, elf_index.sections,
                fde_extents.fde_extents, tool.require_pie_without_textrel,
                tool.gnu_objdump, tool.fingerprint, tool.subprocess.Popen)
        tool.ROOT = root
        artifacts.check = lambda path, item: None
        elf_index.sections = lambda data: [
            {'name': '.text', 'address': 0x1000, 'offset': 0, 'size': 0x100},
            {'name': '.plt', 'address': 0x2000, 'offset': 0, 'size': 0x10}]
        fde_extents.fde_extents = lambda data: (
            None, [{'start': 0x1000, 'end': 0x1100, 'section': '.text'}], None)
        tool.require_pie_without_textrel = lambda data, secs: None
        tool.gnu_objdump = lambda: ('/usr/bin/objdump', 'stubbed')
        tool.fingerprint = lambda spans, read, lines, plt: []
        tool.subprocess.Popen = FakePopen
        try:
            digest, data, rows = tool.load_release('94')
        finally:
            (tool.ROOT, artifacts.check, elf_index.sections,
             fde_extents.fde_extents, tool.require_pie_without_textrel,
             tool.gnu_objdump, tool.fingerprint, tool.subprocess.Popen) = orig
        return binary, calls, digest, data

    def test_objdump_does_not_open_the_target_path(self):
        binary, calls, _, _ = self.run_load()
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0][0], str(binary))

    def test_objdump_reads_the_admitted_bytes(self):
        binary, calls, digest, data = self.run_load()
        self.assertEqual(calls[0][1], ADMITTED)
        self.assertEqual(data, ADMITTED)
        self.assertEqual(digest, SHA)


if __name__ == '__main__':
    unittest.main()
