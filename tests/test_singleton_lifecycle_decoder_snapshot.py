"""singleton_lifecycle generate() must decode a private snapshot.

The tool admitted the target once (artifacts.check plus the controls and
relocations computed from the bytes read into memory) but then ran
readelf/objdump against the target *path*, so frames.txt, the per-range
objdump files, relocations.txt and the decoded reference census were
bound to whatever the path served at decode time while records.json
stamped the admitted digest. A same-size replacement of the watched
relocation slot's addend between admission and decode changed
relocations.txt in a live reproduction while records.json still claimed
the pinned digest. Sibling tools (compact_string_unwind on main,
cguard_consistency_static) already decode a private snapshot of the
admitted bytes.

The pinned node94 capture is an LFS pointer on this VM, so admission
(check/controls/relocations/read_va) is stubbed here; what this test
verifies is exactly the defect's surface -- which file the decoders
open. The wrapper swaps the binary file's bytes (same size) at the
first decoder call, modelling a replacement between admission and
decode, and records the path each decoder was given plus the bytes at
that path at call time.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import singleton_lifecycle as tool

ADMITTED = b'A' * 64
SWAPPED = b'B' * 64


def fde_line(start, end):
    return f'FDE pc={start:016x}..{end:016x}\n'


class DecoderSnapshotTests(unittest.TestCase):
    def run_generate(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        binary = root / 'hl-node'
        binary.write_bytes(ADMITTED)
        out = root / 'out'
        calls = []
        swapped = []

        def note_call(path):
            if not swapped:
                binary.write_bytes(SWAPPED)
                swapped.append(True)
            calls.append((path, Path(path).read_bytes()))

        real_check_output = tool.subprocess.check_output
        real_popen = tool.subprocess.Popen

        def fake_check_output(cmd, text=True, encoding=None):
            note_call(cmd[-1])
            if cmd[0] == 'readelf' and '-wf' in cmd:
                return ''.join(fde_line(s, e) for _, (s, e) in tool.RANGES.items())
            if cmd[0] == 'objdump':
                return 'canned disassembly\n'
            if cmd[0] == 'readelf':
                return ''.join(f'{slot:x}  RELATIVE\n' for slot in tool.SLOTS)
            return real_check_output(cmd, text=text)

        class FakePopen:
            def __init__(self, cmd, stdout=None, text=None):
                note_call(cmd[-1])
                self.stdout = iter([])

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def wait(self):
                return 0

        orig = (tool.check, tool.controls, tool.relocations, tool.read_va,
                tool.subprocess.check_output, tool.subprocess.Popen)
        tool.check = lambda binary_, identity: None
        tool.controls = lambda data: ({}, {})
        tool.relocations = lambda data: []
        # read_va already reads from the admitted `data`; it is not the
        # defect surface, so it is stubbed alongside admission.
        tool.read_va = lambda data, va, length: (0, b'\x00' * length)
        tool.subprocess.check_output = fake_check_output
        tool.subprocess.Popen = FakePopen
        try:
            result = tool.generate(binary, out)
        finally:
            (tool.check, tool.controls, tool.relocations, tool.read_va,
             tool.subprocess.check_output, tool.subprocess.Popen) = orig
        return binary, out, calls, result

    def test_decoders_do_not_open_the_target_path(self):
        binary, out, calls, _ = self.run_generate()
        # readelf frames + whole-.text objdump + one objdump per range
        # + readelf relocations.
        self.assertEqual(len(calls), 2 + len(tool.RANGES) + 1)
        for path, _ in calls:
            self.assertNotEqual(path, str(binary))

    def test_decoders_read_the_admitted_bytes(self):
        binary, out, calls, result = self.run_generate()
        for path, seen in calls:
            self.assertEqual(seen, ADMITTED)
        self.assertEqual(result['target_bytes'], len(ADMITTED))
        records = json.loads((out / 'records.json').read_text())
        self.assertEqual(records['target_bytes'], len(ADMITTED))
        self.assertTrue((out / 'frames.txt').exists())
        self.assertTrue((out / 'relocations.txt').exists())


if __name__ == '__main__':
    unittest.main()
