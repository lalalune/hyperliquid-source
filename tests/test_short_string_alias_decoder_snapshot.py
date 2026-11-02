"""short_string_alias generate() must hand decode() a private snapshot.

The tool admitted the target once (artifacts.check against the pinned
digest, plus the admitted bytes read into memory) but then called
decode(binary, data) with the target *path*: decode() runs readelf -wf
and GNU/LLVM objdump against that path. The instruction bytes are
cross-checked against the admitted data, but frames.txt is emitted
from the live readelf output with no cross-check, so a same-size
replacement between admission and decode changed frames.txt in a live
reproduction while records.json still claimed the pinned digest.
Sibling tools (compact_string_unwind on main, cguard_consistency_static)
already decode a private snapshot of the admitted bytes.

The pinned node94 capture is an LFS pointer on this VM, so admission
(check) and the analysis stages (decode's internals, evaluate) are
stubbed here; what this test verifies is exactly the fix's surface --
which file generate() hands to decode(). The decode stub swaps the
binary file's bytes (same size) before reading the path it was given,
modelling a replacement between admission and decode.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import short_string_alias as tool

ADMITTED = b'A' * 64
SWAPPED = b'B' * 64


class DecoderSnapshotTests(unittest.TestCase):
    def run_generate(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        binary = root / 'hl-node'
        binary.write_bytes(ADMITTED)
        out = root / 'out'
        seen = []

        def fake_decode(path, data):
            binary.write_bytes(SWAPPED)
            seen.append((str(path), Path(path).read_bytes()))
            return {}, {}

        orig = (tool.check, tool.decode, tool.evaluate, tool.read_va)
        tool.check = lambda binary_, identity: None
        tool.decode = fake_decode
        tool.evaluate = lambda code: {'instruction_visits': {}}
        # read_va already reads from the admitted `data`; it is not the
        # defect surface, so it is stubbed alongside admission.
        tool.read_va = lambda data, va, length: (0, b'\x00' * length)
        try:
            result = tool.generate(binary, out)
        finally:
            (tool.check, tool.decode, tool.evaluate, tool.read_va) = orig
        return binary, out, seen, result

    def test_decode_does_not_receive_the_target_path(self):
        binary, out, seen, _ = self.run_generate()
        self.assertEqual(len(seen), 1)
        self.assertNotEqual(seen[0][0], str(binary))

    def test_decode_reads_the_admitted_bytes(self):
        binary, out, seen, result = self.run_generate()
        self.assertEqual(seen[0][1], ADMITTED)
        self.assertEqual(result['target_bytes'], len(ADMITTED))
        records = json.loads((out / 'records.json').read_text())
        self.assertEqual(records['target_bytes'], len(ADMITTED))


if __name__ == '__main__':
    unittest.main()
