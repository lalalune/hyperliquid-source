"""Regression tests for tools/legacy/inv.py section-name reads.

inv.py used to locate each section name with an unbounded
``data.index(b"\\0", stroff + s["name"])``, so a name unterminated inside
.shstrtab silently borrowed its terminator from the bytes past the table:
a section whose name ran past the table could be misreported (e.g. a
table ending in ".commen" followed by "t\\0" was reported as ".comment"),
and a name offset past the table end died with a bare ValueError
traceback. Names are now bounded to the .shstrtab extent, in the file's
own assert idiom for input validation.
"""
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "legacy" / "inv.py"


def build(names, trailing, comment_name_off):
    """Sections: 0=null, 1=.shstrtab, 2=comment candidate.

    The third section's content is a rustc version string, so a borrowed
    ".comment" name shows up directly in the report.
    """
    shoff, names_off = 0x40, 0x100
    comment_off = names_off + len(names) + len(trailing)
    comment = b"rustc version 1.0\0"
    header = bytearray(64)
    header[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<Q", header, 0x28, shoff)

    def sh(name, typ, addr, off, size):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, addr, off, size, 0, 0, 1, 0)

    headers = [bytes(64),
               sh(names.index(b".shstrtab"), 3, 0, names_off, len(names)),
               sh(comment_name_off, 1, 0, comment_off, len(comment))]
    struct.pack_into("<HHH", header, 0x3A, 64, len(headers), 1)
    blob = bytearray(comment_off + len(comment))
    blob[:64] = header
    for i, h in enumerate(headers):
        blob[shoff + i * 64:shoff + (i + 1) * 64] = h
    blob[names_off:names_off + len(names)] = names
    blob[names_off + len(names):names_off + len(names) + len(trailing)] = trailing
    blob[comment_off:comment_off + len(comment)] = comment
    return bytes(blob)


def run_inv(blob):
    with tempfile.TemporaryDirectory() as d:
        p, out = Path(d) / "probe.elf", Path(d) / "out.json"
        p.write_bytes(blob)
        r = subprocess.run([sys.executable, "-I", str(TOOL), str(p), str(out)],
                           capture_output=True, text=True, timeout=60)
        report = json.loads(out.read_text()) if out.exists() else None
        return r, report


class InvSectionNameTests(unittest.TestCase):
    def test_borrowed_terminator_rejected(self):
        # Table ends with ".commen" (no NUL); "t\0" follows immediately.
        # The unbounded read used to report this section as ".comment".
        r, report = run_inv(build(b"\0.shstrtab\0.commen", b"t\0", 11))
        self.assertNotEqual(r.returncode, 0)
        self.assertIsNone(report)
        self.assertIn("unterminated section name", r.stderr)

    def test_offset_past_table_rejected(self):
        # The comment candidate's name offset lies past the table end.
        r, report = run_inv(build(b"\0.shstrtab\0.comment\0", b"", 100))
        self.assertNotEqual(r.returncode, 0)
        self.assertIsNone(report)
        self.assertIn("outside .shstrtab", r.stderr)

    def test_valid_names_still_reported(self):
        r, report = run_inv(build(b"\0.shstrtab\0.comment\0", b"", 11))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("comment", report)
        self.assertEqual(report["comment"], ["rustc version 1.0"])


if __name__ == "__main__":
    unittest.main()
