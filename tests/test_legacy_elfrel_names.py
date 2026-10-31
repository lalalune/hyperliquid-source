"""Regression tests for tools/legacy/elfrel.py section-name reads.

elfrel.py used to locate each section name with an unbounded
``data.index(b"\\0", strtab_off + s[0])``, so a name unterminated inside
.shstrtab silently borrowed its terminator from the bytes past the table
(a section whose name ran past the table could be misidentified as
.rela.dyn), and a name offset past the table end died with a bare
ValueError traceback. Names are now bounded to the .shstrtab extent.
"""
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "legacy" / "elfrel.py"


def build(names, trailing, rela_name_off, extra_name_offs=()):
    """Sections: 0=null, 1=.shstrtab, 2=.rela.dyn, then extras.

    The .rela.dyn section points at one R_X86_64_RELATIVE entry
    (slot 0x3000 -> addend 0x4000) placed after the table + trailing bytes.
    """
    shoff, names_off = 0x40, 0x100
    rela_off = names_off + len(names) + len(trailing)
    header = bytearray(64)
    header[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<Q", header, 0x28, shoff)

    def sh(name, typ, addr, off, size):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, addr, off, size, 0, 0, 1, 0)

    headers = [bytes(64),
               sh(names.index(b".shstrtab"), 3, 0, names_off, len(names)),
               sh(rela_name_off, 4, 0, rela_off, 24)]
    for off_name in extra_name_offs:
        headers.append(sh(off_name, 4, 0, 0, 0))
    struct.pack_into("<HHH", header, 0x3A, 64, len(headers), 1)
    blob = bytearray(rela_off + 24)
    blob[:64] = header
    for i, h in enumerate(headers):
        blob[shoff + i * 64:shoff + (i + 1) * 64] = h
    blob[names_off:names_off + len(names)] = names
    blob[names_off + len(names):names_off + len(names) + len(trailing)] = trailing
    struct.pack_into("<QQq", blob, rela_off, 0x3000, 8, 0x4000)
    return bytes(blob)


def run_elfrel(blob, target="4000"):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "probe.elf"
        p.write_bytes(blob)
        return subprocess.run([sys.executable, "-I", str(TOOL), str(p), target],
                              capture_output=True, text=True, timeout=60)


class ElfrelSectionNameTests(unittest.TestCase):
    def test_borrowed_terminator_rejected(self):
        # Table ends with ".rela" (no NUL); ".dyn\0" follows immediately.
        # The unbounded read used to report this section as ".rela.dyn".
        blob = build(b"\0.shstrtab\0.rela", b".dyn\0", 11)
        r = run_elfrel(blob)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unterminated section name", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_offset_past_table_rejected(self):
        # An extra section whose name offset lies past the table end.
        blob = build(b"\0.shstrtab\0.rela.dyn\0", b"", 11,
                     extra_name_offs=(100,))
        r = run_elfrel(blob)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("outside .shstrtab", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_valid_names_still_report_slots(self):
        blob = build(b"\0.shstrtab\0.rela.dyn\0", b"", 11)
        r = run_elfrel(blob)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 slot(s)", r.stdout)


if __name__ == "__main__":
    unittest.main()
