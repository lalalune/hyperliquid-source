"""Regression tests for tools/legacy/elfrel.py.

elfrel.py used to index by_name[".rela.dyn"] unconditionally, so any valid
ELF without a .rela.dyn section (relocatable object, static binary) died
with a bare KeyError traceback instead of a readable diagnostic.
"""
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "legacy" / "elfrel.py"


def make_elf(with_rela):
    """Minimal ELF64 with a .shstrtab and, optionally, a one-entry .rela.dyn."""
    names = b"\0.shstrtab\0.rela.dyn\0"
    shstrtab_name = names.index(b".shstrtab")
    rela_name = names.index(b".rela.dyn")
    shoff = 0x40
    names_off = 0x100
    rela_off = 0x120
    header = bytearray(64)
    header[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<Q", header, 0x28, shoff)

    def sh(name, typ, addr, off, size):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, addr, off, size, 0, 0, 1, 0)
    headers = [bytes(64), sh(shstrtab_name, 3, 0, names_off, len(names))]
    if with_rela:
        headers.append(sh(rela_name, 4, 0, rela_off, 24))
    struct.pack_into("<HHH", header, 0x3A, 64, len(headers), 1)
    blob = bytearray(rela_off + 24)
    blob[:64] = header
    for i, h in enumerate(headers):
        blob[shoff + i * 64:shoff + (i + 1) * 64] = h
    blob[names_off:names_off + len(names)] = names
    if with_rela:
        # One R_X86_64_RELATIVE entry: slot 0x3000 -> addend 0x4000.
        struct.pack_into("<QQq", blob, rela_off, 0x3000, 8, 0x4000)
    return bytes(blob)


def run_elfrel(blob, *targets):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "probe.elf"
        p.write_bytes(blob)
        return subprocess.run(
            [sys.executable, "-I", str(TOOL), str(p), *targets],
            capture_output=True, text=True, timeout=60)


class ElfrelTests(unittest.TestCase):
    def test_missing_rela_dyn_exits_with_clear_message(self):
        r = run_elfrel(make_elf(with_rela=False), "4000")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no .rela.dyn section", r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertNotIn("KeyError", r.stderr)

    def test_with_rela_dyn_still_reports_slots(self):
        r = run_elfrel(make_elf(with_rela=True), "4000")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("=== target 0x4000", r.stdout)
        self.assertIn("1 slot(s)", r.stdout)


if __name__ == "__main__":
    unittest.main()
