"""Regression tests for tools/legacy/fmtrefs.py.

decode() used to index data[i] with no bounds check, so a template address
past EOF (or a template that runs unterminated to EOF) raised IndexError
and killed the whole scan, losing every other template in the listing.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "legacy" / "fmtrefs.py"
GOT = "6000"


def run_fmtrefs(blob, disasm):
    with tempfile.TemporaryDirectory() as d:
        b = Path(d) / "probe.bin"
        a = Path(d) / "probe.disasm"
        b.write_bytes(blob)
        a.write_text(disasm)
        return subprocess.run(
            [sys.executable, "-I", str(TOOL), str(b), str(a), GOT, "0", "10000"],
            capture_output=True, text=True, timeout=60)


def listing(*targets):
    lines = []
    for i, t in enumerate(targets):
        at = 0x100 * (i + 1)
        lines.append(f"{at:08x}: lea rsi, [rip + 0x0] # 0x{t:x}")
        lines.append(f"{at + 7:08x}: call *0x0(%rip) # 0x{GOT}")
    return "\n".join(lines) + "\n"


class FmtrefsTests(unittest.TestCase):
    def test_out_of_range_template_does_not_kill_scan(self):
        # In-range template at 0x10 decodes to "abc{}de"; the second lea
        # points at 0x9000, far past the 0x40-byte binary.
        blob = bytearray(0x40)
        blob[0x10:0x19] = b"\x03abc\xc0\x02de\x00"
        r = run_fmtrefs(bytes(blob), listing(0x10, 0x9000))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("tmpl@0x10  'abc{}de'", r.stdout)
        self.assertIn("tmpl@0x9000  '{?out-of-range}'", r.stdout)

    def test_unterminated_template_at_eof_decodes_what_fits(self):
        # Template at 0x6: one literal "x", then EOF with no terminator.
        blob = b"\x00" * 6 + b"\x01x"
        r = run_fmtrefs(blob, listing(0x6))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("tmpl@0x6  'x'", r.stdout)


if __name__ == "__main__":
    unittest.main()
