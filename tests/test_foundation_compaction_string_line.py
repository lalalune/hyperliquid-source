"""Tests for the node #94 compaction-stats string line model.

Evidence: research/work-items/RE-001-compaction-string-line-94/.
Run: python3 -m unittest tests.test_foundation_compaction_string_line
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from foundation_compaction_string_line import (  # noqa: E402
    FIELD_ORDER,
    LOOKUP_ORDER,
    OutOfRange,
    render_compaction_string_line,
    render_data_line,
)

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" \
    / "RE-001-compaction-string-line-94"


def sample_map():
    return {k: "v%d" % k for k in FIELD_ORDER}


class TestCompactionStringLine(unittest.TestCase):
    def test_full_output_shape(self):
        out = render_compaction_string_line("node-a", "FIRST", sample_map())
        lines = out.split("\n")
        # header line, data line, dash line, trailing empty from final \n
        self.assertEqual(lines[0], "")
        self.assertEqual(lines[1], "** Compaction Stats [node-a] **")
        self.assertTrue(lines[2].startswith("FIRST    v1   v3     v4 v5  v6"))
        self.assertTrue(lines[2].endswith("v21"))
        self.assertEqual(lines[3], "-" * len(lines[2] + "\n"))
        self.assertEqual(lines[4], "")

    def test_field_order_and_spacing(self):
        data = render_data_line("FIRST", sample_map())
        fields = ["FIRST"] + ["v%d" % k for k in FIELD_ORDER]
        gaps = [4, 3, 5, 1, 2] + [1] * 15
        expected = fields[0]
        for gap, field in zip(gaps, fields[1:]):
            expected += " " * gap + field
        self.assertEqual(data, expected + "\n")

    def test_key_2_is_not_read(self):
        # A map with key 2 present renders identically, and a map
        # without key 2 still renders: the first field is the caller's
        # string, not a map value.
        m = sample_map()
        m[2] = "v2-should-be-ignored"
        self.assertEqual(render_data_line("FIRST", m),
                         render_data_line("FIRST", sample_map()))
        self.assertNotIn("v2-should-be-ignored",
                         render_data_line("FIRST", m))

    def test_missing_key_throws_in_lookup_order(self):
        m = sample_map()
        del m[20]
        del m[1]
        with self.assertRaises(OutOfRange) as ctx:
            render_data_line("FIRST", m)
        self.assertIn("20", str(ctx.exception))  # 20 precedes 1
        with self.assertRaises(OutOfRange):
            render_data_line("FIRST", {k: "v" for k in FIELD_ORDER
                                       if k != 1})

    def test_empty_map_throws_on_21(self):
        with self.assertRaises(OutOfRange) as ctx:
            render_data_line("FIRST", {})
        self.assertIn("21", str(ctx.exception))

    def test_dash_length_matches_data_line(self):
        out = render_compaction_string_line("n", "F", sample_map())
        data = render_data_line("F", sample_map())
        dashes = out.split("\n")[3]
        self.assertEqual(len(dashes), len(data))

    def test_long_output_truncates_to_1999(self):
        big = {k: "x" * 300 for k in FIELD_ORDER}
        out = render_compaction_string_line("n" * 100, "F" * 100, big)
        self.assertEqual(len(out), 1999)
        # Truncation keeps the header prefix intact.
        self.assertTrue(out.startswith("\n** Compaction Stats ["))

    def test_short_output_not_truncated(self):
        out = render_compaction_string_line("n", "F", sample_map())
        self.assertLess(len(out), 1999)
        self.assertTrue(out.endswith("\n"))

    def test_lookup_order_is_descending_without_2(self):
        self.assertEqual(LOOKUP_ORDER,
                         [21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
                          10, 9, 8, 7, 6, 5, 4, 3, 1])

    def test_packet_verification(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "ALL CHECKS PASSED",
                         result.stdout + result.stderr)

    def test_excerpt_regeneration(self):
        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "csline-regen"
        tmp.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [sys.executable, str(PACKET / "export_excerpts.py"),
             "--out", str(tmp)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("window.objdump.txt", "helper.objdump.txt",
                     "callers.objdump.txt", "plt.objdump.txt"):
            self.assertEqual((tmp / name).read_text(),
                             (PACKET / name).read_text(), name)

    def test_corruption_controls(self):
        # Tampering with a packet excerpt must fail verification, and a
        # missing binary must fail it too.
        import shutil
        pkt_copy = Path(os.environ.get("TMPDIR", "/tmp")) \
            / "csline-corrupt" / "pkt"
        if pkt_copy.exists():
            shutil.rmtree(pkt_copy)
        shutil.copytree(PACKET, pkt_copy)
        (pkt_copy / "window.objdump.txt").write_text(
            (PACKET / "window.objdump.txt").read_text().replace(
                "514d770:", "514d771:", 1))
        result = subprocess.run(
            [sys.executable, str(pkt_copy / "verify.py"), "--binary",
             str(Path(__file__).resolve().parents[1] / "work"
                 / "hl-node-94.bin")],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILURES", result.stdout)
        result2 = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"),
             "--binary", "/nonexistent/hl-node-94.bin"],
            capture_output=True, text=True)
        self.assertNotEqual(result2.returncode, 0)


if __name__ == "__main__":
    unittest.main()
