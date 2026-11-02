"""Unit tests for the RE-004 be20 mid-table packet.

Covers regeneration vs the packet files, segment bytes vs the binary,
count cross-checks, relocation entries vs the binary, and tamper
controls (a corrupted digest and a corrupted relocation must fail).
"""

import filecmp
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import be20_mid_table as gen  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-004-be20-mid-table-94"
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"


class TestBe20MidTable(unittest.TestCase):
    def test_generator_output_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen.verify(NODE)
            gen.emit(tmp)
            for name in ("records.tsv", "triples.tsv", "segments.txt",
                         "evidence.json"):
                self.assertTrue(
                    filecmp.cmp(Path(tmp) / name, PACKET / name, shallow=False),
                    f"{name} differs from packet file")

    def test_segment_bytes_match_binary(self):
        data = NODE.read_bytes()
        total = 0
        for name, start, end, kind, digest in gen.SEGMENTS:
            off = gen.file_offset(start, kind)
            chunk = data[off:off + (end - start)]
            self.assertEqual(len(chunk), end - start, name)
            self.assertEqual(hashlib.sha256(chunk).hexdigest(), digest, name)
            total += len(chunk)
        self.assertEqual(total, 750)

    def test_counts_cross_check(self):
        self.assertEqual(len(gen.RECORDS), 4)
        self.assertEqual(len(gen.SEGMENTS), 16)
        self.assertEqual(len(gen.RELOCS), 12)
        self.assertEqual(sum(1 for _ in gen.TRIPLE_DIFFS), 4)
        rec_lines = (PACKET / "records.tsv").read_text().splitlines()
        tri_lines = (PACKET / "triples.tsv").read_text().splitlines()
        seg_lines = (PACKET / "segments.txt").read_text().splitlines()
        self.assertEqual(len(rec_lines), 5)   # header + 4
        self.assertEqual(len(tri_lines), 13)  # header + 12
        self.assertEqual(len(seg_lines), 16)
        seg_bytes = sum(int(line.split("\t")[3]) for line in seg_lines)
        self.assertEqual(seg_bytes, 750)

    def test_reloc_entries_match_binary(self):
        data = NODE.read_bytes()
        for entry, slot, addend in gen.RELOCS:
            off = gen.RELA_DYN_FILE_OFF + entry * gen.RELA_ENTRY_SIZE
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
            self.assertEqual(r_info & 0xFFFFFFFF, gen.RELATIVE_TYPE)
            self.assertEqual(r_offset, slot)
            self.assertEqual(r_addend, addend)

    def test_tamper_segment_fails(self):
        saved = gen.SEGMENTS[0]
        try:
            gen.SEGMENTS[0] = (saved[0], saved[1], saved[2], saved[3],
                               "00" * 32)
            with self.assertRaises(SystemExit):
                gen.verify(NODE)
        finally:
            gen.SEGMENTS[0] = saved

    def test_tamper_reloc_fails(self):
        saved = gen.RELOCS[0]
        try:
            gen.RELOCS[0] = (saved[0], saved[1], saved[2] + 8)
            with self.assertRaises(SystemExit):
                gen.verify(NODE)
        finally:
            gen.RELOCS[0] = saved


if __name__ == "__main__":
    unittest.main()
