import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import pxpriv_admission94 as pa

PACKET = ROOT / "research" / "work-items" / "RE-004-pxpriv-admission-94"
GENERATED = ["evidence.json", "call-sites.tsv", "branches.tsv",
             "admission-cases.tsv", "narrow-width-cases.tsv",
             "constructor-bytes.txt"]


def va_offset(img, va):
    for s in img.sections.values():
        if s["address"] <= va < s["address"] + s["size"]:
            return s["offset"] + (va - s["address"])
    raise AssertionError(f"{va:#x} outside sections")


class DecoderTests(unittest.TestCase):
    def test_branch_forms(self):
        self.assertEqual(pa.decode_branch(b"\x0f\x84\x10\x00\x00\x00", 0x1000),
                         ("je", 6, 0x1016))
        self.assertEqual(pa.decode_branch(b"\x0f\x88\xa3\x01\x00\x00", 0x2000),
                         ("js", 6, 0x21A9))
        self.assertEqual(pa.decode_branch(b"\x0f\x89\x25\x01\x00\x00", 0x3000),
                         ("jns", 6, 0x312B))
        self.assertEqual(pa.decode_branch(b"\x74\x10", 0x4000), ("je", 2, 0x4012))
        self.assertEqual(pa.decode_branch(b"\x75\x66", 0x5000), ("jne", 2, 0x5068))
        self.assertEqual(pa.decode_branch(b"\xeb\xce", 0x6000), ("jmp", 2, 0x5FD0))
        self.assertEqual(pa.decode_branch(b"\xe9\x49\x04\x00\x00", 0x7000),
                         ("jmp", 5, 0x744E))
        # Real case: the A converting-error call (0x2812e92 -> 0x22e4bd0).
        self.assertEqual(pa.decode_branch(b"\xe8\x39\x1d\xad\xff", 0x2812E92),
                         ("call", 5, 0x22E4BD0))
        self.assertEqual(pa.decode_branch(b"\x0f\x8c\x00\x00\x00\x00", 0x1000),
                         ("jl", 6, 0x1006))
        self.assertEqual(pa.decode_branch(b"\x0f\x8f\x00\x00\x00\x00", 0x1000),
                         ("jg", 6, 0x1006))
        # Non-branch opcodes and truncations decode to None.
        self.assertIsNone(pa.decode_branch(b"\x90\x90\x90", 0x1000))
        self.assertIsNone(pa.decode_branch(b"\x0f\x84\x10", 0x1000))
        self.assertIsNone(pa.decode_branch(b"\xe8\x01\x02", 0x1000))
        self.assertIsNone(pa.decode_branch(b"", 0x1000))

    def test_lea_and_slot_resolvers(self):
        self.assertEqual(pa.resolve_lea_rip(b"\x48\x8d\x35\x19\x1a\xf0\xfd", 0x22E4C86),
                         0x1E66A6)
        self.assertEqual(pa.resolve_lea_rip(b"\x4c\x8d\x35\x19\x1a\xf0\xfd", 0x22E4C86),
                         0x1E66A6)
        self.assertIsNone(pa.resolve_lea_rip(b"\x48\x8d\x34\x24\x18", 0x1000))
        self.assertEqual(pa.resolve_got_load(b"\x48\x8b\x05\xaf\x9d\x48\x03", 0x22E4C7A),
                         0x576EA30)
        self.assertIsNone(pa.resolve_got_load(b"\x48\x8b\x44\x24\x10", 0x1000))
        self.assertEqual(pa.resolve_indirect_call_slot(b"\xff\x15\xa0\x93\x48\x03", 0x22E4C9A),
                         0x576E040)
        self.assertIsNone(pa.resolve_indirect_call_slot(b"\xff\xd0", 0x1000))

    def test_admit_boundaries(self):
        self.assertEqual(pa.admit("u64", 0), ("reject", "u64"))
        self.assertEqual(pa.admit("u64", 1), ("admit", None))
        self.assertEqual(pa.admit("u64", (1 << 64) - 1), ("admit", None))
        self.assertEqual(pa.admit("i64", -(1 << 63)), ("reject", "converting"))
        self.assertEqual(pa.admit("i64", -1), ("reject", "converting"))
        self.assertEqual(pa.admit("i64", 0), ("reject", "i64"))
        self.assertEqual(pa.admit("i64", 1), ("admit", None))
        self.assertEqual(pa.admit("i64", (1 << 63) - 1), ("admit", None))
        with self.assertRaises(pa.EvidenceError):
            pa.admit("f32", 0)

    def test_narrow_extension_exhaustive_small_widths(self):
        for raw in range(256):
            self.assertEqual(pa.admit("u64", pa.extend(8, False, raw)),
                             ("reject", "u64") if raw == 0 else ("admit", None))
            v = pa.extend(8, True, raw)
            want = ("reject", "converting") if v < 0 else \
                ("reject", "i64") if v == 0 else ("admit", None)
            self.assertEqual(pa.admit("i64", v), want)
        for width, signed, samples in [
                (16, False, [0, 1, 0x8000, 0xFFFF]),
                (16, True, [0, 1, 0x7FFF, 0x8000, 0xFFFF]),
                (32, False, [0, 1, 0x80000000, 0xFFFFFFFF]),
                (32, True, [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF])]:
            for raw in samples:
                v = pa.extend(width, signed, raw)
                if signed:
                    want = ("reject", "converting") if v < 0 else \
                        ("reject", "i64") if v == 0 else ("admit", None)
                else:
                    want = ("reject", "u64") if v == 0 else ("admit", None)
                self.assertEqual(pa.admit("i64" if signed else "u64", v), want)


class BinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / "artifacts" / "node" / "94" / "hl-node").read_bytes()
        cls.img = pa.Image(cls.data)

    def test_digest_gate(self):
        self.assertEqual(pa.check_digest(self.data), pa.TARGET_SHA256)
        with self.assertRaises(pa.EvidenceError):
            pa.check_digest(b"not the node binary")
        flipped = bytes([self.data[0] ^ 0xFF]) + self.data[1:]
        with self.assertRaises(pa.EvidenceError):
            pa.check_digest(flipped)

    def _mutated_image(self, va, byte_index, new_byte):
        buf = bytearray(self.data)
        off = va_offset(self.img, va) + byte_index
        buf[off] = new_byte
        return pa.Image(bytes(buf))

    def test_tampered_piece_marker_is_rejected(self):
        # u64 piece: marker byte sits at piece_va + 1 + len("invalid value ").
        piece_va = 0x1E66A6
        img = self._mutated_image(piece_va, 1 + len(pa.LITERAL) + 1, 0x1E)
        with self.assertRaises(pa.EvidenceError):
            pa.find_pieces(img)

    def test_tampered_bare_fragment_is_rejected(self):
        img = self._mutated_image(pa.BARE_VA, 0, 0x0B)
        with self.assertRaises(pa.EvidenceError):
            pa.find_pieces(img)

    def test_tampered_ctor_got_slot_is_rejected(self):
        # form-1b u64 ctor 0x22e4c70: GOT-load disp32 starts at +10+3.
        img = self._mutated_image(0x22E4C70, 13, 0x00)
        leas = img.lea_targets()
        with self.assertRaises(pa.EvidenceError):
            pa.verify_ctors(img, leas)

    def test_tampered_call_target_is_rejected(self):
        # i64 error call in caller A: rel32 starts at call_va + 1.
        img = self._mutated_image(0x2812CF7, 1, 0x00)
        calls = img.direct_calls()
        with self.assertRaises(pa.EvidenceError):
            pa.verify_call_sites(img, calls)

    def test_tampered_branch_target_is_rejected(self):
        # A dispatch je: rel32 starts at +2.
        img = self._mutated_image(0x2812CC8, 2, 0x00)
        with self.assertRaises(pa.EvidenceError):
            pa.verify_branches(img)

    def test_tampered_narrow_anchor_is_rejected(self):
        # C u8-register entry: movzx opcode 0f b6 at the entry VA.
        img = self._mutated_image(0x2E62645, 0, 0x90)
        with self.assertRaises(pa.EvidenceError):
            pa.verify_narrow(img)

    def test_packet_files_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(pa.main(["--out", tmp]), 0)
            for name in GENERATED:
                self.assertEqual((Path(tmp) / name).read_bytes(),
                                 (PACKET / name).read_bytes(), name)
        manifest = {}
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            manifest[name] = digest
        self.assertEqual(set(manifest),
                         {p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"})
        for name, digest in manifest.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(),
                             digest, name)


if __name__ == "__main__":
    unittest.main()
