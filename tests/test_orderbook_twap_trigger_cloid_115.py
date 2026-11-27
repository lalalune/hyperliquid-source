"""Verify node #115 Book 8-field schema, cloid_tracker, Trigger/tpsl, TwapState, and 0x58e74c0 anchors."""
import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-006-node115-twap-trigger-cloid"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def _load_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    secs = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _t, _f, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", data, off)
        end = data.index(b"\x00", shstr_off + sh_name)
        secs[data[shstr_off + sh_name : end].decode("utf-8", "replace")] = (
            sh_addr,
            sh_offset,
            sh_size,
        )
    return secs


def _va_to_off(secs: dict[str, tuple[int, int, int]], va: int) -> int:
    for sa, so, sz in secs.values():
        if sa != 0 and sa <= va < sa + sz:
            return so + (va - sa)
    raise KeyError(f"VA 0x{va:x} not mapped")


class OrderbookTwapTriggerCloidNode115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BINARY.read_bytes()
        cls.sha256 = hashlib.sha256(cls.data).hexdigest()
        cls.secs = _load_elf_sections(cls.data)
        cls.evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))

    def test_target_digest_and_rodata_schemas(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)
        for label, va_hex, needle in self.evidence["rodata_anchors"]:
            va = int(va_hex, 16)
            off = _va_to_off(self.secs, va)
            raw = self.data[off : off + len(needle)]
            self.assertEqual(raw.decode("ascii"), needle, f"rodata mismatch for {label}")

    def test_text_slices_and_manifest(self) -> None:
        for rec in self.evidence["anchored_slices"]:
            va = int(rec["va"], 16)
            off = _va_to_off(self.secs, va)
            got = hashlib.sha256(self.data[off : off + rec["size"]]).hexdigest()
            self.assertEqual(got, rec["sha256"])

        manifest = PACKET / "MANIFEST.sha256"
        lines = [
            ln.strip()
            for ln in manifest.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        self.assertGreaterEqual(len(lines), 2)
        for line in lines:
            want, rel = line.split("  ", 1)
            got = hashlib.sha256((PACKET / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want)


if __name__ == "__main__":
    unittest.main()
