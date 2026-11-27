"""Binary-backed verification for RE-010 node #115 Bole Reserve interest engine."""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN_PATH = ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_INDEX = ROOT / "work" / "index" / "node-115-fde.tsv"
PACKET_DIR = ROOT / "research" / "work-items" / "RE-010-node115-bole-reserve-interest-engine"
EVIDENCE_PATH = PACKET_DIR / "evidence.json"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def _load_segments(data: bytes) -> list[tuple[int, int, int]]:
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    segs: list[tuple[int, int, int]] = []
    for i in range(e_phnum):
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", data, e_phoff + i * e_phentsize
        )
        if p_type == 1:
            segs.append((p_vaddr, p_vaddr + p_filesz, p_offset))
    return segs


def _v2o(segs: list[tuple[int, int, int]], va: int) -> int:
    for start, end, off in segs:
        if start <= va < end:
            return off + (va - start)
    raise KeyError(f"VA {hex(va)} not mapped in PT_LOAD")


class TestBoleReserveInterestEngine115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        cls.binary = BIN_PATH.read_bytes()
        cls.segs = _load_segments(cls.binary)
        cls.fdes: dict[int, tuple[int, int, int]] = {}
        for line in FDE_INDEX.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#") or line.startswith("start_va"):
                continue
            parts = line.split("\t")
            start_va = int(parts[0], 16)
            end_va = int(parts[1], 16)
            size = int(parts[2])
            fde_idx = int(parts[-1])
            cls.fdes[start_va] = (end_va, size, fde_idx)

    def test_target_digest_and_exact_fde_extents(self) -> None:
        self.assertEqual(self.evidence["target"]["sha256"], TARGET_SHA256)
        self.assertEqual(hashlib.sha256(self.binary).hexdigest(), TARGET_SHA256)

        for entry in self.evidence["fdes"]:
            start_va = int(entry["start_va"], 16)
            end_va = int(entry["end_va"], 16)
            size = entry["size"]
            self.assertIn(start_va, self.fdes, f"missing FDE {entry['name']}")
            idx_end, idx_size, idx_num = self.fdes[start_va]
            self.assertEqual(idx_end, end_va)
            self.assertEqual(idx_size, size)
            self.assertEqual(idx_num, entry["fde_index"])

    def test_embedded_immediate_constants_and_rodata_anchors(self) -> None:
        # 1e14 scale (0x5af3107a4000) appears as 8-byte LE immediate in all 9 FDEs.
        scale_le = struct.pack("<Q", 100_000_000_000_000)
        for entry in self.evidence["fdes"]:
            start = _v2o(self.segs, int(entry["start_va"], 16))
            chunk = self.binary[start : start + entry["size"]]
            self.assertIn(scale_le, chunk, f"missing 1e14 immediate in {entry['name']}")

        # Julian year ms (31_557_600_000 = 0x758fac300) in Reserve::accrue_interest (0x36a0200).
        accrue_off = _v2o(self.segs, 0x36A0200)
        accrue_bytes = self.binary[accrue_off : accrue_off + 1709]
        self.assertIn(struct.pack("<Q", 31_557_600_000), accrue_bytes)

        # Magic divisors in utilization_bps (0x36a08b0) and yearly_borrow_rate_bps (0x36a0b30).
        util_bps_off = _v2o(self.segs, 0x36A08B0)
        self.assertIn(struct.pack("<Q", 0x6DF37F675EF7), self.binary[util_bps_off : util_bps_off + 312])
        rate_bps_off = _v2o(self.segs, 0x36A0B30)
        self.assertIn(struct.pack("<Q", 0xDBE6FECEBDEDD5BF), self.binary[rate_bps_off : rate_bps_off + 578])

        # Min leg notional $100 (0x5f5e100) in 0x36939f0.
        min_leg_off = _v2o(self.segs, 0x36939F0)
        self.assertIn(struct.pack("<I", 100_000_000), self.binary[min_leg_off : min_leg_off + 465])

        # .rodata anchors: 1e14_f64 at 0x459378 and ASCII strings.
        scale_f64_off = _v2o(self.segs, 0x459378)
        self.assertEqual(struct.unpack_from("<d", self.binary, scale_f64_off)[0], 1e14)
        for anchor in self.evidence["rodata_anchors"]:
            if "ascii" in anchor:
                off = _v2o(self.segs, int(anchor["va"], 16))
                expected = anchor["ascii"].encode("ascii")
                self.assertEqual(self.binary[off : off + len(expected)], expected)

    def test_negative_controls(self) -> None:
        # 1. Wrong Julian year constant (365.0 days = 31_536_000_000 ms) is NOT in accrue_interest.
        accrue_off = _v2o(self.segs, 0x36A0200)
        accrue_bytes = self.binary[accrue_off : accrue_off + 1709]
        self.assertNotIn(struct.pack("<Q", 31_536_000_000), accrue_bytes)

        # 2. Tampering an FDE end VA breaks exact FDE-index check.
        idx_end, _, _ = self.fdes[0x36A0200]
        self.assertNotEqual(idx_end, 0x36A08AD + 1)

        # 3. Wrong scale immediate (1e12) is absent from utilization_scaled.
        util_off = _v2o(self.segs, 0x369FF10)
        self.assertNotIn(struct.pack("<Q", 1_000_000_000_000), self.binary[util_off : util_off + 302])


if __name__ == "__main__":
    unittest.main()
