"""Binary-backed verification for RE-007-node115-spot-clearinghouse-accounting."""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BIN_PATH = REPO / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO / "work" / "index" / "node-115-fde.tsv"
PACKET = REPO / "research" / "work-items" / "RE-007-node115-spot-clearinghouse-accounting"
EVIDENCE_PATH = PACKET / "evidence.json"


def _parse_sections(elf: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", elf, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", elf, 58)
    shstr_off = struct.unpack_from("<Q", elf, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    out: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _t, _f, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", elf, off)
        end = elf.index(b"\x00", shstr_off + sh_name)
        out[elf[shstr_off + sh_name : end].decode("ascii")] = (sh_addr, sh_offset, sh_size)
    return out


def _read_va(elf: bytes, secs: dict[str, tuple[int, int, int]], sec: str, va: int, n: int) -> bytes:
    sva, soff, ssz = secs[sec]
    assert sva <= va and va + n <= sva + ssz, f"VA {hex(va)}..+{n} outside {sec}"
    return elf[soff + (va - sva) : soff + (va - sva) + n]


def _load_fde_map() -> dict[int, int]:
    out: dict[int, int] = {}
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                out[int(parts[0], 16)] = int(parts[1], 16)
    return out


class TestSpotClearinghouseAccounting115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        cls.elf = BIN_PATH.read_bytes()
        cls.secs = _parse_sections(cls.elf)
        cls.fdes = _load_fde_map()

    def test_binary_sha256_and_fde_extents(self) -> None:
        digest = hashlib.sha256(self.elf).hexdigest()
        self.assertEqual(digest, self.evidence["target_sha256"])

        total_bytes = 0
        for rec in self.evidence["fdes"]:
            s = int(rec["start_va"], 16)
            e = int(rec["end_va"], 16)
            self.assertIn(s, self.fdes, f"missing FDE start {rec['start_va']}")
            self.assertEqual(self.fdes[s], e, f"FDE end mismatch for {rec['name']}")
            self.assertEqual(e - s, rec["size"])
            total_bytes += rec["size"]
        self.assertEqual(len(self.evidence["fdes"]), 9)
        self.assertEqual(total_bytes, 12360)

    def test_rodata_literals_constants_instructions_and_panic_locations(self) -> None:
        for item in self.evidence["rodata_strings"]:
            va = int(item["va"], 16)
            expected = item["text"].encode("utf-8")
            got = _read_va(self.elf, self.secs, ".rodata", va, len(expected))
            self.assertEqual(got, expected, f"rodata string mismatch at {item['va']}")

        for item in self.evidence["rodata_bytes"]:
            va = int(item["va"], 16)
            expected = bytes.fromhex(item["hex"])
            got = _read_va(self.elf, self.secs, ".rodata", va, len(expected))
            self.assertEqual(got, expected, f"rodata bytes mismatch for {item['name']}")

        for item in self.evidence["rodata_f64"]:
            va = int(item["va"], 16)
            raw = _read_va(self.elf, self.secs, ".rodata", va, 8)
            bits = struct.unpack("<Q", raw)[0]
            val = struct.unpack("<d", raw)[0]
            self.assertEqual(bits, int(item["bits_hex"], 16), f"f64 bits mismatch for {item['name']}")
            self.assertEqual(val, item["value"])

        for item in self.evidence["instruction_anchors"]:
            va = int(item["va"], 16)
            expected = bytes.fromhex(item["hex"])
            got = _read_va(self.elf, self.secs, ".text", va, len(expected))
            self.assertEqual(got, expected, f"instruction anchor mismatch for {item['name']}")

        # Verify every panic Location struct via .rela.dyn R_X86_64_RELATIVE + .data.rel.ro
        rd_va, rd_off, rd_sz = self.secs[".rela.dyn"]
        drr_va, drr_off, drr_sz = self.secs[".data.rel.ro"]
        reloc_map: dict[int, int] = {}
        for off in range(rd_off, rd_off + rd_sz, 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.elf, off)
            if (r_info & 0xFFFFFFFF) == 8:
                reloc_map[r_offset] = r_addend

        for loc in self.evidence["panic_locations"]:
            va = int(loc["va"], 16)
            self.assertIn(va, reloc_map, f"missing R_X86_64_RELATIVE at {loc['va']}")
            str_va = reloc_map[va]
            do = va - drr_va
            ln, line, col = struct.unpack_from("<QII", self.elf, drr_off + do + 8)
            path_bytes = _read_va(self.elf, self.secs, ".rodata", str_va, ln)
            self.assertEqual(path_bytes.decode("utf-8"), loc["file"])
            self.assertEqual(line, loc["line"])
            self.assertEqual(col, loc["col"])

    def test_negative_controls(self) -> None:
        # 1. Corrupting HYPE 4-byte literal must fail
        hype_bytes = _read_va(self.elf, self.secs, ".text", 0x3BF56DA, 6)
        self.assertNotEqual(hype_bytes, bytes.fromhex("813848595044"))
        # 2. Corrupting Hyperliquidity address must fail
        hl_bytes = _read_va(self.elf, self.secs, ".rodata", 0x7BAEA9, 20)
        self.assertNotEqual(hl_bytes, b"\x00" * 20)
        # 3. Corrupting an FDE end VA must fail
        self.assertNotEqual(self.fdes[0x3BF5120], 0x3BF5FB4)
        # 4. Corrupting dust threshold f64 bits must fail
        dust_bits = struct.unpack("<Q", _read_va(self.elf, self.secs, ".rodata", 0x459130, 8))[0]
        self.assertNotEqual(dust_bits, 0x3EB0C6F7A0B5ED8E)


if __name__ == "__main__":
    unittest.main()
