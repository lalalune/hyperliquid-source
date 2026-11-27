import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import elf_index  # noqa: E402
import fde_extents  # noqa: E402

TARGET_ELF = ROOT / "artifacts" / "node" / "115" / "hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET_DIR = ROOT / "research" / "work-items" / "bridge-contracts-and-state-layout-115"
EVIDENCE_PATH = PACKET_DIR / "evidence.json"


class TestBridgeContractsAndState115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = TARGET_ELF.read_bytes()
        cls.sha256 = hashlib.sha256(cls.data).hexdigest()
        cls.secs = {s["name"]: s for s in elf_index.sections(cls.data)}
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

        rela = cls.secs[".rela.dyn"]
        cls.relocs = {}
        for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", cls.data, off)
            if (r_info & 0xFFFFFFFF) == 8:
                cls.relocs[r_offset] = r_addend

        _, fdes, _ = fde_extents.fde_extents(cls.data)
        cls.fdes = {r["start"]: r for r in fdes}

    def va_to_off(self, va: int) -> int:
        for s in self.secs.values():
            if s["address"] <= va < s["address"] + s["size"]:
                return s["offset"] + (va - s["address"])
        raise AssertionError(f"VA {hex(va)} not mapped")

    def test_target_sha256_and_embedded_arbitrum_contracts(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)

        contracts = self.evidence["contracts"]
        self.assertEqual(len(contracts), 4)
        for c in contracts:
            k_va = int(c["key_va"], 16)
            a_va = int(c["address_va"], 16)
            self.assertEqual(
                self.data[self.va_to_off(k_va) : self.va_to_off(k_va) + len(c["key"])],
                c["key"].encode("ascii"),
            )
            self.assertEqual(
                self.data[self.va_to_off(a_va) : self.va_to_off(a_va) + len(c["address_hex"])],
                c["address_hex"].encode("ascii"),
            )

    def test_all_6_bridge2_panic_locations_and_balance_guard_bytes(self) -> None:
        b2_path = b"l1/src/bridge2.rs"
        b2_va = 0x43E33A
        self.assertEqual(self.data[self.va_to_off(b2_va) : self.va_to_off(b2_va) + len(b2_path)], b2_path)

        locs = self.evidence["bridge2_panic_locations"]
        self.assertEqual(len(locs), 6)
        for item in locs:
            va = int(item["location_va"], 16)
            self.assertEqual(self.relocs[va], b2_va)
            ln, line, col = struct.unpack_from("<QII", self.data, self.va_to_off(va) + 8)
            self.assertEqual(ln, len(b2_path))
            self.assertEqual((line, col), (item["line"], item["col"]))

        # Pin `cmp word [rsp+0xb0], 0x1a2` (0x44d8448) and `sub rax, r14; jb ...` (0x44d845b)
        msg = b"bridge2 withdrawal balance bug"
        self.assertEqual(self.data[self.va_to_off(0x7D30E2) : self.va_to_off(0x7D30E2) + len(msg)], msg)
        self.assertEqual(self.data[self.va_to_off(0x44D845B) : self.va_to_off(0x44D845B) + 3], bytes.fromhex("4c29f0"))

    def test_key_fdes_and_rodata_anchors(self) -> None:
        for item in self.evidence["rodata_anchors"]:
            va = int(item["va"], 16)
            expected = item["ascii"].encode("ascii")
            self.assertEqual(self.data[self.va_to_off(va) : self.va_to_off(va) + len(expected)], expected)
        for item in self.evidence["key_fdes"]:
            s = int(item["start"], 16)
            e = int(item["end"], 16)
            self.assertEqual(self.fdes[s]["end"], e, item["role"])


if __name__ == "__main__":
    unittest.main()
