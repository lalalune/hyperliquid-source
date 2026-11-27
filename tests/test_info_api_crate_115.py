import hashlib
import json
import re
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
PACKET_DIR = ROOT / "research" / "work-items" / "RE-015-node115-info-api-crate"
EVIDENCE_PATH = PACKET_DIR / "evidence.json"
REQUEST_RS = ROOT / "src" / "info-api" / "src" / "request.rs"


class TestInfoApiCrate115(unittest.TestCase):
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
        raise AssertionError(f"VA {hex(va)} not in any section")

    def test_target_sha256_and_source_inventory(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)

        total_locs = 0
        for item in self.evidence["source_paths"]:
            va = int(item["rodata_va"], 16)
            path = item["path"]
            off = self.va_to_off(va)
            self.assertEqual(self.data[off : off + len(path)], path.encode("ascii"))

            loc_count = 0
            for r_off, r_add in self.relocs.items():
                if r_add == va:
                    off_l = self.va_to_off(r_off)
                    ln = struct.unpack_from("<Q", self.data, off_l + 8)[0]
                    if ln == len(path):
                        loc_count += 1
            self.assertEqual(loc_count, item["panic_location_count"], path)
            total_locs += loc_count

        self.assertEqual(len(self.evidence["source_paths"]), 7)
        self.assertEqual(total_locs, 43)

    def test_55_info_request_variants_and_serializer_jump_table(self) -> None:
        table_va = 0x643A9E0
        jt_va = 0x5F45D0
        jt_off = self.va_to_off(jt_va)
        fde = self.fdes[0x273BF30]
        self.assertEqual(fde["end"], 0x273EBC0)

        variants = self.evidence["info_request_variants"]
        self.assertEqual(len(variants), 55)

        rust_src = REQUEST_RS.read_text(encoding="utf-8")
        info_impl = rust_src.split("impl InfoRequestKind", 1)[1].split("impl FileSnapshotKind", 1)[0]
        rust_names = re.findall(r'Self::\w+\s*=>\s*"([A-Za-z0-9_]+)"', info_impl)
        self.assertEqual(len(rust_names), 55)

        for idx, entry in enumerate(variants):
            self.assertEqual(entry["discriminant"], idx)
            slot_va = table_va + idx * 16
            ptr = self.relocs[slot_va]
            ln = struct.unpack_from("<Q", self.data, self.va_to_off(slot_va) + 8)[0]
            wire = self.data[self.va_to_off(ptr) : self.va_to_off(ptr) + ln].decode("ascii")
            self.assertEqual(wire, entry["name"])
            self.assertEqual(wire, rust_names[idx])

            rel = struct.unpack_from("<i", self.data, jt_off + idx * 4)[0]
            arm_va = jt_va + rel
            self.assertEqual(arm_va, int(entry["serializer_arm_va"], 16))
            self.assertGreaterEqual(arm_va, fde["start"])
            self.assertLess(arm_va, fde["end"])
            self.assertEqual(entry["serialized_map_entries"], 1 + len(entry["payload_fields"]))

    def test_file_snapshot_sub_enum_and_rodata_anchors(self) -> None:
        fs_va = 0x643AD50
        expected_fs = ["referrerStates", "l4Snapshots"]
        for i, name in enumerate(expected_fs):
            slot = fs_va + i * 16
            ptr = self.relocs[slot]
            ln = struct.unpack_from("<Q", self.data, self.va_to_off(slot) + 8)[0]
            got = self.data[self.va_to_off(ptr) : self.va_to_off(ptr) + ln].decode("ascii")
            self.assertEqual(got, name)

        for anchor in self.evidence["rodata_anchors"]:
            va = int(anchor["va"], 16)
            expected = anchor["ascii"].encode("ascii")
            off = self.va_to_off(va)
            self.assertEqual(self.data[off : off + len(expected)], expected, anchor["label"])

    def test_key_fdes_match_eh_frame(self) -> None:
        for item in self.evidence["key_fdes"]:
            start = int(item["start"], 16)
            end = int(item["end"], 16)
            self.assertIn(start, self.fdes, item["role"])
            self.assertEqual(self.fdes[start]["end"], end, item["role"])


if __name__ == "__main__":
    unittest.main()
