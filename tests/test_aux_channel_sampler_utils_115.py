"""Binary-backed verification for RE-012 node #115 aux, channel, group_and_seq_sampler, and utils."""

import hashlib
import json
import math
import pathlib
import struct
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
BIN_PATH = REPO / "artifacts" / "node" / "115" / "hl-node"
PACKET_DIR = REPO / "research" / "work-items" / "RE-012-node115-aux-channel-sampler-utils"
RECORDS_PATH = PACKET_DIR / "records.json"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"

EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
RELA_DYN_OFF = 0x6BE8
RELA_DYN_SIZE = 0x163CC8
DATA_REL_RO_DELTA = 0x2000


class TestAuxChannelSamplerUtils115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BIN_PATH.read_bytes()
        cls.records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        cls.relas: dict[int, int] = {}
        for off in range(RELA_DYN_OFF, RELA_DYN_OFF + RELA_DYN_SIZE, 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", cls.data, off)
            if (r_info & 0xFFFFFFFF) == 8:
                cls.relas[r_offset] = r_addend

    def test_pinned_binary_sha256(self) -> None:
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), EXPECTED_SHA256)
        self.assertEqual(self.records["target"]["sha256"], EXPECTED_SHA256)

    def test_rodata_anchors_and_constants(self) -> None:
        for name, entry in self.records["rodata_anchors"].items():
            va = int(entry["va"], 16)
            expected = entry["text"].encode("utf-8")
            self.assertEqual(self.data[va : va + len(expected)], expected, f"mismatch for {name}")

        ns_const = self.records["constants"]["nanos_per_sec"]
        self.assertEqual(struct.unpack_from("<d", self.data, int(ns_const["va"], 16))[0], ns_const["value"])

        inf_const = self.records["constants"]["pos_inf_sentinel"]
        inf_va = int(inf_const["va"], 16)
        self.assertEqual(struct.unpack_from("<Q", self.data, inf_va)[0], int(inf_const["value"], 16))
        self.assertTrue(math.isinf(struct.unpack_from("<d", self.data, inf_va)[0]))

    def test_location_structs_and_relocs(self) -> None:
        for loc in self.records["locations"]:
            va = int(loc["va"], 16)
            expected_file_va = int(loc["file_va"], 16)
            self.assertEqual(self.relas.get(va), expected_file_va, f"missing reloc at {hex(va)}")
            file_off = va - DATA_REL_RO_DELTA
            length, line, col = struct.unpack_from("<QII", self.data, file_off + 8)
            self.assertEqual(self.data[expected_file_va : expected_file_va + length].decode("utf-8"), loc["file"])
            self.assertEqual(line, loc["line"])
            self.assertEqual(col, loc["col"])

    def test_negative_controls_and_fdes(self) -> None:
        va = int(self.records["rodata_anchors"]["batch_vs_stream_conflict"]["va"], 16)
        self.assertNotEqual(self.data[va + 1 : va + 1 + 10], b"cannot set")
        for fde in self.records["fdes"]:
            self.assertEqual(int(fde["end_va"], 16) - int(fde["start_va"], 16), fde["size_bytes"])

    def test_manifest_sha256_integrity(self) -> None:
        lines = [ln.strip() for ln in MANIFEST_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2)
        seen = set()
        for line in lines:
            expected_hash, rel_name = line.split("  ", 1)
            seen.add(rel_name)
            actual = hashlib.sha256((PACKET_DIR / rel_name).read_bytes()).hexdigest()
            self.assertEqual(actual, expected_hash)
        self.assertEqual(seen, {"README.md", "records.json"})


if __name__ == "__main__":
    unittest.main()
