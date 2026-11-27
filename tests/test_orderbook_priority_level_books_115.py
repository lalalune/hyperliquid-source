import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = ROOT / "research" / "work-items" / "RE-006-node115-priority-level-and-books"
EVIDENCE_PATH = PACKET_DIR / "evidence.json"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"
BINARY_PATH = ROOT / "artifacts" / "node" / "115" / "hl-node"


class TestOrderbookPriorityLevelBooks115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        cls.binary = BINARY_PATH.read_bytes()

    def test_manifest_and_target_sha256(self) -> None:
        self.assertEqual(
            hashlib.sha256(self.binary).hexdigest(),
            self.evidence["target_sha256"],
        )
        entries = {}
        for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            digest, rel = line.split(None, 1)
            entries[rel] = digest
        self.assertEqual(set(entries), {"README.md", "evidence.json"})
        for rel, expected in entries.items():
            actual = hashlib.sha256((PACKET_DIR / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, f"manifest mismatch for {rel}")

    def test_fdes_locations_and_priority_comparator_match_node115(self) -> None:
        sec = self.evidence["sections"]
        text_va = int(sec["text_va"], 16)
        text_off = int(sec["text_file_offset"], 16)
        ro_va = int(sec["rodata_va"], 16)
        ro_off = int(sec["rodata_file_offset"], 16)
        drr_va = int(sec["data_rel_ro_va"], 16)
        drr_off = int(sec["data_rel_ro_file_offset"], 16)
        rela_off = int(sec["rela_dyn_file_offset"], 16)
        rela_sz = int(sec["rela_dyn_size"], 16)

        total_bytes = 0
        for fde in self.evidence["fdes"]:
            start = int(fde["start"], 16)
            end = int(fde["end"], 16)
            size = end - start
            self.assertEqual(size, fde["size"], fde["name"])
            total_bytes += size
            raw = self.binary[text_off + (start - text_va) : text_off + (end - text_va)]
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                fde["sha256"],
                f"FDE digest mismatch for {fde['name']}",
            )
        self.assertEqual(len(self.evidence["fdes"]), 7)
        self.assertEqual(total_bytes, 3876)

        # Verify all 16 relocated panic Location records
        rela = {}
        for o in range(rela_off, rela_off + rela_sz, 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.binary, o)
            if (r_info & 0xFFFFFFFF) == 8:
                rela[r_offset] = r_addend

        for loc in self.evidence["panic_locations"]:
            loc_va = int(loc["loc_va"], 16)
            str_va = int(loc["str_va"], 16)
            self.assertEqual(rela.get(loc_va), str_va, f"rela mismatch at {loc['loc_va']}")
            foff = drr_off + (loc_va - drr_va)
            ln, line, col = struct.unpack_from("<QII", self.binary, foff + 8)
            self.assertEqual(line, loc["line"])
            self.assertEqual(col, loc["col"])
            text = self.binary[ro_off + (str_va - ro_va) : ro_off + (str_va - ro_va) + ln].decode(
                "ascii"
            )
            self.assertEqual(text, loc["file"])

        # Negative control: flipping a byte in 0x5911890 must fail SHA-256 verification
        prio_fde = next(f for f in self.evidence["fdes"] if f["name"] == "book_insert_resting_priority")
        s = int(prio_fde["start"], 16)
        e = int(prio_fde["end"], 16)
        mutated = bytearray(self.binary[text_off + (s - text_va) : text_off + (e - text_va)])
        mutated[0] ^= 0xFF
        self.assertNotEqual(hashlib.sha256(bytes(mutated)).hexdigest(), prio_fde["sha256"])


if __name__ == "__main__":
    unittest.main()
