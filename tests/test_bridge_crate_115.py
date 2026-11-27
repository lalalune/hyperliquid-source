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

TARGET_BIN = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET_DIR = ROOT / "research/work-items/bridge-request-abi-all-tags-115"


def _va_to_off(secs, va):
    for sec in secs.values():
        if sec["address"] <= va < sec["address"] + sec["size"] and sec["type"] != 8:
            return sec["offset"] + (va - sec["address"])
    raise KeyError(f"VA 0x{va:x} not mapped")


def _build_rela_map(data, secs):
    rela = secs[".rela.dyn"]
    out = {}
    for pos in range(rela["offset"], rela["offset"] + rela["size"], 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, pos)
        if (r_info & 0xFFFFFFFF) == 8:
            out[r_offset] = r_addend
    return out


class TestBridgeCrate115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET_BIN.read_bytes()
        cls.digest = hashlib.sha256(cls.data).hexdigest()
        cls.secs = {s["name"]: s for s in elf_index.sections(cls.data)}
        cls.rela = _build_rela_map(cls.data, cls.secs)
        cls.evidence = json.loads((PACKET_DIR / "evidence.json").read_text(encoding="utf-8"))

    def test_target_digest_and_manifest(self):
        self.assertEqual(self.digest, TARGET_SHA256)
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)
        self.assertFalse(self.evidence["captured_code_executed"])
        for line in (PACKET_DIR / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            want, rel = line.split("  ", 1)
            got = hashlib.sha256((PACKET_DIR / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want, f"MANIFEST mismatch for {rel}")

    def test_bridge_panic_locations_match_binary(self):
        expected_paths = {
            0x43E33A: "l1/src/bridge2.rs",
            0x43E34C: "l1/src/bridge_request.rs",
        }
        observed = []
        for slot, addend in sorted(self.rela.items()):
            if addend in expected_paths:
                off = _va_to_off(self.secs, slot)
                slen, line, col = struct.unpack_from("<QII", self.data, off + 8)
                path = self.data[
                    _va_to_off(self.secs, addend) : _va_to_off(self.secs, addend) + slen
                ].decode("ascii")
                observed.append({"va": f"0x{slot:x}", "file": path, "line": line, "col": col})
        self.assertEqual(len(observed), 7)
        self.assertEqual(observed, self.evidence["panic_locations"])

    def test_bridge_request_8_tag_jump_table_and_labels(self):
        jt_va = 0x7D3708
        jt_off = _va_to_off(self.secs, jt_va)
        observed_arms = []
        for tag in range(8):
            rel = struct.unpack_from("<i", self.data, jt_off + tag * 4)[0]
            observed_arms.append({"tag": tag, "arm_va": f"0x{jt_va + rel:x}"})
        self.assertEqual(observed_arms, self.evidence["jump_table_0x7d3708"])

        for item in self.evidence["rodata_labels"]:
            va = int(item["va"], 16)
            text = item["text"].encode("ascii")
            off = _va_to_off(self.secs, va)
            self.assertEqual(self.data[off : off + len(text)], text)

        # Verify inline "unlock" literal in Tag 6 (0x4526a14..0x4526a20):
        # 0x4526a14: mov word ptr [rax+4], 0x6b63 ("ck")
        # 0x4526a1a: mov dword ptr [rax], 0x6f6c6e75 ("unlo")
        off_u = _va_to_off(self.secs, 0x4526A14)
        self.assertIn(b"ck", self.data[off_u : off_u + 8])
        self.assertIn(b"unlo", self.data[off_u + 6 : off_u + 14])

    def test_fde_extents_and_hashes(self):
        _, records, _ = fde_extents.fde_extents(self.data)
        by_start = {r["start"]: r for r in records}
        self.assertEqual(len(self.evidence["fdes"]), 12)
        for item in self.evidence["fdes"]:
            st = int(item["start_va"], 16)
            en = int(item["end_va"], 16)
            self.assertIn(st, by_start)
            self.assertEqual(by_start[st]["end"], en)
            body = self.data[_va_to_off(self.secs, st) : _va_to_off(self.secs, st) + (en - st)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), item["sha256"])

    def test_negative_controls_detect_corrupted_tag_or_label(self):
        jt_off = _va_to_off(self.secs, 0x7D3708)
        tag5_arm = 0x7D3708 + struct.unpack_from("<i", self.data, jt_off + 5 * 4)[0]
        self.assertEqual(tag5_arm, 0x45267ED)
        self.assertNotEqual(tag5_arm, 0x452695A)  # swapped Tag 5 / Tag 6 must differ
        off_lbl = _va_to_off(self.secs, 0x7D3BBC)
        self.assertEqual(self.data[off_lbl : off_lbl + 17], b"requestWithdrawal")
        self.assertNotEqual(self.data[off_lbl : off_lbl + 17], b"RequestWithdrawal")


if __name__ == "__main__":
    unittest.main()
