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

TARGET_BIN = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET_DIR = ROOT / "research/work-items/RE-015-global-constants-crate-115"
AWS_NAME_RS = ROOT / "src/global-constants/src/aws_name.rs"


def _va_to_off(secs, va):
    for sec in secs.values():
        if sec["address"] <= va < sec["address"] + sec["size"] and sec["type"] != 8:
            return sec["offset"] + (va - sec["address"])
    raise KeyError(f"VA 0x{va:x} not mapped in file-backed section")


def _build_rela_map(data, secs):
    rela = secs[".rela.dyn"]
    out = {}
    for pos in range(rela["offset"], rela["offset"] + rela["size"], 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, pos)
        if (r_info & 0xFFFFFFFF) == 8:
            out[r_offset] = r_addend
    return out


def _read_name_table(data, secs, rela_map, base_va, count):
    names = []
    for i in range(count):
        slot = base_va + i * 16
        ptr = rela_map[slot]
        length = struct.unpack_from("<Q", data, _va_to_off(secs, slot + 8))[0]
        raw = data[_va_to_off(secs, ptr) : _va_to_off(secs, ptr) + length]
        names.append(raw.decode("ascii"))
    return names


class TestGlobalConstants115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET_BIN.read_bytes()
        cls.digest = hashlib.sha256(cls.data).hexdigest()
        cls.secs = {s["name"]: s for s in elf_index.sections(cls.data)}
        cls.rela = _build_rela_map(cls.data, cls.secs)
        cls.evidence = json.loads((PACKET_DIR / "evidence.json").read_text(encoding="utf-8"))

    def test_target_digest_and_manifest_integrity(self):
        self.assertEqual(self.digest, TARGET_SHA256)
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)
        self.assertFalse(self.evidence["captured_code_executed"])

        manifest_lines = [
            line.strip()
            for line in (PACKET_DIR / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertGreaterEqual(len(manifest_lines), 2)
        for line in manifest_lines:
            want, rel = line.split("  ", 1)
            got = hashlib.sha256((PACKET_DIR / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want, f"MANIFEST mismatch for {rel}")

    def test_panic_locations_match_binary(self):
        expected_targets = {
            0x44C851: "global_constants/src/aws_name.rs",
            0x445B63: "global_constants/src/static_config.rs",
        }
        observed = []
        for slot, addend in sorted(self.rela.items()):
            if addend in expected_targets:
                off = _va_to_off(self.secs, slot)
                slen, line, col = struct.unpack_from("<QII", self.data, off + 8)
                path = self.data[_va_to_off(self.secs, addend) : _va_to_off(self.secs, addend) + slen].decode("ascii")
                observed.append(
                    {"va": f"0x{slot:x}", "file": path, "line": line, "col": col}
                )
        self.assertEqual(len(observed), 5)
        self.assertEqual(observed, self.evidence["panic_locations"])

    def test_all_79_aws_names_match_binary_and_rust_enum(self):
        t1 = _read_name_table(self.data, self.secs, self.rela, 0x63F8788, 79)
        t2 = _read_name_table(self.data, self.secs, self.rela, 0x6410CE8, 79)
        self.assertEqual(t1, t2)
        self.assertEqual(t1, self.evidence["aws_names"])
        self.assertEqual(t1[13], "EaTx")
        self.assertEqual(t1[32], "SoloSandbox")
        self.assertEqual(t1[33], "NvTestnet")
        self.assertEqual(t1[37], "NvMainnet3")
        self.assertEqual(t1[39], "DummyNv")

        rust_src = AWS_NAME_RS.read_text(encoding="utf-8")
        rust_variants = re.findall(r"^\s+([A-Z][A-Za-z0-9]+)\s*=\s*(\d+),$", rust_src, re.M)
        self.assertEqual(len(rust_variants), 79)
        for idx, (name, disc) in enumerate(rust_variants):
            self.assertEqual(int(disc), idx)
            self.assertEqual(name, t1[idx])

    def test_rodata_4671d0_f64_table_and_got_exports(self):
        off = _va_to_off(self.secs, 0x4671D0)
        vals = list(struct.unpack_from("<79d", self.data, off))
        self.assertEqual(vals, self.evidence["rodata_4671d0_f64"])
        ones = [i for i, v in enumerate(vals) if v == 1.0]
        self.assertEqual(ones, [1, 2, 9, 10, 11, 12, 13, 15, 16, 18, 20, 22, 25, 26, 35, 36, 37, 38])
        self.assertEqual(sum(1 for v in vals if v == 5.0), 61)

        for entry in self.evidence["got_exports"]:
            slot = int(entry["slot_va"], 16)
            target = int(entry["target_va"], 16)
            self.assertEqual(self.rela[slot], target)

    def test_fde_extents_and_body_hashes(self):
        _, records, _ = fde_extents.fde_extents(self.data)
        by_start = {r["start"]: r for r in records}
        self.assertEqual(len(self.evidence["fdes"]), 41)
        for item in self.evidence["fdes"]:
            st = int(item["start_va"], 16)
            en = int(item["end_va"], 16)
            self.assertIn(st, by_start)
            self.assertEqual(by_start[st]["end"], en)
            body = self.data[_va_to_off(self.secs, st) : _va_to_off(self.secs, st) + (en - st)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), item["sha256"])

    def test_negative_controls_detect_drift(self):
        # Negative control 1: swapped #94 discriminant (NvTestnet at 32) must fail.
        t1 = _read_name_table(self.data, self.secs, self.rela, 0x63F8788, 79)
        self.assertNotEqual(t1[32], "NvTestnet")
        # Negative control 2: mutating a recorded f64 table entry breaks equality.
        mutated = list(self.evidence["rodata_4671d0_f64"])
        mutated[33] = 1.0
        off = _va_to_off(self.secs, 0x4671D0)
        self.assertNotEqual(list(struct.unpack_from("<79d", self.data, off)), mutated)


if __name__ == "__main__":
    unittest.main()
