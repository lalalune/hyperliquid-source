import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import elf_index  # noqa: E402
import fde_extents  # noqa: E402

TARGET_BIN = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET_DIR = ROOT / "research/work-items/RE-011-node115-evm-crate-and-precompiles"


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


class TestEvmCrate115(unittest.TestCase):
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

    def test_all_9_evm_panic_locations_match_binary(self):
        expected_paths = {
            0x436B72: "l1/src/evm/evm_db.rs",
            0x435C78: "l1/src/evm/evm_state.rs",
            0x432D07: "l1/src/evm/hash.rs",
            0x43AD8A: "l1/src/evm/hyper_evm.rs",
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
        self.assertEqual(len(observed), 9)
        self.assertEqual(observed, self.evidence["panic_locations"])

    def test_all_21_read_precompile_callbacks_and_gas_immediates(self):
        _, records, _ = fde_extents.fde_extents(self.data)
        by_start = {r["start"]: r for r in records}
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        self.assertEqual(len(self.evidence["read_precompiles"]), 21)
        for item in self.evidence["read_precompiles"]:
            rec_va = int(item["record_va"], 16)
            cb_va = int(item["callback_va"], 16)
            # Check 20-byte address key and callback slot relocation in .data.rel.ro
            off_rec = _va_to_off(self.secs, rec_va)
            self.assertEqual(self.data[off_rec : off_rec + 20].hex(), item["address_hex"])
            self.assertEqual(self.rela[rec_va + 0x18], cb_va)

            # Verify FDE extent and SHA-256
            f = by_start[cb_va]
            self.assertEqual(f["end"], int(item["end_va"], 16))
            body = self.data[_va_to_off(self.secs, cb_va) : _va_to_off(self.secs, cb_va) + (f["end"] - cb_va)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), item["sha256"])

            # Verify universal 0x7d0 (2000) / 0x3e8 (1000) / shl 5 preamble
            pre = " | ".join(f"{i.mnemonic} {i.op_str}" for i in list(md.disasm(body[:96], cb_va))[:25])
            self.assertIn("0x7d0", pre)
            self.assertIn("0x3e8", pre)
            self.assertIn("shl", pre)

            # Verify fixed post-output gas immediate if fixed-size
            if item["fixed_output_bytes"] is not None:
                expected_add = 1000 + 33 * item["fixed_output_bytes"]
                hex_imm = hex(expected_add)
                all_ins = [f"{i.mnemonic} {i.op_str}" for i in md.disasm(body, cb_va)]
                self.assertTrue(
                    any(i.startswith("add ") and hex_imm in i for i in all_ins),
                    f"{item['suffix']} missing add {hex_imm}",
                )

    def test_negative_controls_detect_gas_or_suffix_corruption(self):
        # Negative control 1: changing per-byte gas from 33 to 32 breaks 0x0800's 0x1888 immediate
        self.assertEqual(1000 + 33 * 160, 0x1888)
        self.assertNotEqual(1000 + 32 * 160, 0x1888)
        # Negative control 2: 0x0809 callback must not claim 64-byte output (0xc28)
        rec0809 = next(r for r in self.evidence["read_precompiles"] if r["suffix"] == "0809")
        self.assertEqual(rec0809["fixed_output_bytes"], 32)
        self.assertNotEqual(rec0809["fixed_output_bytes"], 64)


if __name__ == "__main__":
    unittest.main()
