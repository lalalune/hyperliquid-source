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
PACKET_DIR = ROOT / "research/work-items/RE-011-node115-evm-rpc-crate"


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


class TestEvmRpcCrate115(unittest.TestCase):
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

    def test_all_6_source_files_and_57_panic_locations(self):
        expected_paths = {
            0x4349EB: "evm_rpc/src/evm_rpc.rs",
            0x44801D: "evm_rpc/src/evm_store.rs",
            0x44C811: "evm_rpc/src/evm_write_forwarder.rs",
            0x44F487: "evm_rpc/src/expensive_call_limiter.rs",
            0x444DAE: "evm_rpc/src/method_router.rs",
            0x44AC21: "evm_rpc/src/reth_rpc_helpers_copied.rs",
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
        self.assertEqual(len(observed), 57)
        self.assertEqual(observed, self.evidence["panic_locations"])

    def test_all_29_method_literals_and_fdes(self):
        self.assertEqual(len(self.evidence["methods"]), 29)
        for m in self.evidence["methods"]:
            va = int(m["rodata_va"], 16)
            raw = m["name"].encode("ascii")
            off = _va_to_off(self.secs, va)
            self.assertEqual(self.data[off : off + len(raw)], raw)

        for lit in self.evidence["rodata_literals"]:
            va = int(lit["va"], 16)
            raw = lit["text"].encode("ascii")
            off = _va_to_off(self.secs, va)
            self.assertEqual(self.data[off : off + len(raw)], raw)

        _, records, _ = fde_extents.fde_extents(self.data)
        by_start = {r["start"]: r for r in records}
        for item in self.evidence["fdes"]:
            st = int(item["start_va"], 16)
            en = int(item["end_va"], 16)
            self.assertEqual(by_start[st]["end"], en)
            body = self.data[_va_to_off(self.secs, st) : _va_to_off(self.secs, st) + (en - st)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), item["sha256"])

    def test_negative_controls_detect_method_drift(self):
        names = [m["name"] for m in self.evidence["methods"]]
        self.assertIn("eth_usingBigBlocks", names)
        self.assertIn("eth_bigBlockGasPrice", names)
        self.assertNotIn("eth_nonexistentMethod", names)
        off = _va_to_off(self.secs, 0x453CF0)
        self.assertEqual(self.data[off : off + 16], b"Method not found")
        self.assertNotEqual(self.data[off : off + 16], b"method not found")


if __name__ == "__main__":
    unittest.main()
