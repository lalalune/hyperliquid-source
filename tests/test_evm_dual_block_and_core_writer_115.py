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
PACKET_DIR = ROOT / "research" / "work-items" / "RE-011-node115-evm-dual-block-and-core-writer"
EVIDENCE_PATH = PACKET_DIR / "evidence.json"


class TestEvmDualBlockAndCoreWriter115(unittest.TestCase):
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

    def test_target_sha256_and_dual_block_gas_immediates(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)

        # Verify exact mov eax, 30_000_000 / mov ecx, 3_000_000 / cmovne rcx, rax at both sites:
        # b8 80 c3 c9 01  b9 c0 c6 2d 00  48 0f 45 c8
        expected_seq = bytes.fromhex("b880c3c901b9c0c62d00480f45c8")
        for site_va in (0x433DD30, 0x2A1E37B):
            off = self.va_to_off(site_va)
            self.assertEqual(self.data[off : off + len(expected_seq)], expected_seq, hex(site_va))

        # Verify exact f64 bucket-guard pairs:
        s_a, s_b = struct.unpack_from("<dd", self.data, self.va_to_off(0x4554F0))
        b_a, b_b = struct.unpack_from("<dd", self.data, self.va_to_off(0x453520))
        self.assertEqual((s_a, s_b), (0.03, 0.07))
        self.assertEqual((b_a, b_b), (0.05, 0.05))

    def test_three_system_contracts_descriptors_and_sha256(self) -> None:
        contracts = self.evidence["system_contracts"]
        self.assertEqual(len(contracts), 3)
        for c in contracts:
            addr_va = int(c["addr_rodata_va"], 16)
            addr_bytes = bytes.fromhex(c["address_hex"])
            self.assertEqual(self.data[self.va_to_off(addr_va) : self.va_to_off(addr_va) + 20], addr_bytes)

            desc_va = int(c["descriptor_va"], 16)
            ptr = self.relocs[desc_va + 8]
            ln = struct.unpack_from("<Q", self.data, self.va_to_off(desc_va) + 16)[0]
            self.assertEqual(ptr, int(c["bytecode_va"], 16))
            self.assertEqual(ln, c["bytecode_len"])
            bc = self.data[self.va_to_off(ptr) : self.va_to_off(ptr) + ln]
            self.assertEqual(hashlib.sha256(bc).hexdigest(), c["bytecode_sha256"])

    def test_core_writer_v1_jump_table_and_17_action_slots(self) -> None:
        jt_va = 0x79E340
        jt_off = self.va_to_off(jt_va)
        fde = self.fdes[0x38BF120]
        self.assertEqual(fde["end"], 0x38C044C)

        # Pin `cmp r13b, 1` (41 80 fd 01) at 0x38bf508 and `cmp rbx, 0x10` (48 83 fb 10) at 0x38bf515
        self.assertEqual(self.data[self.va_to_off(0x38BF508) : self.va_to_off(0x38BF508) + 4], bytes.fromhex("4180fd01"))
        self.assertEqual(self.data[self.va_to_off(0x38BF515) : self.va_to_off(0x38BF515) + 4], bytes.fromhex("4883fb10"))

        slots = self.evidence["core_writer_actions"]
        self.assertEqual(len(slots), 17)
        for idx, slot in enumerate(slots):
            aid = idx + 1
            self.assertEqual(slot["action_id"], aid)
            rel = struct.unpack_from("<i", self.data, jt_off + idx * 4)[0]
            tgt = jt_va + rel
            self.assertEqual(tgt, int(slot["arm_va"], 16))
            self.assertGreaterEqual(tgt, fde["start"])
            self.assertLess(tgt, fde["end"])
            if aid == 14:
                self.assertFalse(slot["active"])
                self.assertEqual(tgt, 0x38C0323)
            else:
                self.assertTrue(slot["active"])
                self.assertNotEqual(tgt, 0x38C0323)

    def test_key_fdes_and_event_signatures(self) -> None:
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
