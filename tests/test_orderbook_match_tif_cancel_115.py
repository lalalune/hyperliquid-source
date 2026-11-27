"""Verify node #115 orderbook TIF jump table, crossing predicate, match step, and cancel lookup."""
import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-006-node115-match-tif-cancel"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def _load_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    secs = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _t, _f, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", data, off)
        end = data.index(b"\x00", shstr_off + sh_name)
        secs[data[shstr_off + sh_name : end].decode("utf-8", "replace")] = (
            sh_addr,
            sh_offset,
            sh_size,
        )
    return secs


def _va_to_off(secs: dict[str, tuple[int, int, int]], va: int) -> int:
    for sa, so, sz in secs.values():
        if sa != 0 and sa <= va < sa + sz:
            return so + (va - sa)
    raise KeyError(f"VA 0x{va:x} not mapped")


class OrderbookMatchTifCancelNode115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BINARY.read_bytes()
        cls.sha256 = hashlib.sha256(cls.data).hexdigest()
        cls.secs = _load_elf_sections(cls.data)
        cls.evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))

    def test_target_digest_matches_pinned_node115(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)

    def test_tif_jump_table_at_0x936ecc(self) -> None:
        tbl_va = 0x936ECC
        off = _va_to_off(self.secs, tbl_va)
        targets = [
            tbl_va + struct.unpack_from("<i", self.data, off + 4 * i)[0] for i in range(5)
        ]
        # 0 = Alo (0x59025c6), 1/3/4 = Ioc/FrontendMarket/LiquidationMarket (0x59025b0), 2 = Gtc (0x590261a)
        self.assertEqual(
            targets,
            [0x59025C6, 0x59025B0, 0x590261A, 0x59025B0, 0x59025B0],
        )
        # Max cap constant 10^15 (0x38d7ea4c68000) at 0x590264b
        off_cap = _va_to_off(self.secs, 0x590264B)
        self.assertEqual(
            self.data[off_cap : off_cap + 10], bytes.fromhex("48b80080c6a47e8d0300")
        )

    def test_match_step_self_trade_and_reduce_only_anchors(self) -> None:
        # 0x5911e9f: cmp $0xffff, %eax; je 0x5911eda (20-byte SIMD self-trade check)
        off_stp = _va_to_off(self.secs, 0x5911E9F)
        self.assertEqual(self.data[off_stp : off_stp + 7], bytes.fromhex("3dffff00007434"))
        # 0x5911eda: movb $0x2, 0x650(%rsp) (self-trade status tag = 2)
        off_tag2 = _va_to_off(self.secs, 0x5911EDA)
        self.assertEqual(
            self.data[off_tag2 : off_tag2 + 8], bytes.fromhex("c684245006000002")
        )
        # 0x5911f30: cmpb $0x0, 0xc0(%rbp) (resting reduce_only flag)
        off_ro = _va_to_off(self.secs, 0x5911F30)
        self.assertEqual(self.data[off_ro : off_ro + 7], bytes.fromhex("80bdc000000000"))

    def test_cancel_oid_hash_and_owner_check_anchors(self) -> None:
        # 0x23ce47a: movabs $0xf1357aea2e62a9c5, %rax; imul %rax, %rsi; rol $0x14, %rsi
        off_hash = _va_to_off(self.secs, 0x23CE47A)
        self.assertEqual(
            self.data[off_hash : off_hash + 18],
            bytes.fromhex("48b8c5a9622eea7a35f1480faff048c1c614"),
        )
        # 0x23ce4dd: cmpl $0x2, (%rax,%rcx,1) (vacant slab slot guard)
        off_vac = _va_to_off(self.secs, 0x23CE4DD)
        self.assertEqual(self.data[off_vac : off_vac + 4], bytes.fromhex("833c0802"))
        # 0x50bcc97: xor $0x1, %dl (opposite side flip)
        off_flip = _va_to_off(self.secs, 0x50BCC97)
        self.assertEqual(self.data[off_flip : off_flip + 3], bytes.fromhex("80f201"))

    def test_anchored_digests_and_manifest(self) -> None:
        for rec in self.evidence["anchored_slices"]:
            va = int(rec["va"], 16)
            off = _va_to_off(self.secs, va)
            got = hashlib.sha256(self.data[off : off + rec["size"]]).hexdigest()
            self.assertEqual(got, rec["sha256"], f"digest mismatch at {rec['va']}")

        manifest = PACKET / "MANIFEST.sha256"
        lines = [
            ln.strip()
            for ln in manifest.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        self.assertGreaterEqual(len(lines), 2)
        for line in lines:
            want, rel = line.split("  ", 1)
            got = hashlib.sha256((PACKET / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want, f"manifest mismatch for {rel}")


if __name__ == "__main__":
    unittest.main()
