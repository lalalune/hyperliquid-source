"""Verify node #115 fees/vlm binary anchors (`0x2a8b0a0`, `0x56195a0`, `0x543dc50`, `0x36e1b10`, `0x46a6860`)."""
import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-004-node115-vlm-accounting"
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


class FeesVlmAccountingNode115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BINARY.read_bytes()
        cls.sha256 = hashlib.sha256(cls.data).hexdigest()
        cls.secs = _load_elf_sections(cls.data)
        cls.evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))

    def test_target_digest_matches_pinned_node115(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)

    def test_vlm_fold_and_fee_instruction_anchors(self) -> None:
        # 0x2a8b0cf: imul $0x510, %rax, %r13 (4c 69 e8 10 05 00 00)
        off_stride = _va_to_off(self.secs, 0x2A8B0CF)
        self.assertEqual(
            self.data[off_stride : off_stride + 7], bytes.fromhex("4c69e810050000")
        )
        # 0x2a8b1f8: add $0x3f0, %rdi (spot clearinghouse offset)
        off_spot = _va_to_off(self.secs, 0x2A8B1F8)
        self.assertEqual(
            self.data[off_spot : off_spot + 7], bytes.fromhex("4881c7f0030000")
        )
        # 0x36e1b46: ucomisd -0x8(%rdx), %xmm0 (66 0f 2e 42 f8)
        off_ucomi = _va_to_off(self.secs, 0x36E1B46)
        self.assertEqual(self.data[off_ucomi : off_ucomi + 5], bytes.fromhex("660f2e42f8"))
        # 0x46a6871: mov $0x64, %eax; mulq 0x60(%rsi) (b8 64 00 00 00 48 f7 66 60)
        off_x100 = _va_to_off(self.secs, 0x46A6871)
        self.assertEqual(
            self.data[off_x100 : off_x100 + 9], bytes.fromhex("b86400000048f76660")
        )

    def test_anchored_function_digests_and_manifest(self) -> None:
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
