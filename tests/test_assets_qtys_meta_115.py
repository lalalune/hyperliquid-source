"""Verify node #115 assets/qtys/pdi/meta binary anchors and integrated Rust crate."""
import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-004-node115-assets-qtys-meta"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def _load_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    secs = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        end = data.index(b"\x00", shstr_off + sh_name)
        name = data[shstr_off + sh_name : end].decode("utf-8", "replace")
        secs[name] = (sh_addr, sh_offset, sh_size)
    return secs


def _va_to_off(secs: dict[str, tuple[int, int, int]], va: int) -> int:
    for _name, (sa, so, sz) in secs.items():
        if sa != 0 and sa <= va < sa + sz:
            return so + (va - sa)
    raise KeyError(f"VA 0x{va:x} not mapped in ELF sections")


class AssetsQtysMetaNode115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BINARY.read_bytes()
        cls.sha256 = hashlib.sha256(cls.data).hexdigest()
        cls.secs = _load_elf_sections(cls.data)
        cls.evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))

    def test_target_digest_matches_pinned_node115(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)

    def test_pow10_f64_rodata_table_at_0x5ed748(self) -> None:
        off = _va_to_off(self.secs, 0x5ED748)
        vals = struct.unpack_from("<20d", self.data, off)
        expected = tuple(float(10**i) for i in range(20))
        self.assertEqual(vals, expected)
        self.assertEqual(
            hashlib.sha256(self.data[off : off + 160]).hexdigest(),
            self.evidence["pow10_f64_sha256"],
        )

    def test_pdi_perp_meta_and_spot_meta_instruction_anchors(self) -> None:
        # pdi.rs:32 (0x22b31f0): mov $0x2710, %eax (b8 10 27 00 00)
        off_pdi = _va_to_off(self.secs, 0x22B31F0)
        self.assertEqual(self.data[off_pdi : off_pdi + 5], bytes.fromhex("b810270000"))

        # perp_meta.rs (0x22e4846): imul $0x2710, %rdx, %rax (48 69 c2 10 27 00 00)
        off_pm_mul = _va_to_off(self.secs, 0x22E4846)
        self.assertEqual(
            self.data[off_pm_mul : off_pm_mul + 7], bytes.fromhex("4869c210270000")
        )
        # perp_meta.rs (0x22e4888): cmp $0x7, %rax (48 83 f8 07)
        off_pm_cmp = _va_to_off(self.secs, 0x22E4888)
        self.assertEqual(self.data[off_pm_cmp : off_pm_cmp + 4], bytes.fromhex("4883f807"))
        # perp_meta.rs (0x22e48a8): mov $0x6, %esi (be 06 00 00 00)
        off_pm_max = _va_to_off(self.secs, 0x22E48A8)
        self.assertEqual(self.data[off_pm_max : off_pm_max + 5], bytes.fromhex("be06000000"))

        # spot_meta.rs (0x22f5e3f..0x22f5e51): movzbl 0x49(...), sub 0x48(...)
        off_sm_wei = _va_to_off(self.secs, 0x22F5E3F)
        self.assertEqual(self.data[off_sm_wei : off_sm_wei + 6], bytes.fromhex("410fb6440349"))
        off_sm_sub = _va_to_off(self.secs, 0x22F5E4C)
        self.assertEqual(self.data[off_sm_sub : off_sm_sub + 5], bytes.fromhex("412a443348"))

    def test_qtys_saturation_and_evidence_digests(self) -> None:
        # impl_ntl.rs:682 (0x294bd45): mov $0xffffffffffffffff, %rax
        off_ntl_sat = _va_to_off(self.secs, 0x294BD45)
        self.assertEqual(
            self.data[off_ntl_sat : off_ntl_sat + 7], bytes.fromhex("48c7c0ffffffff")
        )
        # impl_ntl.rs:683 (0x2a83a8a): sar $0x3f, %rax; movabs $0x8000000000000000, %rcx
        off_ntli_sat = _va_to_off(self.secs, 0x2A83A8A)
        self.assertEqual(
            self.data[off_ntli_sat : off_ntli_sat + 14],
            bytes.fromhex("48c1f83f48b90000000000000080"),
        )
        for rec in self.evidence["anchored_slices"]:
            va = int(rec["va"], 16)
            size = rec["size"]
            off = _va_to_off(self.secs, va)
            got = hashlib.sha256(self.data[off : off + size]).hexdigest()
            self.assertEqual(got, rec["sha256"], f"digest mismatch at {rec['va']}")

    def test_packet_manifest_integrity(self) -> None:
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
