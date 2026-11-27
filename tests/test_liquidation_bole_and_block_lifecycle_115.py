"""Verify node #115 backstop liquidation allocator (0x44dcf80), bole liquidation order (0x2c80670), and begin_block/end_block lifecycle."""
import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-007-node115-liquidation-bole-and-block-lifecycle"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def _load_elf_tables(data: bytes) -> tuple[dict[str, tuple[int, int, int]], dict[int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    secs: dict[str, tuple[int, int, int]] = {}
    relas: dict[int, int] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _f, sh_addr, sh_offset, sh_size, _l, _i, _a, sh_entsize = (
            struct.unpack_from("<IIQQQQIIQQ", data, off)
        )
        end = data.index(b"\x00", shstr_off + sh_name)
        secs[data[shstr_off + sh_name : end].decode("utf-8", "replace")] = (
            sh_addr,
            sh_offset,
            sh_size,
        )
        if sh_type == 4:
            for j in range(0, sh_size, sh_entsize):
                r_offset, _r_info, r_addend = struct.unpack_from("<QQq", data, sh_offset + j)
                relas[r_offset] = r_addend
    return secs, relas


def _va_to_off(secs: dict[str, tuple[int, int, int]], va: int) -> int:
    for sa, so, sz in secs.values():
        if sa != 0 and sa <= va < sa + sz:
            return so + (va - sa)
    raise KeyError(f"VA 0x{va:x} not mapped")


def _verify_evidence(
    data: bytes,
    secs: dict[str, tuple[int, int, int]],
    relas: dict[int, int],
    evidence: dict,
) -> None:
    if evidence["target_sha256"] != TARGET_SHA256:
        raise AssertionError("target_sha256 mismatch")
    for rec in evidence["anchored_slices"]:
        va = int(rec["va"], 16)
        off = _va_to_off(secs, va)
        got = hashlib.sha256(data[off : off + rec["size"]]).hexdigest()
        if got != rec["sha256"]:
            raise AssertionError(f"slice {rec['name']} digest mismatch")
    prev_lea = 0
    for phase in evidence["begin_block_phases"]:
        lea_va = int(phase["lea_va"], 16)
        if lea_va <= prev_lea:
            raise AssertionError(f"begin_block phases out of VA order at {phase['name']}")
        prev_lea = lea_va
        lea_off = _va_to_off(secs, lea_va)
        disp = struct.unpack_from("<i", data, lea_off + 3)[0]
        dst = lea_va + 7 + disp
        str_va = int(phase["string_va"], 16)
        if dst != str_va:
            raise AssertionError(f"LEA at {phase['lea_va']} resolves to {hex(dst)} != {phase['string_va']}")
        str_off = _va_to_off(secs, str_va)
        got_name = data[str_off : str_off + phase["string_len"]].decode("ascii")
        if got_name != phase["name"]:
            raise AssertionError(f"phase string mismatch: {got_name} != {phase['name']}")
        g_off = _va_to_off(secs, int(phase["bucket_guard_va"], 16))
        if list(struct.unpack_from("<2d", data, g_off)) != phase["bucket_guard_f64"]:
            raise AssertionError(f"bucket guard mismatch for {phase['name']}")
    eb = evidence["end_block_action_router_call"]
    c_va = int(eb["call_va"], 16)
    c_off = _va_to_off(secs, c_va)
    if data[c_off] != 0xE8:
        raise AssertionError("expected call rel32 at end_block_action_router_call")
    rel = struct.unpack_from("<i", data, c_off + 1)[0]
    if c_va + 5 + rel != int(eb["target_va"], 16):
        raise AssertionError("end_block action router target mismatch")
    for loc in evidence["panic_locations"]:
        va = int(loc["va"], 16)
        off = _va_to_off(secs, va)
        ptr = relas.get(va, struct.unpack_from("<Q", data, off)[0])
        length, line, col = struct.unpack_from("<QII", data, off + 8)
        poff = _va_to_off(secs, ptr)
        path = data[poff : poff + length].decode("utf-8", "replace")
        if (path, line, col) != (loc["path"], loc["line"], loc["col"]):
            raise AssertionError(f"panic Location {loc['va']} mismatch")


class LiquidationBoleAndBlockLifecycleNode115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BINARY.read_bytes()
        cls.sha256 = hashlib.sha256(cls.data).hexdigest()
        cls.secs, cls.relas = _load_elf_tables(cls.data)
        cls.evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))

    def test_target_digest_fdes_7_begin_block_phases_and_end_block_router_call(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        _verify_evidence(self.data, self.secs, self.relas, self.evidence)
        self.assertEqual(len(self.evidence["anchored_slices"]), 5)
        self.assertEqual(len(self.evidence["begin_block_phases"]), 7)
        self.assertEqual(len(self.evidence["panic_locations"]), 5)

    def test_rodata_constants_and_instruction_anchors(self) -> None:
        ro = self.evidence["rodata_constants"]
        self.assertEqual(ro["bole_liquidator_addr_hex"], "bb" * 20)
        off20 = _va_to_off(self.secs, int(ro["bole_liquidator_addr_va"], 16))
        self.assertEqual(self.data[off20 : off20 + 20], b"\xbb" * 20)
        off16 = _va_to_off(self.secs, int(ro["bole_liquidator_16b_va"], 16))
        self.assertEqual(self.data[off16 : off16 + 16], b"\xbb" * 16)
        err_off = _va_to_off(self.secs, int(ro["liquidator_cross_margin_err_va"], 16))
        want_err = ro["liquidator_cross_margin_err"].encode("ascii")
        self.assertEqual(self.data[err_off : err_off + len(want_err)], want_err)
        for name, (va_hex, want_hex) in self.evidence["instruction_anchors"].items():
            va = int(va_hex, 16)
            want = bytes.fromhex(want_hex)
            off = _va_to_off(self.secs, va)
            self.assertEqual(self.data[off : off + len(want)], want, msg=name)

    def test_manifest_and_negative_controls(self) -> None:
        manifest = PACKET / "MANIFEST.sha256"
        lines = [ln.strip() for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2)
        for line in lines:
            want, rel = line.split("  ", 1)
            got = hashlib.sha256((PACKET / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want)

        # Negative control 1: swap phase order.
        bad_order = json.loads(json.dumps(self.evidence))
        bad_order["begin_block_phases"][0], bad_order["begin_block_phases"][1] = (
            bad_order["begin_block_phases"][1],
            bad_order["begin_block_phases"][0],
        )
        with self.assertRaises(AssertionError):
            _verify_evidence(self.data, self.secs, self.relas, bad_order)

        # Negative control 2: corrupt end_block router target.
        bad_call = json.loads(json.dumps(self.evidence))
        bad_call["end_block_action_router_call"]["target_va"] = "0x2bda7c1"
        with self.assertRaises(AssertionError):
            _verify_evidence(self.data, self.secs, self.relas, bad_call)

        # Negative control 3: corrupt anchored slice digest.
        bad_slice = json.loads(json.dumps(self.evidence))
        bad_slice["anchored_slices"][0]["sha256"] = "0" * 64
        with self.assertRaises(AssertionError):
            _verify_evidence(self.data, self.secs, self.relas, bad_slice)


if __name__ == "__main__":
    unittest.main()
