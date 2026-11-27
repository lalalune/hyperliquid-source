"""Verify node #115 reference oracle monitor (0x366f900), OracleKind (0x3db4e40), and 27-file Stream E2 source map."""
import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map"
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
    for loc in evidence["stream_e2_non_exchange_source_locations"]:
        va = int(loc["va"], 16)
        off = _va_to_off(secs, va)
        ptr = relas.get(va, struct.unpack_from("<Q", data, off)[0])
        length, line, col = struct.unpack_from("<QII", data, off + 8)
        poff = _va_to_off(secs, ptr)
        path = data[poff : poff + length].decode("utf-8", "replace")
        if (path, line, col) != (loc["path"], loc["line"], loc["col"]):
            raise AssertionError(f"source Location {loc['va']} mismatch")


class ClearinghouseOracleAndSourceMapNode115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BINARY.read_bytes()
        cls.sha256 = hashlib.sha256(cls.data).hexdigest()
        cls.secs, cls.relas = _load_elf_tables(cls.data)
        cls.evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))

    def test_target_digest_fdes_and_27_distinct_source_files(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        _verify_evidence(self.data, self.secs, self.relas, self.evidence)
        self.assertEqual(len(self.evidence["anchored_slices"]), 5)
        distinct_files = {
            loc["path"] for loc in self.evidence["stream_e2_non_exchange_source_locations"]
        }
        self.assertEqual(len(distinct_files), 27)

    def test_rodata_constants_and_instruction_anchors(self) -> None:
        ro = self.evidence["rodata_constants"]
        self.assertEqual(
            struct.unpack_from("<d", self.data, _va_to_off(self.secs, int(ro["neg_one_va"], 16)))[0],
            -1.0,
        )
        self.assertEqual(
            struct.unpack_from("<d", self.data, _va_to_off(self.secs, int(ro["nanos_per_sec_va"], 16)))[0],
            1_000_000_000.0,
        )
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

        # Negative control 1: corrupt FDE digest.
        bad_fde = json.loads(json.dumps(self.evidence))
        bad_fde["anchored_slices"][1]["sha256"] = "1" * 64
        with self.assertRaises(AssertionError):
            _verify_evidence(self.data, self.secs, self.relas, bad_fde)

        # Negative control 2: corrupt source path.
        bad_loc = json.loads(json.dumps(self.evidence))
        bad_loc["stream_e2_non_exchange_source_locations"][0]["path"] = "l1/src/fake.rs"
        with self.assertRaises(AssertionError):
            _verify_evidence(self.data, self.secs, self.relas, bad_loc)


if __name__ == "__main__":
    unittest.main()
