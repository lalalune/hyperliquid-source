"""Verify node #115 exchange orchestration source map and stake_requirement gate (0x2c59480, 0x2c58c70, 0x294ceb0)."""
import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-010-node115-exchange-orchestration-map"
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
        if sh_type == 4:  # SHT_RELA
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
    jt = evidence["stake_requirement_jump_table"]
    jt_base = int(jt["base_va"], 16)
    for arm in jt["arms"]:
        rel = struct.unpack_from("<i", data, _va_to_off(secs, jt_base + arm["arm"] * 4))[0]
        if rel != arm["rel32"] or jt_base + rel != int(arm["target"], 16):
            raise AssertionError(f"jump table arm {arm['arm']} mismatch")
    st = evidence["stake_requirement_chain_table"]
    st_base = int(st["base_va"], 16)
    for row in st["variants"]:
        rel = struct.unpack_from("<i", data, _va_to_off(secs, st_base + row["variant"] * 4))[0]
        tbl_va = st_base + rel
        if rel != row["rel32"] or tbl_va != int(row["table_va"], 16):
            raise AssertionError(f"stake table rel32 mismatch for variant {row['variant']}")
        got_vals = list(struct.unpack_from("<4Q", data, _va_to_off(secs, tbl_va)))
        if got_vals != row["chains_u64"]:
            raise AssertionError(f"stake table values mismatch for variant {row['variant']}")
    for loc in evidence["exchange_source_locations"]:
        va = int(loc["va"], 16)
        off = _va_to_off(secs, va)
        ptr = relas.get(va, struct.unpack_from("<Q", data, off)[0])
        length, line, col = struct.unpack_from("<QII", data, off + 8)
        poff = _va_to_off(secs, ptr)
        path = data[poff : poff + length].decode("utf-8", "replace")
        if (path, line, col) != (loc["path"], loc["line"], loc["col"]):
            raise AssertionError(f"exchange source location {loc['va']} mismatch")


class ExchangeOrchestrationMapNode115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BINARY.read_bytes()
        cls.sha256 = hashlib.sha256(cls.data).hexdigest()
        cls.secs, cls.relas = _load_elf_tables(cls.data)
        cls.evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))

    def test_target_digest_fdes_tables_and_15_source_files(self) -> None:
        self.assertEqual(self.sha256, TARGET_SHA256)
        _verify_evidence(self.data, self.secs, self.relas, self.evidence)
        self.assertEqual(len(self.evidence["anchored_slices"]), 9)
        self.assertEqual(len(self.evidence["stake_requirement_jump_table"]["arms"]), 4)
        self.assertEqual(len(self.evidence["stake_requirement_chain_table"]["variants"]), 4)
        distinct_files = {loc["path"] for loc in self.evidence["exchange_source_locations"]}
        self.assertEqual(len(distinct_files), 15)

    def test_outcome_strings_and_instruction_anchors(self) -> None:
        od = self.evidence["outcome_deployer_strings"]
        for key_va, key_txt in [("not_deployer_va", "not_deployer"), ("not_active_va", "not_active")]:
            va = int(od[key_va], 16)
            want = od[key_txt].encode("ascii")
            off = _va_to_off(self.secs, va)
            self.assertEqual(self.data[off : off + len(want)], want)
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

        # Negative control 1: corrupt stake-table Mainnet amount.
        bad_stake = json.loads(json.dumps(self.evidence))
        bad_stake["stake_requirement_chain_table"]["variants"][0]["chains_u64"][3] += 1
        with self.assertRaises(AssertionError):
            _verify_evidence(self.data, self.secs, self.relas, bad_stake)

        # Negative control 2: corrupt jump-table arm target.
        bad_jt = json.loads(json.dumps(self.evidence))
        bad_jt["stake_requirement_jump_table"]["arms"][2]["target"] = "0x2c58c70"
        with self.assertRaises(AssertionError):
            _verify_evidence(self.data, self.secs, self.relas, bad_jt)

        # Negative control 3: corrupt anchored slice digest.
        bad_slice = json.loads(json.dumps(self.evidence))
        bad_slice["anchored_slices"][0]["sha256"] = "f" * 64
        with self.assertRaises(AssertionError):
            _verify_evidence(self.data, self.secs, self.relas, bad_slice)


if __name__ == "__main__":
    unittest.main()
