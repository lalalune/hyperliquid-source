import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("state_hashers", ROOT / "tools/state_hashers.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)
sr = sh.sr
BIN = ROOT / "artifacts/node/94/hl-node"
PACKET = ROOT / "research/work-items/RE-009-storage-state-roots"
OUTPUT_SHA256 = "1e7fbe921766315fb37f5c72227b24ba8ceb07822ad950de570b4553480855fa"
DATA = BIN.read_bytes() if BIN.exists() else None
BLAKE3_SLOT = 0x57700C8
BLAKE3_FN = 0x14F93E0
SHA512_K0_SITE = 0x4EC4B2D  # imm64 of `48 b8` movabs at 0x4ec4b2b
STRING_FN = 0x506CB20  # std::string user; its raw 0x8082 byte match is not a constant
STRING_MOV_VA = 0x506D98B


def path(r, source, kinds):
    return next(p for p in r["paths"] if p["source"] == source and tuple(p["edge_kinds"]) == kinds)


@unittest.skipIf(DATA is None, "pinned binary not present")
class StateHashersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = sh.build(DATA)
        cls.text = sh.render(cls.r)
        cls.elf = sr.Elf(DATA)

    def rebuild(self, b):
        return sh.build(b, expected_sha256=hashlib.sha256(b).hexdigest())

    def patched(self, va, new):
        b = bytearray(DATA)
        o = self.elf.off(va)
        b[o:o + len(new)] = new
        return self.rebuild(bytes(b))

    def test_pinned_output(self):
        r = self.r
        self.assertEqual(hashlib.sha256(self.text).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "hashers.json").read_bytes(), self.text)
        self.assertEqual(r["hasher_count"], 29)
        self.assertEqual(r["hasher_with_first_party_location_count"], 0)
        self.assertEqual(r["edge_counts"], {"rel32_edges": 495523, "slot_edges": 345767, "vtable_edges": 21027})
        self.assertEqual(r["first_party_direct_hasher_caller_count"], 108)
        blake = [c["function"] for c in r["first_party_direct_hasher_callers"]
                 if any(x["to"] == BLAKE3_FN for x in c["calls"])]
        self.assertEqual(blake, [0x3269AE0, 0x37E5620])

    def test_chains(self):
        c = path(self.r, "0x3269ae0", sh.KINDS_DIRECT)
        self.assertEqual([(x["from"], x["kind"], x["site"], x["slot"], x["to"]) for x in c["chain"]],
                         [(0x3269AE0, "slot", 0x3269D96, BLAKE3_SLOT, BLAKE3_FN)])
        c = path(self.r, "all_scoped_db_state_functions", sh.KINDS_DIRECT)
        self.assertEqual([(x["from"], x["kind"], x["site"], x["slot"], x["to"]) for x in c["chain"]],
                         [(0x2208E60, "slot", 0x220925C, 0x57739F8, 0x394B410),
                          (0x394B410, "slot", 0x394B4DE, BLAKE3_SLOT, BLAKE3_FN)])
        for src in ("0x332d440", "0x32699c0"):
            for kinds, reached in ((sh.KINDS_DIRECT, None), (sh.KINDS_ALL, None)):
                p = path(self.r, src, kinds)
                self.assertTrue(p["exhausted"])
                self.assertIsNone(p["hit"])
                self.assertEqual(p["max_depth"], 14)
        self.assertEqual([path(self.r, s, k)["reached"] for s in ("0x332d440", "0x32699c0")
                          for k in (sh.KINDS_DIRECT, sh.KINDS_ALL)], [680, 783, 676, 778])

    def test_constants_absent_from_first_party(self):
        self.assertEqual(sum(len(c["first_party_functions"]) for c in self.r["constants"]), 0)
        iv0 = next(c for c in self.r["constants"] if c["constant"].startswith("u32_0x6a09e667"))
        self.assertEqual(iv0["functions"], [0x14FA7B0, 0x14FB530, 0x4E9A8A0])
        self.assertEqual(self.r["keccak_rc_tables"],
                         [{"table": 0x7D04C8, "lea_sites": [0x4F598F0], "functions": [0x4F59480]}])

    def test_u64_constants_require_movabs(self):
        consts = {c["constant"]: c for c in self.r["constants"]}
        k0 = consts["u64_0x428a2f98d728ae22_sha512_k0"]
        self.assertEqual((k0["sites"], k0["functions"]), ([SHA512_K0_SITE], [0x4EC4A40]))
        for name in ("u64_0x0000000000008082_keccak_rc1", "u64_0x800000000000808a_keccak_rc2"):
            self.assertEqual(consts[name]["text_hits"], 0)
        # 0x506d98b: 48 c7 82 80 00 00 00 00 00 00 00  mov QWORD PTR [rdx+0x80],0x0
        self.assertEqual(DATA[self.elf.off(STRING_MOV_VA):self.elf.off(STRING_MOV_VA) + 11],
                         bytes.fromhex("48c78280" + "00" * 7))
        self.assertNotIn(STRING_FN, [h["function"] for h in self.r["hashers"]])

    def test_movabs_prefix_mutations_remove_u64_reason(self):
        # 0x4ec4b2b: 48 b8 <imm64>. Break the opcode, then clear REX.W (40 b8 is mov eax,imm32).
        for va, byte in ((SHA512_K0_SITE - 1, b"\x90"), (SHA512_K0_SITE - 2, b"\x40")):
            with self.subTest(va=hex(va)):
                r = self.patched(va, byte)
                row = next(h for h in r["hashers"] if h["function"] == 0x4EC4A40)
                self.assertNotIn("const:u64_0x428a2f98d728ae22_sha512_k0", row["reasons"])

    def test_rc2_movabs_r15_is_detected(self):
        # movabs r15,0x800000000000808a (REX.WB, b8+7): RC[2] needs an imm64.
        r = self.patched(STRING_MOV_VA, bytes.fromhex("49bf8a80000000000080") + b"\x90")
        row = next(h for h in r["hashers"] if h["function"] == STRING_FN)
        self.assertEqual(row["reasons"], ["const:u64_0x800000000000808a_keccak_rc2"])

    def test_re005_encoders_not_linked(self):
        e = self.r["re005_encoders"]
        self.assertEqual(e["functions_calling_both"], [])
        self.assertTrue(all(x["reachable_hashers"] == [] for x in e["encoders"]))
        self.assertEqual(e["lt_hash_sources_reaching_encoders"],
                         {"0x32699c0": [], "0x3269ae0": [], "0x332d440": []})
        self.assertEqual((e["hasher_direct_caller_count"], e["encoder_direct_caller_count"]), (289, 90))

    def test_hashseed_invariance(self):
        outs = set()
        for seed in ("0", "7", "99"):
            p = subprocess.run([sys.executable, "-B", str(ROOT / "tools/state_hashers.py")],
                               env=dict(os.environ, PYTHONHASHSEED=seed), capture_output=True, check=True)
            outs.add(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, {OUTPUT_SHA256})

    # --- tamper / boundary ------------------------------------------------
    def test_wrong_binary_rejected(self):
        with self.assertRaises(sh.EvidenceError):
            sh.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_reloc_addend_off_by_one_breaks_chain(self):
        _a, off, size = self.elf.sections[".rela.dyn"]
        b = bytearray(DATA)
        for o in range(off, off + size, 24):
            if struct.unpack_from("<Q", b, o)[0] == BLAKE3_SLOT:
                struct.pack_into("<q", b, o + 16, BLAKE3_FN + 1)
                break
        else:
            self.fail("slot relocation not found")
        r = self.rebuild(bytes(b))
        p = path(r, "0x3269ae0", sh.KINDS_DIRECT)
        self.assertNotIn(BLAKE3_FN, [x["to"] for x in p["chain"]])
        self.assertNotIn(0x3269AE0, [c["function"] for c in r["first_party_direct_hasher_callers"]])

    def test_call_site_mutation_moves_chain(self):
        r = self.patched(0x3269D96, b"\x90" * 6)
        p = path(r, "0x3269ae0", sh.KINDS_DIRECT)
        self.assertEqual(p["chain"][0]["site"], 0x3269FB1)

    def test_constant_mutation_removes_reason(self):
        site = next(c for c in self.r["constants"] if c["constant"].startswith("u32_0x510e527f"))["sites"][0]
        r = self.patched(site, b"\0\0\0\0")
        row = next(h for h in r["hashers"] if h["function"] == 0x4E9A8A0)
        self.assertNotIn("const:u32_0x510e527f_blake3_iv4_sha256_h4", row["reasons"])

    def test_bad_encoder_list_rejected(self):
        old = sh.RE005_ENCODERS
        sh.RE005_ENCODERS = old[:-1] + (old[-1] + 1,)
        try:
            with self.assertRaises(sh.EvidenceError):
                sh.build(DATA)
        finally:
            sh.RE005_ENCODERS = old

    def test_hasher_boundaries(self):
        starts, ends = sr.fde_index(self.elf)
        for h in self.r["hashers"]:
            self.assertTrue(sr.is_fde_start(starts, h["function"]))
            self.assertFalse(sr.is_fde_start(starts, h["function"] + 1))
        self.assertEqual(sr.containing(starts, ends, 0x14FA004 - 1)[0], BLAKE3_FN)
        self.assertNotEqual((sr.containing(starts, ends, 0x14FA004) or (0,))[0], BLAKE3_FN)

    # --- external cross-checks ------------------------------------------
    @unittest.skipIf(shutil.which("readelf") is None, "readelf missing")
    def test_readelf_slots_and_fdes(self):
        rel = subprocess.run(["readelf", "-rW", str(BIN)], capture_output=True, text=True, check=True).stdout
        for slot, tgt in ((BLAKE3_SLOT, BLAKE3_FN), (0x57739F8, 0x394B410)):
            self.assertRegex(rel, rf"(?m)^{slot:016x}\s+0+8 R_X86_64_RELATIVE\s+{tgt:x}$")
        fr = subprocess.run(["readelf", "-wf", str(BIN)], capture_output=True, text=True, check=True).stdout
        for f, e in ((BLAKE3_FN, 0x14FA004), (0x394B410, 0x394B657)):
            self.assertIn(f"pc={f:016x}..{e:016x}", fr)

    @unittest.skipIf(shutil.which("objdump") is None, "objdump missing")
    def test_objdump_call_sites_from_function_start(self):
        starts, ends = sr.fde_index(self.elf)
        sites = [(0x3269AE0, s, BLAKE3_SLOT) for s in (0x3269D96, 0x3269FB1, 0x326A1BD)]
        sites += [(0x2208E60, 0x220925C, 0x57739F8), (0x394B410, 0x394B4DE, BLAKE3_SLOT),
                  (0x37E5620, 0x37E572B, BLAKE3_SLOT)]
        for f, s, slot in sites:
            e = ends[starts.index(f)]
            out = subprocess.run(["objdump", "-d", "-M", "intel", f"--start-address={f:#x}",
                                  f"--stop-address={e:#x}", str(BIN)], capture_output=True, text=True,
                                 check=True).stdout
            self.assertRegex(out, rf"(?m)^ +{s:x}:\s+ff 15 [0-9a-f ]+\s+call\s+QWORD PTR \[rip\+0x[0-9a-f]+\]\s+# {slot:x}")


if __name__ == "__main__":
    unittest.main()
