import bisect
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("consensus_wire", ROOT / "tools/consensus_wire.py")
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)
BIN = ROOT / "artifacts/node/94/hl-node"
PACKET = ROOT / "research/work-items/RE-008-consensus-wire-state"
OUTPUT_SHA256 = "c3be6de771cf5856b5e36560f3ac93d13168f78e7991870b7b870fef4ad3dd3a"
DATA = BIN.read_bytes() if BIN.exists() else None


def tool(name):
    return shutil.which(name)


@unittest.skipIf(DATA is None, "pinned binary not present")
class ConsensusWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = cw.build(DATA)
        cls.text = cw.render(cls.r)
        cls.elf = cw.Elf(DATA)

    def mutated(self, va, new):
        b = bytearray(DATA)
        o = self.elf.off(va)
        b[o:o + len(new)] = new
        b = bytes(b)
        return cw.build(b, expected_sha256=hashlib.sha256(b).hexdigest())

    def test_pinned_counts_and_hashes(self):
        r = self.r
        self.assertEqual(r["fde_count"], 121299)
        self.assertEqual(r["first_party_location_count"], 1186)
        self.assertEqual(r["scoped_location_counts"], {
            "node/src/consensus/signed.rs": 1,
            "node/src/consensus/state.rs": 11,
            "node/src/consensus/types.rs": 1,
        })
        self.assertEqual(sum(r["scoped_location_counts"].values()), 13)
        self.assertEqual(sum(1 for f in r["functions"] if f["scoped"]), 8)
        self.assertEqual(len(r["tags"]), 24)
        self.assertEqual(r["reconstruction_status_counts"], {
            "fde_start_no_own_location": 13,
            "fde_start_with_own_location": 7,
            "inside_fde": 12,
        })
        self.assertEqual(hashlib.sha256(self.text).hexdigest(), OUTPUT_SHA256)

    def test_packet_matches_tool(self):
        self.assertEqual((PACKET / "consensus-wire.json").read_bytes(), self.text)

    def test_seed_fde_status(self):
        by = {s["name"]: s for s in self.r["seeds"]}
        self.assertTrue(by["signed_verify_signed_block"]["fde_start"])
        self.assertEqual(by["signed_verify_signed_block"]["own_scoped_files"],
                         {"node/src/consensus/signed.rs": [188]})
        self.assertTrue(by["signed_verify_qc"]["fde_start"])
        self.assertEqual(by["signed_verify_qc"]["own_scoped_files"],
                         {"node/src/consensus/types.rs": [70]})
        self.assertTrue(by["state_new"]["fde_start"])
        self.assertTrue(by["state_register_client_block"]["fde_start"])
        for name in ("types_Timeout_ser_a", "types_Tc", "types_Block_a", "types_Signed"):
            self.assertFalse(by[name]["fde_start"])

    def test_signature_map_cross_edges(self):
        edges = {(e["from"], e["to"], e["kind"]) for e in self.r["signature_map"]["cross_verifier_edges"]}
        self.assertEqual(edges, {
            ("verify_signed_block", 0x4758d70, "rel32"),
            ("verify_signed_block", 0x47594f0, "rel32"),
            ("verify_signed_timeout", 0x4758d70, "rel32"),
            ("verify_tc", 0x454aa10, "rel32"),
        })
        self.assertEqual(self.r["signature_map"]["proposer_mismatch_template_owner"], [0x47b01b0])
        q = self.r["signature_map"]["quorum_diagnostic_template_owners"]
        self.assertEqual(q["Qc does not have quorum"], [0x4775de0])
        self.assertEqual(q["Tc does not have quorum"], [0x4775de0])
        self.assertEqual(q["Failed to verify qc signature"], [0x4775de0])

    def test_quorum_math_sites(self):
        q = self.r["quorum"]
        self.assertEqual(q["function"], 0x4ad90d0)
        self.assertEqual(q["instruction_starts"], {
            "mov_edx_3": 0x4ad9612,
            "mov_rax_r10": 0x4ad9617,
            "mul_rdx": 0x4ad961a,
            "add_rcx_rcx": 0x4ad961d,
            "cmp_rcx_rax": 0x4ad9620,
            "sbb_rsi_rdx": 0x4ad9623,
            "setb_al": 0x4ad9626,
        })
        self.assertEqual(q["verify_qc_call"], {
            "site": 0x47590ca, "kind": "slot", "slot": 0x5776ae8, "to": 0x4ad90d0,
        })
        # Exact opcodes
        self.assertEqual(self.elf.read(0x4ad9612, 5), bytes.fromhex("ba03000000"))
        self.assertEqual(self.elf.read(0x4ad9617, 3), bytes.fromhex("4c89d0"))
        self.assertEqual(self.elf.read(0x4ad961a, 3), bytes.fromhex("48f7e2"))
        self.assertEqual(self.elf.read(0x4ad961d, 3), bytes.fromhex("4801c9"))
        self.assertEqual(self.elf.read(0x4ad9620, 3), bytes.fromhex("4839c1"))
        self.assertEqual(self.elf.read(0x4ad9623, 3), bytes.fromhex("4819d6"))
        self.assertEqual(self.elf.read(0x4ad9626, 3), bytes.fromhex("0f92c0"))

    def test_hashseed_invariance(self):
        outs = set()
        for seed in ("0", "7", "99"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = subprocess.run([sys.executable, "-B", str(ROOT / "tools/consensus_wire.py")],
                               env=env, capture_output=True, check=True)
            outs.add(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, {OUTPUT_SHA256})

    def test_wrong_binary_hash_rejected(self):
        with self.assertRaises(cw.EvidenceError):
            cw.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_location_line_mutation_changes_output(self):
        loc = next(l for l in self.r["scoped_locations"]
                   if l["file"] == "node/src/consensus/state.rs")
        r = self.mutated(loc["slot"] + 16, struct.pack("<I", loc["line"] + 1))
        got = next(l for l in r["scoped_locations"] if l["slot"] == loc["slot"])
        self.assertEqual(got["line"], loc["line"] + 1)

    def test_location_len_mutation_drops_record(self):
        loc = next(l for l in self.r["scoped_locations"]
                   if l["file"] == "node/src/consensus/signed.rs")
        r = self.mutated(loc["slot"] + 8, struct.pack("<Q", 0))
        self.assertNotIn(loc["slot"], [l["slot"] for l in r["scoped_locations"]])
        self.assertEqual(r["scoped_location_counts"].get("node/src/consensus/signed.rs", 0), 0)

    def test_lea_retarget_drops_tag_owner(self):
        tag = next(x for x in self.r["tags"] if x["text"] == "QcNoQuorum")
        site = next(s for a in tag["anchors"] for s in a["lea_sites"])
        disp = struct.unpack("<i", self.elf.read(site + 3, 4))[0]
        before = len(tag["functions"])
        r = self.mutated(site + 3, struct.pack("<i", disp + 0x100))
        got = next(x for x in r["tags"] if x["text"] == "QcNoQuorum")
        self.assertEqual(len(got["functions"]), before - 1)

    def test_quorum_imm3_mutation_rejected(self):
        with self.assertRaises(cw.EvidenceError):
            self.mutated(0x4ad9612, bytes.fromhex("ba04000000"))  # mov edx, 4

    def test_quorum_setb_mutation_rejected(self):
        with self.assertRaises(cw.EvidenceError):
            self.mutated(0x4ad9626, bytes.fromhex("0f93c0"))  # setae al

    def test_quorum_slot_reloc_tamper_rejected(self):
        with self.assertRaises(cw.EvidenceError):
            # Flip addend of the RELATIVE reloc targeting the quorum function.
            # Easier path: corrupt the call displacement so slot mismatches pin.
            self.mutated(0x47590ca + 2, struct.pack("<i", 0))

    def test_cross_edge_rel32_mutation_drops_edge(self):
        edge = next(e for e in self.r["signature_map"]["cross_verifier_edges"]
                    if e["from"] == "verify_signed_block" and e["to"] == 0x4758d70)
        # nop the call (e8 xx xx xx xx -> 90 90 90 90 90)
        r = self.mutated(edge["site"], b"\x90" * 5)
        left = {(e["from"], e["to"]) for e in r["signature_map"]["cross_verifier_edges"]}
        self.assertNotIn(("verify_signed_block", 0x4758d70), left)

    def test_fde_end_exclusive_and_seed_off_by_one(self):
        starts, ends = cw.fde_index(self.elf)
        j = bisect.bisect_left(starts, 0x47b01b0)
        self.assertEqual(starts[j], 0x47b01b0)
        e = ends[j]
        self.assertEqual(cw.containing(starts, ends, e - 1), (0x47b01b0, e))
        self.assertNotEqual(cw.containing(starts, ends, e), (0x47b01b0, e))
        for v in (0x47b01af, 0x47b01b1):
            self.assertFalse(cw.is_fde_start(starts, v))

    def test_template_anchor_is_exact(self):
        leas = cw.lea_targets(self.elf)
        for x in self.r["tags"]:
            for a in x["anchors"]:
                if a["lea_sites"]:
                    self.assertIn(a["anchor"], leas)
                    self.assertNotIn(a["anchor"] - 1, leas)
                    self.assertNotIn(a["anchor"] + 1, leas)
                if x["kind"] == "template":
                    o = self.elf.off(a["anchor"])
                    self.assertEqual(DATA[o - 1], 0)

    def test_negative_control_literal(self):
        relocs = cw.relative_relocs(self.elf)
        leas = cw.lea_targets(self.elf)
        self.assertEqual(cw.literal_anchors(self.elf, "exact", "NoSuchConsensusTagXYZ", leas, relocs), [])
        # Substring of a real tag must not match as exact occurrence start with lea
        # (VerifySignature is a substring of SignableContentVerifySignature — confirm
        # our inventory does not treat it as its own tag.)
        texts = {t["text"] for t in self.r["tags"]}
        self.assertNotIn("VerifySignature", texts)

    def test_non_elf_rejected(self):
        with self.assertRaises(cw.EvidenceError):
            cw.Elf(b"\0" * 64)

    def test_seed_edit_changes_status(self):
        with tempfile.TemporaryDirectory() as d:
            ref = Path(d)
            for f in cw.REF_FILES:
                (ref / f).parent.mkdir(parents=True, exist_ok=True)
                (ref / f).write_bytes((ROOT / cw.REF_DIR / f).read_bytes())
            p = ref / "node/consensus/signed.rs"
            p.write_text(p.read_text().replace("0x47B01B0", "0x47B01B1"))
            r = cw.build(DATA, ref_root=ref)
        st = {c["va"]: c["status"] for c in r["reconstruction_addresses"]}
        self.assertEqual(st[0x47B01B1], "inside_fde")
        self.assertNotIn(0x47B01B0, st)

    @unittest.skipIf(tool("readelf") is None, "readelf missing")
    def test_readelf_fde_bounds(self):
        out = subprocess.run(["readelf", "-wf", str(BIN)], capture_output=True, text=True, check=True).stdout
        pairs = sorted({(int(a, 16), int(b, 16))
                        for a, b in re.findall(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out)})
        starts, ends = cw.fde_index(self.elf)
        self.assertEqual(pairs, sorted(zip(starts, ends)))

    @unittest.skipIf(tool("readelf") is None, "readelf missing")
    def test_readelf_location_slots(self):
        out = subprocess.run(["readelf", "-rW", str(BIN)], capture_output=True, text=True, check=True).stdout
        rel = {int(m.group(1), 16): int(m.group(2), 16)
               for m in re.finditer(
                   r"^([0-9a-f]{16})\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", out, re.M)}
        for l in self.r["scoped_locations"]:
            self.assertIn(l["slot"], rel)

    @unittest.skipIf(tool("objdump") is None, "objdump missing")
    def test_objdump_tag_leas(self):
        for x in self.r["tags"]:
            for a in x["anchors"]:
                for s in a["lea_sites"][:1]:  # one site per anchor is enough
                    out = subprocess.run(
                        ["objdump", "-d", "--no-show-raw-insn",
                         f"--start-address={s:#x}", f"--stop-address={s + 7:#x}", str(BIN)],
                        capture_output=True, text=True, check=True).stdout
                    self.assertRegex(
                        out,
                        rf"{s:x}:\s+lea\s+-?0x[0-9a-f]+\(%rip\),%r\w+\s+# {a['anchor']:x}")

    @unittest.skipIf(tool("objdump") is None, "objdump missing")
    def test_objdump_quorum_compare(self):
        out = subprocess.run(
            ["objdump", "-d", "--start-address=0x4ad960b", "--stop-address=0x4ad9629", str(BIN)],
            capture_output=True, text=True, check=True).stdout
        self.assertIn("ba 03 00 00 00", out)  # mov $0x3,%edx
        self.assertIn("48 f7 e2", out)        # mul %rdx
        self.assertIn("48 01 c9", out)        # add %rcx,%rcx
        self.assertIn("0f 92 c0", out)        # setb %al



class MainErrorTests(unittest.TestCase):
    def test_main_reports_missing_binary(self):
        self.assertEqual(cw.main(['--binary', '/tmp/definitely-missing-hl.bin']), 2)


if __name__ == "__main__":
    unittest.main()
