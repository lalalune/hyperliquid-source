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
spec = importlib.util.spec_from_file_location("consensus_error_tags", ROOT / "tools/consensus_error_tags.py")
cet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cet)
sr = cet.sr
BIN = ROOT / "artifacts/node/94/hl-node"
PACKET = ROOT / "research/work-items/RE-008-consensus-error-tags-94"
MERGED_RE008 = ROOT / "research/work-items/RE-008-consensus-wire-state/consensus-wire.json"
OUTPUT_SHA256 = "98cb870229cc0c066c1112293bc5fb121b29bdde03e62ff923a54f9a4fe56cb0"
DATA = BIN.read_bytes() if BIN.exists() else None
TOOL = ROOT / "tools/consensus_error_tags.py"
RECORDED_OBJDUMP = "GNU objdump (GNU Binutils) 2.47.20260726"
NICHE = cet.NICHE


def gnu_tool(name):
    """Path of ``name`` if it is the GNU binutils build, else None (LLVM's
    objdump/readelf take different flags and print a different format)."""
    exe = shutil.which(name)
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    first = out.splitlines()[0] if out else ""
    return exe if first.startswith(f"GNU {name}") else None


OBJDUMP = gnu_tool("objdump")
READELF = gnu_tool("readelf")


def h(s):
    return int(s, 16)


@unittest.skipIf(DATA is None, "pinned binary not present")
class ConsensusErrorTagsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = cet.build(DATA)
        cls.text = cet.render(cls.r)
        cls.d = json.loads(cls.text)          # rendered form: addresses are hex strings
        cls.elf = sr.Elf(DATA)

    # -- helpers ----------------------------------------------------------- #
    def rebuild(self, b):
        """Rebuild under the mutated bytes' own sha and return the rendered dict."""
        return json.loads(cet.render(cet.build(b, expected_sha256=hashlib.sha256(b).hexdigest())))

    def patched(self, *edits):
        """Apply (va, expected old bytes, new bytes) edits; the old bytes are
        asserted first, so every control is pinned to the bytes it changes."""
        b = bytearray(DATA)
        for va, old, new in edits:
            o = self.elf.off(va)
            self.assertEqual(bytes(b[o:o + len(old)]), old, f"unexpected bytes at {va:#x}")
            b[o:o + len(new)] = new
        return bytes(b)

    def assertTamperRaises(self, pattern, *edits):
        with self.assertRaisesRegex(cet.EvidenceError, pattern):
            self.rebuild(self.patched(*edits))

    def census(self, d, fde):
        return next(c for c in d["census"] if c["fde"] == fde)

    def variants_at(self, d, fde, site):
        return {e["variant_if_same_enum"] for e in self.census(d, fde)["in_range_tag_stores"]
                if e["site"] == site}

    # -- pinned output ----------------------------------------------------- #
    def test_pinned_output_and_byte_equality(self):
        self.assertEqual(hashlib.sha256(self.text).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "consensus-error-tags.json").read_bytes(), self.text)

    def test_tag_table(self):
        d = self.d
        self.assertEqual(d["tag_count"], 42)
        self.assertEqual(len(d["tags"]), 42)
        self.assertTrue(d["name_table_three_way_agreement"])
        self.assertTrue(all(t["name_agrees_three_way"] for t in d["tags"]))
        names = {h(t["tag"]): (t["variant"], t["name_len"]) for t in d["tags"]}
        self.assertEqual(names[0x00], ("Hardfork", 8))
        self.assertEqual(names[0x01], ("SignableContentVerifySignature", 30))
        self.assertEqual(names[0x1C], ("ClientBlockMissingTx", 20))
        self.assertEqual(names[0x1D], ("CommitProofChildQc", 18))
        self.assertEqual(names[0x27], ("TxInvalidBroadcasterNonce", 25))
        self.assertEqual(names[0x28], ("MissingValidatorSetRound", 24))
        self.assertEqual((names[0x13][0], names[0x14][0]), ("RpcPeer", "NoClientBlocks"))
        shared = {h(t["tag"]) for t in d["tags"] if t["shared_name_ptr"]}
        self.assertEqual(shared, {0x00, 0x08, 0x0C, 0x1A, 0x29})
        self.assertEqual(d["tags"][0x03]["field_keys"], ["block_round", "last_commit_round"])

    def test_dispatch_rule(self):
        d = self.d
        rule = d["dispatch_rule"]
        self.assertTrue(rule["identical_across_copies"])
        self.assertEqual(rule["rcx_2pow63_bytes"], "48b90000000000000080")
        self.assertEqual(rule["select_bytes"], "4831c14885c0b827000000480f48c1")
        self.assertEqual(rule["tail_bytes"], "486304814801c8ffe0")
        self.assertEqual((rule["default_index"], rule["default_index_row"]), ("0x27", "TxInvalidBroadcasterNonce"))
        mons = d["formatter_monomorphs"]
        self.assertEqual([m["jump_table"] for m in mons], ["0x6f9c44", "0x6f2af0", "0x3e23e8"])
        self.assertEqual([m["dispatch"]["word0"] for m in mons], ["*rdi", "*rdi", "**rdi"])
        self.assertEqual([m["dispatch"]["rcx_2pow63"] for m in mons], ["0x4753d75", "0x44c448e", "0x244e401"])
        self.assertEqual([m["dispatch"]["cmovs"] for m in mons], ["0x4753d8a", "0x44c44a3", "0x244e416"])
        self.assertTrue(all(m["dispatch"]["core_contiguous"] for m in mons))
        self.assertEqual([m["name_sink_histogram"] for m in mons],
                         [{"call_rel32 0x49c6940": 42}, {"call_indirect": 23, "jmp_indirect": 19},
                          {"call_indirect": 23, "jmp_indirect": 19}])

    def test_table_bound(self):
        d = self.d
        self.assertEqual([m["in_fde_run"] for m in d["formatter_monomorphs"]], [47, 42, 42])
        self.assertEqual(d["table_bound"]["copies_whose_past_table_slot_leaves_fde"], ["0x244e3f0", "0x44c4480"])
        self.assertEqual(d["formatter_monomorphs"][0]["entry_past_table"],
                         {"index": "0x2a", "target": "0x4754af0", "in_fde": True, "aliases_tags": ["0x29"]})
        self.assertEqual(d["table_bound"]["past_table_niche"], "0x800000000000002a")
        self.assertEqual(d["table_bound"]["past_table_niche_movabs_in_fde_0x47b01b0"], ["0x47b01c9"])

    def test_variant_index_crosscheck(self):
        x = self.d["variant_index_crosscheck"]
        self.assertEqual((x["fde"], x["jump_table"], x["in_fde_run"]), ("0x4752890", "0x6f9b9c", 43))
        self.assertEqual((x["dispatch"]["word0"], x["dispatch"]["rcx_2pow63"], x["dispatch"]["rcx_2pow63_origin"]),
                         ("*rsi", "0x47528ae", "0x47528a1"))
        rows = x["explicit_index_calls"]
        self.assertEqual([r["tag"] for r in rows],
                         ["0x1", "0x6", "0x10", "0x13", "0x17", "0x1c", "0x20", "0x21", "0x25", "0x28", "0x29"])
        self.assertTrue(all(r["variant_index"] == r["tag"] and r["index_equals_tag"] for r in rows))
        self.assertEqual({(r["container"], r["container_len"]) for r in rows}, {("Error", 5)})
        r1c = next(r for r in rows if r["tag"] == "0x1c")
        self.assertEqual((r1c["call"], r1c["name_ptr"], r1c["name_len"]), ("0x475386a", "0x6fbb2d", 20))

    def test_census(self):
        m = self.d["metrics"]["census"]
        self.assertEqual((m["fdes"], m["niche_movabs_sites"], m["raw_pattern_hits"],
                          m["movabs_sites_resolved"], m["unresolved_site_count"]), (7, 55, 55, 55, 0))
        self.assertEqual((m["in_range_tag_store_records"], m["in_range_tag_store_addresses"],
                          m["in_range_distinct_tags"]), (31, 27, 14))
        self.assertEqual(m["in_range_records_by_dest_class"], {"entry_rdi_copy": 15, "rsp": 16})
        self.assertEqual((m["niche_0x00_store_records"], m["past_table_niche_store_records"],
                          m["out_of_range_niche_store_records"], m["narrow_store_records"],
                          m["narrow_comparison_records"]), (5, 7, 2, 0, 0))
        self.assertEqual(m["comparison_records_by_class"], {"niche_0x00": 5, "niche_0x03": 1, "niche_0x2a": 31})
        self.assertEqual(self.variants_at(self.d, "0x47b01b0", "0x47b03a1"),
                         {"BadBlockProposer", "BadBlockQcRound", "BadBlockTcRound"})
        vsb = self.census(self.d, "0x47b01b0")
        self.assertEqual(vsb["entry_rdi_copies"], ["rbx"])
        self.assertEqual({e["dest"]["base"] for e in vsb["in_range_tag_stores"]}, {"rbx"})
        self.assertEqual([c["label"] for c in self.d["census"]],
                         ["fde_0x47b01b0", "fde_0x4758d70", "fde_0x47594f0", "fde_0x454aa10",
                          "fde_0x4b31e70", "fde_0x44ab560", "fde_0x44adfa0"])
        self.assertEqual([c["lead_label"] for c in self.d["census"]],
                         ["verify_signed_block", "verify_qc", "verify_tc", "verify_signed_timeout",
                          None, None, "state_dispatch"])
        self.assertTrue(all("unverified lead" in c["lead_label_source"]
                            for c in self.d["census"] if c["lead_label"]))
        for c in self.d["census"]:
            for e in c["niche_0x00_stores"]:
                self.assertEqual(e["variant_if_error"], "Hardfork")
                self.assertNotIn("variant", e)

    def test_census_call_edges(self):
        edges = {(e["from"], e["site"], e["kind"], e["to"]) for e in self.d["census_call_edges"]}
        self.assertIn(("0x47b01b0", "0x47b01e3", "slot", "0x4b31e70"), edges)
        self.assertIn(("0x44adfa0", "0x44af5eb", "rel32", "0x44ab560"), edges)
        self.assertEqual(len(edges), 13)

    def test_binary_wide_denominator(self):
        w = {x["immediate"]: x for x in self.d["metrics"]["binary_wide_niche_movabs"]}
        self.assertEqual((w["0x8000000000000028"]["fdes"], w["0x8000000000000028"]["census_fde_count"]), (13, 3))
        self.assertEqual((w["0x800000000000002a"]["fdes"], w["0x800000000000002a"]["census_fde_count"]), (47, 3))

    def test_corrections(self):
        cor = self.d["corrections"]
        dt = cor["merged_re008_disputed_token"]
        self.assertFalse(dt["is_single_variant_in_binary"])
        self.assertEqual((dt["real_token_a"]["name"], dt["real_token_a"]["tag"], dt["real_token_a"]["len"]),
                         ("ClientBlockMissingTx", "0x1c", 20))
        self.assertEqual((dt["real_token_b"]["name"], dt["real_token_b"]["tag"], dt["real_token_b"]["len"]),
                         ("CommitProofChildQc", "0x1d", 18))
        self.assertEqual(len(dt["cross_token_evidence"]), 3)
        self.assertTrue(all(e["spans_two_tokens"] for e in dt["cross_token_evidence"]))
        self.assertEqual([(e["site"], e["len"]) for e in dt["merged_lea_sites"]],
                         [("0x244ed87", 20), ("0x44c4e77", 20), ("0x4753850", 20), ("0x475527e", 20)])
        self.assertEqual(dt["strings_of_token_len_written_by_any_arm"], 0)
        self.assertEqual((len(cor["in_binary_not_in_can1357"]), len(cor["in_can1357_not_in_binary"])), (21, 10))

    def test_merged_lea_sites_match_merged_packet(self):
        merged = json.loads(MERGED_RE008.read_text())
        sites = sorted({h(s) for t in merged["tags"] if t["text"] == cet.MERGED_RE008_DISPUTED_TOKEN
                        for a in t["anchors"] for s in a["lea_sites"]})
        self.assertEqual(tuple(sites), cet.MERGED_RE008_LEA_SITES)

    # -- negative controls ------------------------------------------------- #
    def test_wrong_binary_rejected(self):
        with self.assertRaisesRegex(cet.EvidenceError, "sha256"):
            cet.build(b"not an elf")
        with self.assertRaisesRegex(cet.EvidenceError, "sha256"):
            cet.build(DATA, expected_sha256="00" * 32)

    def test_truncated_input_fails_closed(self):
        for n in (0x40, 0x1000, 0x2000000, len(DATA) - 1000):
            b = DATA[:n]
            with self.subTest(n=n), self.assertRaisesRegex(cet.EvidenceError, "malformed input|truncated"):
                cet.build(b, expected_sha256=hashlib.sha256(b).hexdigest())

    def test_length_patch_breaks_three_way_agreement(self):
        # copy 0x4753d60 arm 0x1c: mov edx,0x14 at 0x4755285 -> 0x13.
        self.assertTamperRaises("disagree", (0x4755285, b"\xba\x14", b"\xba\x13"))

    def test_per_copy_string_patch_breaks_agreement(self):
        # last byte of 'ClientBlockMissingTx' in copy 0x4753d60's own pool.
        self.assertTamperRaises("disagree", (0x6FBB40, b"x", b"X"))

    def test_shared_string_patch_is_not_cross_checked(self):
        # boundary control: 'Hardfork' at 0x20a280 is one string all three
        # copies point to, so a patch changes the row without disagreement.
        r = self.rebuild(self.patched((0x20A286, b"rk", b"xk")))
        self.assertEqual(r["tags"][0]["variant"], "Hardfoxk")
        self.assertTrue(r["tags"][0]["shared_name_ptr"])

    def test_jump_table_nudge_breaks_agreement(self):
        # copy 0x244e3f0 (table 0x3e23e8): point entry 0x1c at entry 0x1d's arm.
        o = self.elf.off(0x3E23E8)
        e1c = DATA[o + 4 * 0x1C:o + 4 * 0x1C + 4]
        e1d = DATA[o + 4 * 0x1D:o + 4 * 0x1D + 4]
        self.assertTamperRaises("disagree", (0x3E23E8 + 4 * 0x1C, e1c, e1d))

    def test_jump_table_entry_out_of_fde_fails_closed(self):
        o = self.elf.off(0x6F9C44)
        self.assertTamperRaises("leaves FDE before the bound",
                                (0x6F9C44, DATA[o:o + 4], struct.pack("<i", 0x7FFFFFFF)))

    def test_dispatch_lea_displacement_mismatch(self):
        # copy 0x44c4480: lea rcx,[rip+disp] at 0x44c44aa now points 4 bytes on.
        o = self.elf.off(0x44C44AD)
        disp = struct.unpack("<i", DATA[o:o + 4])[0]
        self.assertTamperRaises(r"dispatch table 0x6f2af4 != pinned 0x6f2af0",
                                (0x44C44AD, DATA[o:o + 4], struct.pack("<i", disp + 4)))

    def test_dispatch_select_corruption_second_copy(self):
        cases = {
            "cmovs -> cmovns": (0x44C44A3, bytes.fromhex("480f48c1"), bytes.fromhex("480f49c1")),
            "mov eax,0x27 -> 0x26": (0x44C449E, bytes.fromhex("b827"), bytes.fromhex("b826")),
            "xor rcx,rax -> or": (0x44C4498, bytes.fromhex("4831c1"), bytes.fromhex("4809c1")),
            "test rax,rax -> test rcx,rcx": (0x244E40E, bytes.fromhex("4885c0"), bytes.fromhex("4885c9")),
        }
        for name, edit in cases.items():
            with self.subTest(name):
                self.assertTamperRaises("select bytes not found", edit)

    def test_dispatch_rcx_constant_corruption(self):
        # movabs rcx,0x8000000000000000 at 0x4753d75 -> 0x4000000000000000.
        self.assertTamperRaises(r"rcx != 2\^63", (0x4753D7E, b"\x80", b"\x40"))

    def test_dispatch_word0_provenance(self):
        # mov rax,[rdi] at 0x4753d72 -> mov rax,[rsi].
        self.assertTamperRaises(r"word0 provenance \*rsi != \*rdi",
                                (0x4753D72, bytes.fromhex("488b07"), bytes.fromhex("488b06")))

    def test_dispatch_tail_corruption_second_copy(self):
        cases = {
            "movsxd scale 4 -> 8": (0x44C44B1, bytes.fromhex("48630481"), bytes.fromhex("486304c1")),
            "add rax,rcx -> sub": (0x44C44B5, bytes.fromhex("4801c8"), bytes.fromhex("4829c8")),
            "jmp rax -> jmp rcx": (0x44C44B8, bytes.fromhex("ffe0"), bytes.fromhex("ffe1")),
        }
        for name, edit in cases.items():
            with self.subTest(name):
                self.assertTamperRaises("tail bytes", edit)

    def test_arm_walk_leaving_fde_fails_closed(self):
        # copy 0x244e3f0 arm 0x1c (0x244ed73): jmp rel32 to 0x244f300, past the FDE end 0x244f211.
        rel = 0x244F300 - (0x244ED73 + 5)
        self.assertTamperRaises(r"walk left the FDE",
                                (0x244ED73, bytes.fromhex("4983c608" "4c"), b"\xe9" + struct.pack("<i", rel)))

    def test_fde_lookup_requires_fde_start(self):
        t = cet.Target(DATA)
        self.assertEqual(t.fde(0x4753D60), (0x4753D60, 0x47564BF))
        with self.assertRaisesRegex(cet.EvidenceError, "is not an FDE start"):
            t.fde(0x4753D61)

    def test_census_unresolved_site_is_counted(self):
        # movabs r13 -> movabs r11 at 0x47b01c9: r11 is caller-saved and dies at
        # the call at 0x47b01e3, so this site reaches no store or compare.
        r = self.rebuild(self.patched((0x47B01C9, b"\x49\xbd", b"\x49\xbb")))
        c = self.census(r, "0x47b01b0")
        self.assertEqual((c["niche_movabs_count"], c["movabs_sites_resolved"]), (1, 0))
        self.assertEqual(c["in_range_tag_stores"], [])
        self.assertEqual(r["metrics"]["census"]["movabs_sites_resolved"], 54)

    def test_census_budget_overflow_is_recorded(self):
        t = cet.Target(DATA)
        lo, hi = t.fde(0x47B01B0)
        *_, unresolved = cet.census_site(t, lo, hi, 0x47B01C9, 13, NICHE + 0x2A, budget=2)
        self.assertTrue(unresolved)

    def test_census_narrow_store_is_separated(self):
        # 0x47b03a1 mov [rbx],r13 -> mov [rbx],r13d: a 32-bit store of the
        # tracked register is not a niche-word store.
        r = self.rebuild(self.patched((0x47B03A1, b"\x4c\x89\x2b", b"\x44\x89\x2b")))
        c = self.census(r, "0x47b01b0")
        self.assertEqual(c["in_range_tag_stores"], [])
        self.assertEqual({e["site"] for e in c["narrow_stores"]}, {"0x47b03a1"})
        self.assertEqual(r["metrics"]["census"]["narrow_store_records"], 4)

    def test_entry_rdi_copy_requires_live_rdi(self):
        # 0x47b01c3 mov r14,rsi -> mov rdi,rsi: rdi is overwritten before the
        # entry block's mov rbx,rdi, so rbx is no longer an rdi copy.
        r = self.rebuild(self.patched((0x47B01C3, b"\x49\x89\xf6", b"\x48\x89\xf7")))
        c = self.census(r, "0x47b01b0")
        self.assertEqual(c["entry_rdi_copies"], [])
        self.assertEqual({e["dest_class"] for e in c["in_range_tag_stores"]}, {"other"})

    def test_variant_index_name_mismatch_fails_closed(self):
        # fourth monomorph arm 0x1c: mov r9d,0x14 at 0x475385c -> 0x13.
        self.assertTamperRaises(r"fourth monomorph arm 0x1c writes 'ClientBlockMissingT'",
                                (0x475385C, b"\x41\xb9\x14", b"\x41\xb9\x13"))

    def test_census_delta_byte_dependence(self):
        # 0x47b039d: add r13,-0x1e (0xe2) -> 0x..0c BadBlockProposer at 0x47b03a1.
        r = self.rebuild(self.patched((0x47B039D, b"\x49\x83\xc5\xe2", b"\x49\x83\xc5\xe8")))
        v = self.variants_at(r, "0x47b01b0", "0x47b03a1")
        self.assertNotIn("BadBlockProposer", v)
        self.assertIn("RpcRoundRobin", v)            # 0x2a - 0x18 = 0x12

    def test_spans_two_tokens_is_computed(self):
        # a fresh copy of the 31-char token inside an unrelated path string at
        # 0x1e2d40 is not followed by 'ChildQc', so it must not count as spanning.
        tok = cet.MERGED_RE008_DISPUTED_TOKEN.encode()
        o = self.elf.off(0x1E2D40)
        r = self.rebuild(self.patched((0x1E2D40, DATA[o:o + len(tok)], tok)))
        dt = r["corrections"]["merged_re008_disputed_token"]
        self.assertIn("0x1e2d40", dt["occurrences"])
        spans = {e["occurrence"]: e["spans_two_tokens"] for e in dt["cross_token_evidence"]}
        self.assertFalse(spans["0x1e2d40"])
        self.assertEqual(r["metrics"]["corrections"]["occurrences_spanning_two_tokens"], 3)

    def test_disputed_token_as_one_variant_is_detected(self):
        # make the arm-0x1c name length 31 (0x1f) everywhere. In each formatter
        # copy that mov edx,0x14 tail is shared with arm 0x25 (equal-length
        # names are tail-merged), so the fourth monomorph's own 0x25 length
        # (0x47529be) is patched too and both rows change consistently.
        r = self.rebuild(self.patched(
            (0x4755285, b"\xba\x14", b"\xba\x1f"), (0x44C4E7E, b"\xba\x14", b"\xba\x1f"),
            (0x244ED8E, b"\xba\x14", b"\xba\x1f"), (0x475385C, b"\x41\xb9\x14", b"\x41\xb9\x1f"),
            (0x47529BE, b"\x41\xb9\x14", b"\x41\xb9\x1f")))
        dt = r["corrections"]["merged_re008_disputed_token"]
        self.assertEqual(r["tags"][0x1C]["variant"], cet.MERGED_RE008_DISPUTED_TOKEN)
        self.assertEqual(r["tags"][0x25]["variant"], "AddTxNotSignedActionTxUnexpecte")
        self.assertTrue(dt["is_single_variant_in_binary"])
        self.assertEqual(r["metrics"]["corrections"]["merged_lea_sites_with_len_20"], 0)
        self.assertGreater(dt["strings_of_token_len_written_by_any_arm"], 0)

    def test_eh_frame_hdr_corruption_fails_closed(self):
        hdr = self.elf.sections[".eh_frame_hdr"][1]
        b = bytearray(DATA)
        b[hdr] = 0xFF  # version byte -> unexpected encodings
        with self.assertRaisesRegex(cet.EvidenceError, "eh_frame_hdr"):
            self.rebuild(bytes(b))

    # -- CLI and determinism ---------------------------------------------- #
    def test_hashseed_invariance(self):
        for seed in ("0", "7", "99"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            out = subprocess.run([sys.executable, "-I", "-B", str(TOOL)], cwd=ROOT, env=env, capture_output=True)
            self.assertEqual(out.returncode, 0, out.stderr.decode()[:400])
            self.assertEqual(hashlib.sha256(out.stdout).hexdigest(), OUTPUT_SHA256,
                             f"nondeterministic under PYTHONHASHSEED={seed}")

    def test_cli_under_OO_and_wrong_input(self):
        out = subprocess.run([sys.executable, "-OO", "-I", "-B", str(TOOL)], cwd=ROOT, capture_output=True)
        self.assertEqual(out.returncode, 0, out.stderr.decode()[:400])
        self.assertEqual(hashlib.sha256(out.stdout).hexdigest(), OUTPUT_SHA256)
        bad = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--binary", str(TOOL)], cwd=ROOT,
                             capture_output=True)
        self.assertEqual(bad.returncode, 2)
        self.assertIn(b"sha256", bad.stderr)


@unittest.skipIf(DATA is None, "pinned binary not present")
@unittest.skipUnless(OBJDUMP and READELF, "GNU binutils objdump/readelf not on PATH")
class ConsensusErrorTagsGnuCrossChecks(unittest.TestCase):
    """Independent oracles: GNU objdump / readelf, no tool code beyond decode()."""

    # objdump instruction starts per FDE (the 3 formatters, the fourth
    # monomorph, the 7 census FDEs).
    STARTS = {0x4753D60: 2263, 0x44C4480: 806, 0x244E3F0: 803, 0x4752890: 1025,
              0x47B01B0: 148, 0x4758D70: 322, 0x47594F0: 244, 0x454AA10: 182,
              0x4B31E70: 1336, 0x44AB560: 229, 0x44ADFA0: 3470}

    @classmethod
    def setUpClass(cls):
        cls.d = json.loads((PACKET / "consensus-error-tags.json").read_text())
        frames = subprocess.run([READELF, "--debug-dump=frames", str(BIN)], capture_output=True,
                                text=True, check=True).stdout
        cls.fdes = {}
        for m in re.finditer(r" FDE cie=\w+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", frames):
            cls.fdes.setdefault(int(m.group(1), 16), int(m.group(2), 16))
        cls.fde_lines = len(re.findall(r" FDE cie=", frames))

    def lines(self, lo, hi):
        out = subprocess.run([OBJDUMP, "-d", "-M", "intel", "--no-show-raw-insn",
                              f"--start-address={lo:#x}", f"--stop-address={hi:#x}", str(BIN)],
                             capture_output=True, text=True, check=True).stdout
        rows = {}
        order = []
        for ln in out.splitlines():
            m = re.match(r"^\s*([0-9a-f]+):\t(\S+)\s*(.*)$", ln)
            if m:
                va = int(m.group(1), 16)
                rows[va] = (m.group(2), m.group(3).strip())
                order.append(va)
        return rows, order

    def rodata(self, lo, n):
        out = subprocess.run([OBJDUMP, "-s", "-j", ".rodata", f"--start-address={lo:#x}",
                              f"--stop-address={lo + n:#x}", str(BIN)], capture_output=True,
                             text=True, check=True).stdout
        blob = b""
        for ln in out.splitlines():
            m = re.match(r"^ ([0-9a-f]+) (.*)$", ln)
            if m:
                # rows hold 16 bytes from the start address; the hex digits
                # come first, so the first 2*k non-space characters are hex.
                k = min(16, lo + n - int(m.group(1), 16))
                blob += bytes.fromhex(m.group(2).replace(" ", "")[:2 * k])
        self.assertEqual(len(blob), n)
        return blob

    def test_fde_ranges_against_readelf(self):
        self.assertEqual(self.fde_lines, self.d["fde_count"])
        mons = self.d["formatter_monomorphs"] + [self.d["variant_index_crosscheck"]]
        for rec in mons + self.d["census"]:
            self.assertEqual(self.fdes[h(rec["fde"])], h(rec["fde_end"]), rec["fde"])

    def test_decoder_lengths_against_objdump(self):
        t = cet.Target(DATA)
        total = 0
        for fn, want in self.STARTS.items():
            lo, hi = fn, self.fdes[fn]
            rows, order = self.lines(lo, hi)
            self.assertEqual(len(order), want, f"{fn:#x}")
            for i, va in enumerate(order):
                nxt = order[i + 1] if i + 1 < len(order) else hi
                self.assertEqual(cet.decode(t.text, va - t.t_va)[0], nxt - va, f"length at {va:#x}")
            total += len(order)
        self.assertEqual(total, 10828)

    def test_all_rows_against_objdump(self):
        """Jump tables via objdump -s, each arm's first (lea rsi, mov edx) pair
        before a call or a jmp through a register via objdump -d, name bytes via
        objdump -s: all 42 rows of all three copies."""
        for c, mon in enumerate(self.d["formatter_monomorphs"]):
            lo, hi, table = h(mon["fde"]), h(mon["fde_end"]), h(mon["jump_table"])
            raw = self.rodata(table, 4 * 43)
            ents = [table + struct.unpack_from("<i", raw, 4 * k)[0] for k in range(43)]
            self.assertEqual(ents[42], h(mon["entry_past_table"]["target"]))
            rows, order = self.lines(lo, hi)
            nxt = dict(zip(order, order[1:]))
            for k in range(42):
                cp = self.d["tags"][k]["copies"][c]
                self.assertEqual(ents[k], h(cp["arm"]), f"{mon['fde']} k={k:#x}")
                ptr = ln = None
                ip = ents[k]
                found = None
                for _ in range(800):
                    mnem, ops = rows[ip]
                    m = re.match(r"rsi,\[rip\+0x[0-9a-f]+\]\s+#\s+([0-9a-f]+)", ops) if mnem == "lea" else None
                    if m:
                        ptr = int(m.group(1), 16)
                    elif mnem == "mov" and re.fullmatch(r"edx,0x[0-9a-f]+", ops):
                        ln = int(ops.split(",")[1], 16)
                    elif mnem == "call" or (mnem == "jmp" and re.fullmatch(r"r\w+", ops)):
                        if ptr is not None and ln is not None:
                            found = (ptr, ln)
                            break
                        ptr = ln = None
                    if mnem == "ret":
                        break
                    jm = re.match(r"([0-9a-f]+) <", ops) if mnem == "jmp" else None
                    ip = int(jm.group(1), 16) if jm else nxt[ip]
                self.assertIsNotNone(found, f"{mon['fde']} k={k:#x}")
                self.assertEqual(found, (h(cp["name_ptr"]), self.d["tags"][k]["name_len"]), f"k={k:#x}")
                self.assertEqual(self.rodata(found[0], found[1]).decode(), self.d["tags"][k]["variant"])

    def test_census_sites_against_objdump(self):
        mem = re.compile(r"QWORD PTR \[(\w+)(?:([+-])0x([0-9a-f]+))?\]")
        regs = set(cet.REG)
        for c in self.d["census"]:
            rows, _ = self.lines(h(c["fde"]), h(c["fde_end"]))
            for s in c["niche_movabs_sites"]:
                self.assertEqual(rows[h(s["site"])], ("movabs", f"{s['reg']},{s['value']}"), s["site"])
            for key in ("in_range_tag_stores", "niche_0x00_stores", "past_table_niche_stores",
                        "out_of_range_niche_stores"):
                for s in c[key]:
                    mnem, ops = rows[h(s["site"])]
                    dst, src = ops.rsplit(",", 1)
                    m = mem.fullmatch(dst)
                    self.assertEqual(mnem, "mov", s["site"])
                    self.assertIsNotNone(m, f"not a QWORD store: {s['site']} {ops}")
                    disp = int(m.group(3) or "0", 16) * (-1 if m.group(2) == "-" else 1)
                    self.assertEqual((m.group(1), disp, src), (s["dest"]["base"], h(s["dest"]["disp"]), s["src"]))
                    self.assertIsNone(s["dest"]["index"])
            for s in c["niche_comparisons"]:
                mnem, ops = rows[h(s["site"])]
                a, b = ops.split(",")
                self.assertEqual(mnem, "cmp", s["site"])
                self.assertIn(s["reg"], (a, b))
                for operand in (a, b):
                    self.assertTrue(operand in regs or mem.fullmatch(operand), f"not 64-bit: {s['site']} {ops}")

    def test_readelf_sections_match_tool(self):
        out = subprocess.run([READELF, "-SW", str(BIN)], capture_output=True, text=True).stdout
        elf = sr.Elf(DATA)
        for name in (".text", ".rodata"):
            m = re.search(rf"\]\s+{re.escape(name)}\s+\w+\s+([0-9a-f]+)\s+([0-9a-f]+)", out)
            self.assertIsNotNone(m, f"{name} not found in readelf output")
            self.assertEqual(elf.sections[name][:2], (int(m.group(1), 16), int(m.group(2), 16)))

    def test_excerpts_regenerate(self):
        version = subprocess.run([OBJDUMP, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        if version != RECORDED_OBJDUMP:
            self.skipTest(f"excerpts were made with {RECORDED_OBJDUMP}, found {version}")
        out = subprocess.run([sys.executable, "-I", "-B", str(PACKET / "make_excerpts.py"), "--check"],
                             cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr[:400])


if __name__ == "__main__":
    unittest.main()
