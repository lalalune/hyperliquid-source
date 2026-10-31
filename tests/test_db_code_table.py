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
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("db_code_table", ROOT / "tools/db_code_table.py")
dct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dct)
sr = dct.sr
BIN = ROOT / "artifacts/node/94/hl-node"
PACKET = ROOT / "research/work-items/RE-009-db-code-table-94"
OUTPUT_SHA256 = "e84c625a02abde7376f07c0098799185601fe68723495b084ad997926d331f30"
DATA = BIN.read_bytes() if BIN.exists() else None

# codegen copies / key sites (checked, never trusted as given)
TAG_BLOBS = (0x594FF2, 0x6F7394)            # copy1 / copy2 2-byte tag string blobs
TAG_SLOT28 = (0x56F1A00, 0x572D8C0)         # slot one past each 28-entry tag table
LEN_TABLES = (0x5953F8, 0x6F87B0)           # copy1 / copy2 u64 name length tables
BUCKET_LEN_TABLES = (0x58C280, 0x6F8900)    # copy1 / copy2 u64 bucket-name length tables
TEMPLATE = 0x1DEE9F                         # 04 'dhs/' c0 00
WRAPPER0 = 0x358CEA0
LAST = 0x459CF30                            # a non-first wrapper, for cross-wrapper tampers
GLOBAL_READ0 = 0x358D07C                    # movzx ecx,[r14+0x48] in wrapper 0
# the six wrappers (end exclusive)
WRAPPERS = ((0x358CEA0, 0x358D2D9), (0x358D2E0, 0x358D719), (0x358D720, 0x358DB59),
            (0x459C6B0, 0x459CAE9), (0x459CAF0, 0x459CF29), (0x459CF30, 0x459D369))
NAMES = ["Candle", "FundingLedgerUpdates", "NonFundingLedgerUpdates", "BoleInterest",
         "PortfolioSamples", "UserFills", "AssetTrades", "LegacyRewardHistory", "ExplorerUserTxs",
         "FundingHistory", "AssetCtxHistory", "OrderHistory", "UserTwapSliceFills", "TwapHistory",
         "UserPositionSamples", "UserAggregatedFills", "SpotEvents", "GovProposals",
         "DelegatorEvents", "DelegatorRewardHistory", "ValidatorBucketStats", "EvmTxs",
         "EvmBlockNumbers", "EvmBlocks", "EvmStateAccounts", "EvmStateContracts", "EvmStateStorage",
         "LegacyPortfolioSamples"]
TAGS = ["cA", "lu", "nf", "bi", "Ps", "uf", "aT", "rh", "et", "fH", "aH", "oh", "ts", "th", "up",
        "ua", "se", "gP", "de", "dr", "vb", "Et", "En", "Eb", "Ea", "Ec", "Es", "ps"]
# aligned objdump census over the whole of .text (instruction text -> hits; all 6 in-wrapper)
CENSUS = {
    r"mov    eax,0x81ffeff": 6,
    r"mov    eax,0xe00100": 6,
    r"mov    eax,0x20ff01": 6,
    r"add    cl,0xf6": 6,
    r"cmp    BYTE PTR \[rsp\+0xc\],0x3": 6,
    r"movzx  ecx,BYTE PTR \[r14\+0x48\]": 1838,
    r"cmp    cl,0x16": 1851,
    r"shr    eax,cl": 94,
    r"cmp    BYTE PTR \[rsp\+0xc\],0x2": 25,
}
TEXT_INSTRUCTIONS = 16649471


def gnu(tool):
    """Path to `tool` only if it is GNU binutils (LLVM tools reject these flags)."""
    if shutil.which(tool) is None:
        return None
    try:
        v = subprocess.run([tool, "--version"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return tool if "GNU" in v else None


# ---- objdump listing + control-flow helpers (GNU objdump, Intel syntax) -----
INSN = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(\S+)(?:\s+(.*))?$")
CONT = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} ?)+)$")
JCC = {"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge",
       "jle", "jg", "jrcxz", "jecxz", "loop", "loope", "loopne"}


def listing(lo, hi):
    """[(address, length, mnemonic, operands)] for [lo, hi), contiguous."""
    out = subprocess.run(["objdump", "-d", "-M", "intel", f"--start-address={lo:#x}",
                          f"--stop-address={hi:#x}", str(BIN)], capture_output=True, text=True,
                         check=True).stdout
    ins = []
    for raw in out.splitlines():
        line = re.sub(r" <[^>]*>", "", raw).rstrip()
        m = INSN.match(line)
        if m:
            ins.append([int(m.group(1), 16), len(m.group(2).split()), m.group(3), (m.group(4) or "").strip()])
            continue
        m = CONT.match(line)
        if m and ins:
            ins[-1][1] += len(m.group(2).split())
    return [tuple(i) for i in ins]


def cfg(ins):
    """Direct-flow successors; calls are assumed to return (conservative)."""
    succ = {}
    for a, n, mn, op in ins:
        nxt = a + n
        direct = re.fullmatch(r"[0-9a-f]+", op)
        if mn == "jmp":
            succ[a] = [int(op, 16)] if direct else None          # None = indirect jump
        elif mn in JCC:
            succ[a] = [int(op, 16), nxt]
        elif mn in ("ret", "ud2"):
            succ[a] = []
        else:
            succ[a] = [nxt]
    preds = defaultdict(set)
    for a, ss in succ.items():
        for t in ss or ():
            preds[t].add(a)
    return succ, preds


def reachable(succ, roots, removed=()):
    seen, stack = set(), [r for r in roots if r not in removed]
    while stack:
        a = stack.pop()
        if a in seen or a in removed or a not in succ:
            continue
        seen.add(a)
        stack.extend(succ[a] or ())
    return seen


def normalised(ins, lo, hi):
    """Masks: RIP operand + objdump '# target' -> [rip+REL]; direct call target ->
    CALLTGT; direct jmp/jcc target -> offset from the FDE start (inside) or EXT."""
    out = []
    for a, n, mn, op in ins:
        o = re.sub(r"\[rip\+0x[0-9a-f]+\]\s+# [0-9a-f]+", "[rip+REL]", op)
        if re.fullmatch(r"[0-9a-f]+", o):
            if mn == "call":
                o = "CALLTGT"
            elif mn == "jmp" or mn in JCC:
                t = int(o, 16)
                o = f"+{t - lo:#x}" if lo <= t < hi else "EXT"
        out.append((a - lo, n, mn, o))
    return out


def writes(op, regs):
    return re.match(r"(%s)\b" % "|".join(regs), op) is not None


@unittest.skipIf(DATA is None, "pinned binary not present")
class DbCodeTableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = dct.build(DATA)
        cls.text = dct.render(cls.r)
        cls.d = json.loads(cls.text)   # published shape: addresses are hex strings
        cls.elf = sr.Elf(DATA)

    # ---- helpers ------------------------------------------------------
    def rebuild(self, b):
        return dct.build(b, expected_sha256=hashlib.sha256(b).hexdigest())

    def patched(self, *patches):
        b = bytearray(DATA)
        for va, new in patches:
            o = self.elf.off(va)
            b[o:o + len(new)] = new
        return bytes(b)

    def sites(self, pattern, wrappers=WRAPPERS, offset=0):
        """VA (+offset) of every raw match of `pattern` inside the given wrappers."""
        out = []
        for lo, hi in wrappers:
            blob = DATA[self.elf.off(lo):self.elf.off(hi)]
            out.extend(lo + m.start() + offset for m in re.finditer(pattern, blob, re.S))
        return out

    def only(self, va):
        return [w for w in WRAPPERS if w[0] == va]

    def mov_bpl_sites(self, wrappers=WRAPPERS):
        """(imm8 VA, value) of every `mov bpl,imm8` (40 b5 01|02) inside the wrappers."""
        return [(va, DATA[self.elf.off(va)]) for va in self.sites(b"\x40\xb5[\x01\x02]", wrappers, 2)]

    def family_cmp_sites(self, wrappers=WRAPPERS):
        """imm8 VA of every `cmp al,imm8` that follows `lea eax,[r14-0x15]`."""
        return self.sites(re.escape(b"\x41\x8d\x46\xeb\x3c"), wrappers, 5)

    def reloc_patched(self, edits, base=None):
        """Rewrite the addend of the RELATIVE relocation at each slot in `edits`."""
        _a, off, size = self.elf.sections[".rela.dyn"]
        b = bytearray(DATA if base is None else base)
        todo = dict(edits)
        for o in range(off, off + size, 24):
            slot = struct.unpack_from("<Q", b, o)[0]
            if slot in todo and struct.unpack_from("<Q", b, o + 8)[0] & 0xFFFFFFFF == 8:
                struct.pack_into("<q", b, o + 16, todo.pop(slot))
        self.assertEqual(todo, {}, "relocation slot not found")
        return bytes(b)

    # ---- pinned output ------------------------------------------------
    def test_pinned_output(self):
        r = self.d
        self.assertEqual(hashlib.sha256(self.text).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "db-code-table.json").read_bytes(), self.text)
        self.assertEqual(r["binary_sha256"], dct.EXPECTED_SHA256)
        self.assertEqual(r["elf_type"], "ET_DYN (PIE)")
        self.assertEqual(r["fde_count"], 121299)
        self.assertEqual(r["code_count"], 28)
        self.assertEqual(r["wrapper_count"], 6)
        self.assertEqual([(w["wrapper"], w["end"]) for w in r["wrappers"]],
                         [(f"{lo:#x}", f"{hi:#x}") for lo, hi in WRAPPERS])
        self.assertEqual(r["tag_table_bases"], ["0x56f1920", "0x572d7e0"])
        self.assertEqual(r["name_formatters"], ["0x35b67f0", "0x45c4a10"])
        self.assertEqual(r["masks"], {"primary": "0x81ffeff", "aux": "0xe00100", "config_gate": "0x20ff01"})
        self.assertEqual(len(r["home_mask_sites"]), 12)
        self.assertEqual(r["bucket_assignment"], {"primary_bucket": 0, "aux_bucket": 1, "other_bucket": 2})
        self.assertEqual(r["bucket_names"], {"0": "Exchange", "1": "Rpc", "2": "EvmState"})
        self.assertEqual(r["evm_family"], {"base": 21, "threshold": 6})

    def test_table_rows(self):
        rows = self.d["table"]
        self.assertEqual([x["tag"] for x in rows], TAGS)
        self.assertEqual([x["name"] for x in rows], NAMES)
        self.assertEqual([x["code"] for x in rows if x["is_evm_family"]], [21, 22, 23, 24, 25, 26])
        self.assertEqual([x["code"] for x in rows if x["path_built"]], [21, 22, 23])
        self.assertEqual([x["home_bucket"] for x in rows],
                         [0] * 8 + [1] + [0] * 12 + [1, 1, 1, 2, 2, 2, 0])
        self.assertEqual([x["home_bucket_name_inferred"] for x in rows[24:27]], ["EvmState"] * 3)

    def test_path_build(self):
        # The build branch formats one (code byte, name formatter) pair with the
        # template at 0x1dee9f; only codes 21..23 pass the code-side gate.
        p = self.d["path_build"]
        self.assertEqual(p["template_target"], "0x1dee9f")
        self.assertEqual(p["template_bytes"], "04 64 68 73 2f c0 00")
        self.assertEqual(p["template_pieces"], ["dhs/", "{}"])
        self.assertEqual((p["argument_slots"], p["args_pairs"], p["arg_value_slot"]), (1, 1, "rsp+0x7"))
        self.assertEqual(p["rendered_template"], "dhs/{}")
        self.assertEqual((p["format_fn_got"], p["format_fn"]), ("0x576e040", "0x1344760"))
        self.assertEqual(p["built_for_codes"], [21, 22, 23])
        self.assertEqual(p["code_gate"], "(code - 21) as u8 < 3")
        self.assertEqual(p["niche_when_skipped"], "0x8000000000000000")
        self.assertEqual(p["config_byte_suppressed_values"], [10, 18, 19, 20, 21, 22, 23, 24, 25, 31])
        self.assertEqual(p["consumers"], [
            {"got_slot": "0x576ef10", "target_fn": "0x1402050",
             "location_files": ["base/src/daily_liner.rs:27:13"]},
            {"got_slot": "0x576ef78", "target_fn": "0x14019b0",
             "location_files": ["base/src/daily_liner.rs:58:51", "base/src/hour.rs:12:13",
                                "base/src/time.rs:62:44"]},
            {"got_slot": "0x576dfe0", "import": "memcpy"},
            {"got_slot": "0x576e010", "target_fn": "0x54c8cb0", "location_files": []}])
        w0 = self.d["wrappers"][0]
        self.assertEqual((w0["config_gate"]["build_branch"], w0["config_gate"]["niche_site"],
                          w0["config_gate"]["merge"]), ("0x358d0b5", "0x358d09f", "0x358d14e"))
        self.assertEqual(w0["build_branch"]["format_out_slot"], "rsp+0x58")

    def test_bucket_names_from_db_home_formatters(self):
        # Each db_home.rs:83 panic passes one (bucket byte, formatter) pair; the two
        # formatters' len/off tables abut after 3 entries and agree on the names.
        b = self.d["bucket_name_formatters"]
        self.assertEqual([(x["function"], x["formatter"], x["location_slot"], x["location"],
                           x["arg_value_slot"], x["len_table"], x["off_table"]) for x in b],
                         [("0x332eba0", "0x33dd5b0", "0x56e9988", "db/src/db_home.rs:83:13", "rsp+0x7",
                           "0x58c280", "0x58c298"),
                          ("0x459b500", "0x45fb180", "0x572aef8", "db/src/db_home.rs:83:13", "rsp+0xe",
                           "0x6f8900", "0x6f8918")])
        for x in b:
            self.assertEqual(x["names"], ["Exchange", "Rpc", "EvmState"])
            self.assertEqual(int(x["off_table"], 16) - int(x["len_table"], 16), 3 * 8)
            self.assertEqual(x["template"]["rendered_template"], "db_home contains db_bundle in path: {}")
            self.assertEqual(x["template"]["template_target"], "0x1ffb00")
        # the 3-arm write_str shape is NOT unique; the one with these names is chosen
        self.assertEqual(self.d["bucket_display_fn"], "0x1586ee0")
        self.assertEqual(self.d["bucket_display_shape_candidates"], ["0x1586ee0", "0x3818cf0"])

    def test_config_gate(self):
        g = self.d["config_gate"]
        self.assertEqual((g["got_slot"], g["global_base"], g["global_byte_offset"], g["global_byte_addr"],
                          g["once_state_offset"]), ("0x576e928", "0x577b288", "0x48", "0x577b2d0", "0x50"))
        self.assertEqual((g["shift_bias"], g["shift_range"], g["shift_const"], g["shift_amount_expr"]),
                         (246, 22, "0x20ff01", "global_byte - 10"))
        self.assertEqual((g["code_lt_threshold"], g["code_le_threshold"]), (3, 2))
        self.assertEqual(g["gate_sequence_hits_in_text"], 6)
        self.assertEqual((g["initializer_fn"], g["initializer_location_files"]),
                         ("0x164ff00", ["global_constants/src/static_config.rs:24:9"]))

    def test_static_callers(self):
        callers = [(c["function"], c["call_site"], c["code"], c["name"], c["wrapper"])
                   for c in self.d["static_callers"]]
        self.assertEqual(callers, [
            ("0x3269ae0", "0x3269c5c", 24, "EvmStateAccounts", "0x358cea0"),
            ("0x3269ae0", "0x3269e77", 25, "EvmStateContracts", "0x358d720"),
            ("0x3269ae0", "0x326a086", 26, "EvmStateStorage", "0x358d2e0"),
            ("0x47f1590", "0x47f2670", 23, "EvmBlocks", "0x459caf0"),
            ("0x47f1590", "0x47f2682", 21, "EvmTxs", "0x459c6b0"),
            ("0x47f1590", "0x47f2697", 22, "EvmBlockNumbers", "0x459cf30")])
        self.assertEqual(self.d["caller_location_files"],
                         {"0x3269ae0": ["l1/src/evm/evm_db.rs:154:67"], "0x47f1590": ["node/src/aux.rs:252:13"]})

    def test_wrappers_not_address_taken(self):
        # Each wrapper start has exactly one reference, a rel32 e8 call; no other form.
        refs = self.d["references"]["wrappers"]
        calls = {c["wrapper"]: c["call_site"] for c in self.d["static_callers"]}
        self.assertEqual(sorted(refs), [f"{lo:#x}" for lo, _ in WRAPPERS])
        for w, rec in refs.items():
            self.assertEqual(rec["call_rel32"], [calls[w]])
            for k in ("jmp_rel32", "jcc_rel32", "rip_relative", "rel8_branch", "relocations"):
                self.assertEqual(rec[k], [], f"{w} {k}")
            self.assertEqual((rec["absolute_qword"], rec["absolute_dword"]), (0, 0))

    def test_formatter_and_tag_blob_references(self):
        f = self.d["references"]["formatters"]
        sites = lambda va: [x - 3 for x in (int(s, 16) for s in f[va]["rip_relative"])]  # lea starts
        self.assertEqual(sites("0x35b67f0"), [lo + 0x222 for lo, _ in WRAPPERS[:3]])
        self.assertEqual(sites("0x45c4a10"), [lo + 0x222 for lo, _ in WRAPPERS[3:]])
        self.assertEqual(sites("0x33dd5b0"), [0x332ED34])
        self.assertEqual(sites("0x45fb180"), [0x459C17D])
        for rec in f.values():
            for k in ("call_rel32", "jmp_rel32", "jcc_rel32", "rel8_branch", "relocations"):
                self.assertEqual(rec[k], [])
            self.assertEqual((rec["absolute_qword"], rec["absolute_dword"]), (0, 0))
        self.assertEqual([(t["blob"], t["length"], t["file_occurrences"], t["relative_relocs_into"],
                           t["code_references_into"]) for t in self.d["tag_blobs"]],
                         [("0x594ff2", 56, 2, 28, 0), ("0x6f7394", 56, 2, 28, 0)])

    def test_label_string_counts(self):
        self.assertEqual(self.d["label_string_counts"],
                         {"DbBundle": 0, "DbHub": 0, "DbCode": 0, "WrappedDbHome": 0, "wrap_home": 0,
                          "home_bucket": 0, "timed_liner": 0, "daily_liner": 2, "db_bundle": 1})
        self.assertEqual(DATA.find(b"db_bundle"), self.elf.off(0x1FFB12))

    def test_elf_is_pie(self):
        # e_type at file offset 0x10 is ET_DYN (03 00); DT_FLAGS_1 carries DF_1_PIE.
        self.assertEqual(DATA[0x10:0x12], b"\x03\x00")
        self.assertEqual(dct._elf_type(self.elf), "ET_DYN (PIE)")

    def test_wrappers_are_fde_starts(self):
        starts, ends = sr.fde_index(self.elf)
        for lo, hi in WRAPPERS:
            self.assertTrue(sr.is_fde_start(starts, lo))
            self.assertEqual(sr.containing(starts, ends, lo), (lo, hi))

    # ---- determinism --------------------------------------------------
    def test_hashseed_invariance(self):
        outs = set()
        for seed in ("0", "7", "99"):
            p = subprocess.run([sys.executable, "-B", str(ROOT / "tools/db_code_table.py")],
                               env=dict(os.environ, PYTHONHASHSEED=seed), capture_output=True, check=True)
            outs.add(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, {OUTPUT_SHA256})

    def test_verify_script_passes(self):
        p = subprocess.run([sys.executable, "-I", "-B", str(PACKET / "verify.py")], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(p.stdout.startswith("PASS"))

    # ---- tamper: the output follows the bytes -------------------------
    def test_wrong_binary_rejected(self):
        with self.assertRaisesRegex(dct.EvidenceError, "binary sha256"):
            dct.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_tag_bytes_are_load_bearing(self):
        r = self.rebuild(self.patched((TAG_BLOBS[0], b"X"), (TAG_BLOBS[1], b"X")))
        self.assertEqual(r["table"][0]["tag"], "XA")
        self.assertEqual(r["table"][1]["tag"], "lu")  # neighbour unchanged (stride 2)

    def test_name_length_is_load_bearing(self):
        four = struct.pack("<Q", 4)
        r = self.rebuild(self.patched((LEN_TABLES[0], four), (LEN_TABLES[1], four)))
        self.assertEqual(r["table"][0]["name"], "Cand")  # "Candle"[:4]

    def test_bucket_name_bytes_are_load_bearing(self):
        # both formatters (and the 3-arm Display) point at the same "Exchange" bytes
        r = self.rebuild(self.patched((0x20AA98, b"X")))
        self.assertEqual(r["bucket_names"]["0"], "Xxchange")
        self.assertEqual(r["table"][0]["home_bucket_name_inferred"], "Xxchange")

    def test_template_literal_is_load_bearing(self):
        r = self.rebuild(self.patched((TEMPLATE + 1, b"xyz/")))
        self.assertEqual(r["path_build"]["rendered_template"], "xyz/{}")

    def test_family_threshold_all_sites_is_load_bearing(self):
        patches = [(s, b"\x07") for s in self.family_cmp_sites()]
        self.assertEqual(len(patches), 12)          # two per wrapper, six wrappers
        r = self.rebuild(self.patched(*patches))
        self.assertEqual(r["evm_family"], {"base": 21, "threshold": 7})
        self.assertTrue(r["table"][27]["is_evm_family"])  # code-0x15 == 6 < 7 now

    def test_family_base_all_sites_is_load_bearing(self):
        # lea eax,[r14-0x15] -> [r14-0x14] at all 18 sites: base and both gates move
        patches = self.sites(re.escape(b"\x41\x8d\x46\xeb"), offset=3)
        self.assertEqual(len(patches), 18)
        r = self.rebuild(self.patched(*[(s, b"\xec") for s in patches]))
        self.assertEqual(r["evm_family"], {"base": 20, "threshold": 6})
        self.assertEqual(r["path_build"]["built_for_codes"], [20, 21, 22])

    def test_bucket_bpl_swap_changes_output(self):
        patches = [(va, bytes([3 - cur])) for va, cur in self.mov_bpl_sites()]
        self.assertEqual(len(patches), 12)          # two bpl writes per wrapper, six wrappers
        r = self.rebuild(self.patched(*patches))
        self.assertEqual(r["bucket_assignment"], {"primary_bucket": 0, "aux_bucket": 2, "other_bucket": 1})
        self.assertEqual(r["table"][8]["home_bucket"], 2)  # ExplorerUserTxs was 1

    def test_primary_mask_all_six_is_load_bearing(self):
        sites = self.sites(re.escape(b"\xb8\xff\xfe\x1f\x08"), offset=1)
        self.assertEqual(len(sites), 6)
        r = self.rebuild(self.patched(*[(s, struct.pack("<I", 0x081FFEFF & ~(1 << 27))) for s in sites]))
        self.assertEqual(r["masks"]["primary"], 0x01FFEFF)
        self.assertEqual(r["table"][27]["home_bucket"], 2)  # bit 27 cleared -> neither mask

    def test_code_thresholds_all_six_change_output(self):
        lt = self.sites(re.escape(b"\x80\x7c\x24\x0c\x03\x0f\x93\xc1"), offset=4)
        le = self.sites(re.escape(b"\x80\x7c\x24\x0c\x02\x77"), offset=4)
        self.assertEqual((len(lt), len(le)), (6, 6))
        r = self.rebuild(self.patched(*[(s, b"\x04") for s in lt], *[(s, b"\x03") for s in le]))
        self.assertEqual(r["path_build"]["built_for_codes"], [21, 22, 23, 24])

    def test_caller_code_is_load_bearing(self):
        # mov esi,0x18 -> 0x1b before the 0x3269c5c call: that caller now passes code 27
        self.assertEqual(DATA[self.elf.off(0x3269C54):self.elf.off(0x3269C54) + 5], b"\xbe\x18\x00\x00\x00")
        r = self.rebuild(self.patched((0x3269C55, b"\x1b")))
        self.assertEqual([c["call_site"] for c in r["table"][27]["static_callers"]], [0x3269C5C])
        self.assertEqual(r["table"][24]["static_callers"], [])

    def test_shift_bias_all_six_changes_suppressed_set(self):
        sites = self.sites(re.escape(b"\x80\xc1\xf6"), offset=2)
        self.assertEqual(len(sites), 6)
        r = self.rebuild(self.patched(*[(s, b"\xf5") for s in sites]))
        self.assertEqual(r["path_build"]["config_byte_suppressed_values"],
                         [11, 19, 20, 21, 22, 23, 24, 25, 26, 32])

    # ---- tamper: copies and wrappers must agree (fails closed) --------
    def test_tag_copies_must_agree(self):
        with self.assertRaisesRegex(dct.EvidenceError, "tag-table copies disagree"):
            self.rebuild(self.patched((TAG_BLOBS[0], b"X")))

    def test_name_copies_must_agree(self):
        with self.assertRaisesRegex(dct.EvidenceError, "name-table copies disagree"):
            self.rebuild(self.patched((LEN_TABLES[0], struct.pack("<Q", 4))))

    def test_bucket_name_copies_must_agree(self):
        with self.assertRaisesRegex(dct.EvidenceError, "bucket-name formatter copies disagree"):
            self.rebuild(self.patched((BUCKET_LEN_TABLES[0], struct.pack("<Q", 7))))

    # Each of these alters ONE non-first wrapper consistently, so only the
    # cross-wrapper agreement check (_require_equal) can catch it.
    def test_cross_wrapper_bucket_writes(self):
        patches = [(va, bytes([3 - cur])) for va, cur in self.mov_bpl_sites(self.only(LAST))]
        self.assertEqual(len(patches), 2)
        with self.assertRaisesRegex(dct.EvidenceError, "wrappers disagree on bucket branch writes"):
            self.rebuild(self.patched(*patches))

    def test_cross_wrapper_range_tests(self):
        patches = [(s, b"\x07") for s in self.family_cmp_sites(self.only(LAST))]
        self.assertEqual(len(patches), 2)
        with self.assertRaisesRegex(dct.EvidenceError, "wrappers disagree on range tests"):
            self.rebuild(self.patched(*patches))

    def test_cross_wrapper_mask(self):
        site = self.sites(re.escape(b"\xb8\xff\xfe\x1f\x08"), self.only(LAST), 1)
        with self.assertRaisesRegex(dct.EvidenceError, "wrappers disagree on mask set"):
            self.rebuild(self.patched((site[0], struct.pack("<I", 0x081FFEFF & ~(1 << 27)))))

    def test_cross_wrapper_config_gate_bias(self):
        site = self.sites(re.escape(b"\x80\xc1\xf6"), self.only(LAST), 2)
        with self.assertRaisesRegex(dct.EvidenceError, "wrappers disagree on config gate"):
            self.rebuild(self.patched((site[0], b"\xf5")))

    def test_cross_wrapper_config_gate_got_slot(self):
        # point the last wrapper's GOT load at the neighbouring (also RELATIVE) slot
        site = self.sites(re.escape(b"\x4c\x8b\x35"), self.only(LAST), 3)[0]
        disp = struct.unpack("<i", DATA[self.elf.off(site):self.elf.off(site) + 4])[0]
        with self.assertRaisesRegex(dct.EvidenceError, "wrappers disagree on config gate"):
            self.rebuild(self.patched((site, struct.pack("<i", disp + 8))))

    # ---- tamper: within-wrapper structure (fails closed) --------------
    def test_family_compares_must_agree_within_wrapper(self):
        firsts = {}
        for s in self.family_cmp_sites():
            firsts.setdefault(next(lo for lo, hi in WRAPPERS if lo <= s < hi), s)
        with self.assertRaisesRegex(dct.EvidenceError, r"EVM-family thresholds disagree \[7, 6\]"):
            self.rebuild(self.patched(*[(s, b"\x07") for s in firsts.values()]))

    def test_reduced_code_store_must_be_family_lea(self):
        # the lea that feeds the third [rsp+0xc] store (no cmp after it), all six
        third = self.sites(re.escape(b"\x41\x8d\x46\xeb\x89\x44\x24\x0c"), offset=3)
        self.assertEqual(len(third), 6)
        with self.assertRaisesRegex(dct.EvidenceError, r"\[rsp\+0xc\] store at .* is not the family lea"):
            self.rebuild(self.patched(*[(s, b"\xec") for s in third]))

    def test_bucket_writes_must_be_0_1_2(self):
        with self.assertRaisesRegex(dct.EvidenceError, r"bucket writes \{0,2,2\} are not \{0,1,2\}"):
            self.rebuild(self.patched(*[(va, b"\x02") for va, _cur in self.mov_bpl_sites()]))

    def test_code_thresholds_must_agree(self):
        lt = self.sites(re.escape(b"\x80\x7c\x24\x0c\x03\x0f\x93\xc1"), offset=4)
        with self.assertRaisesRegex(dct.EvidenceError, r"setae/ja code thresholds disagree \(4 vs 2\)"):
            self.rebuild(self.patched(*[(s, b"\x04") for s in lt]))

    def test_gate_branch_targets_must_close(self):
        je = self.sites(re.escape(b"\xf6\xc1\x01\x74"), offset=4)
        self.assertEqual(len(je), 6)
        with self.assertRaisesRegex(dct.EvidenceError, "config-gate branch targets do not close"):
            self.rebuild(self.patched(*[(s, bytes([DATA[self.elf.off(s)] + 1])) for s in je]))

    def test_formatted_value_must_be_code_byte(self):
        lea7 = self.sites(re.escape(b"\x48\x8d\x44\x24\x07\x48\x89\x84\x24"), offset=4)
        self.assertEqual(len(lea7), 6)
        with self.assertRaisesRegex(dct.EvidenceError, "formatted value is not the stored code byte"):
            self.rebuild(self.patched(*[(s, b"\x08") for s in lea7]))

    def test_primary_bt_is_load_bearing(self):
        # bt eax,r12d -> bt ecx,r12d after the PRIMARY mask in all six: no chain
        sites = self.sites(re.escape(b"\xb8\xff\xfe\x1f\x08\x44\x0f\xa3\xe0"), offset=8)
        with self.assertRaisesRegex(dct.EvidenceError, "expected one PRIMARY->AUX bt chain, found 0"):
            self.rebuild(self.patched(*[(s, b"\xe1") for s in sites]))

    def test_global_byte_read_is_load_bearing(self):
        with self.assertRaisesRegex(dct.EvidenceError, "expected one config-gate sequence, found 0"):
            self.rebuild(self.patched((GLOBAL_READ0, b"\x90")))

    def test_family_lea_corruption_is_detected(self):
        patches = [(s, b"\x90\x90\x90\x90")
                   for s in self.sites(re.escape(b"\x41\x8d\x46\xeb"), self.only(WRAPPER0))]
        with self.assertRaisesRegex(dct.EvidenceError, "EVM-family range test not found"):
            self.rebuild(self.patched(*patches))

    # ---- tamper: template bytes (walker rules) -----------------------
    def test_template_slot_count_must_match_pairs(self):
        # c0 -> 00: the template ends after 'dhs/' with 0 argument slots, but 1 pair is passed
        with self.assertRaisesRegex(dct.EvidenceError, r"0 argument slots but 1 \(value, formatter\) pairs"):
            self.rebuild(self.patched((TEMPLATE + 5, b"\x00")))

    def test_template_marker_and_end_bytes(self):
        for off, new in ((5, b"\xc1"), (6, b"\x01"), (0, b"\x03")):   # marker, end, length
            with self.subTest(offset=off):
                with self.assertRaisesRegex(dct.EvidenceError, "not printable ASCII"):
                    self.rebuild(self.patched((TEMPLATE + off, new)))

    # ---- tamper: table length controls --------------------------------
    def test_tag_progression_must_terminate(self):
        # slot 28 continues the stride-2 progression into two non-printable bytes
        b = self.reloc_patched({TAG_SLOT28[0]: TAG_BLOBS[0] + 56})
        b = bytearray(b)
        o = self.elf.off(TAG_BLOBS[0] + 56)
        b[o:o + 2] = b"\xff\xff"
        with self.assertRaisesRegex(dct.EvidenceError, "progression did not terminate"):
            self.rebuild(bytes(b))

    def test_tag_count_must_equal_name_count(self):
        # both copies gain a 29th (equal, printable) tag; the names stay at 28
        b = bytearray(self.reloc_patched({TAG_SLOT28[0]: TAG_BLOBS[0] + 56, TAG_SLOT28[1]: TAG_BLOBS[1] + 56}))
        for blob in TAG_BLOBS:
            o = self.elf.off(blob + 56)
            b[o:o + 2] = b"zz"
        with self.assertRaisesRegex(dct.EvidenceError, "tag count 29 != name count 28"):
            self.rebuild(bytes(b))

    def test_code_count_bound_is_live(self):
        saved = dct.MAX_CODES
        dct.MAX_CODES = 28
        try:
            with self.assertRaisesRegex(dct.EvidenceError, "code count 28 reaches 32-bit bt wraparound"):
                dct.build(DATA)
        finally:
            dct.MAX_CODES = saved

    def test_tag_reloc_addend_corruption(self):
        with self.assertRaisesRegex(dct.EvidenceError, "tag-table copies disagree"):
            self.rebuild(self.reloc_patched({0x56F1920: TAG_BLOBS[0] + 1}))

    def test_display_head_break_fails_closed(self):
        # no shape-matching function has the bucket names -> fails (does not pick 0x3818cf0)
        with self.assertRaisesRegex(dct.EvidenceError, "bucket Display: 0 functions match"):
            self.rebuild(self.patched((0x1586EE0, b"\x48\x89\xf1")))

    # ---- external GNU cross-checks -----------------------------------
    @unittest.skipUnless(gnu("readelf"), "GNU readelf missing")
    def test_readelf_relocations(self):
        rel = subprocess.run(["readelf", "-rW", str(BIN)], capture_output=True, text=True, check=True).stdout
        for slot, tgt in ((0x56F1920, 0x594FF2), (0x572D7E0, 0x6F7394), (0x576E928, 0x577B288),
                          (0x577B288, 0x164FF00), (0x576E040, 0x1344760), (0x576EF10, 0x1402050),
                          (0x576EF78, 0x14019B0)):
            self.assertRegex(rel, rf"(?m)^0*{slot:x}\s+0+8 R_X86_64_RELATIVE\s+{tgt:x}$")
        self.assertRegex(rel, r"(?m)^0*576dfe0\s+\S+ R_X86_64_GLOB_DAT\s+0+ memcpy@")

    @unittest.skipUnless(gnu("readelf"), "GNU readelf missing")
    def test_readelf_reports_pie(self):
        out = subprocess.run(["readelf", "-hdW", str(BIN)], capture_output=True, text=True, check=True).stdout
        self.assertRegex(out, r"Type:\s+DYN")
        self.assertRegex(out, r"FLAGS_1\)\s+Flags: .*PIE")

    @unittest.skipUnless(gnu("objdump"), "GNU objdump missing")
    def test_objdump_wrapper_bodies_and_control_flow(self):
        bodies = []
        for lo, hi in WRAPPERS:
            ins = listing(lo, hi)
            self.assertEqual(len(ins), 240)
            self.assertEqual(sum(n for _a, n, _m, _o in ins), hi - lo)
            self.assertTrue(all(a + n == b for (a, n, _m, _o), (b, *_r) in zip(ins, ins[1:])))
            bodies.append(normalised(ins, lo, hi))
            succ, preds = cfg(ins)
            self.assertNotIn(None, succ.values(), "indirect jmp")
            at = {a: (mn, op) for a, _n, mn, op in ins}
            build, niche, merge, store = lo + 0x215, lo + 0x1FF, lo + 0x2AE, lo + 0x2DA
            self.assertEqual(at[build], ("lea", "rax,[rsp+0x7]"))
            self.assertEqual(at[niche], ("movabs", "r12,0x8000000000000000"))
            self.assertEqual(at[store], ("mov", "QWORD PTR [rbx+0x48],r12"))
            # build branch: entered only by the gate's je and the ja fall-through
            self.assertEqual(preds[build], {lo + 0x1FD, lo + 0x213})
            self.assertEqual({(a, t) for a, ss in succ.items() for t in ss
                              if build < t < merge and not build <= a < merge}, set())
            self.assertEqual(preds[merge], {lo + 0x209, lo + 0x29E, lo + 0x2A8})
            # every path to the [rbx+0x48] store passes the niche or the build branch.
            # Roots: the entry plus every non-padding instruction without a direct
            # predecessor (the landing pads, entered by unwinding).
            pads = {a for a, _n, mn, op in ins if not preds[a] and a != lo and "nop" not in mn + op}
            self.assertEqual(sorted(a - lo for a in pads), [0x3DB, 0x3E0, 0x402, 0x407])
            roots = {lo} | pads
            self.assertIn(store, reachable(succ, roots))
            self.assertNotIn(store, reachable(succ, roots, {niche, build}))
            # every path to the gate passes one of the three [rsp+0xc] stores
            gate = lo + 0x1C9
            stores = {a for a, _n, mn, op in ins if mn == "mov" and op == "DWORD PTR [rsp+0xc],eax"}
            self.assertEqual(len(stores), 3)
            self.assertNotIn(gate, reachable(succ, roots, stores))
            # rbp / r14 writes
            self.assertEqual([(a - lo, mn, op) for a, _n, mn, op in ins
                              if mn not in ("push", "cmp", "test", "bt") and writes(op, ("rbp", "ebp", "bp", "bpl"))],
                             [(0x1D, "xor", "ebp,ebp"), (0x62, "mov", "bpl,0x1"), (0x308, "pop", "rbp"),
                              (0x322, "mov", "bpl,0x2")])
            self.assertEqual(at[lo + 0x309], ("ret", ""))   # the pop rbp is the epilogue
            r14_writes = [a for a, _n, mn, op in ins
                          if mn not in ("push", "cmp", "test") and writes(op, ("r14", "r14d", "r14b"))]
            self.assertEqual([a - lo for a in r14_writes], [0x11, 0x1C9, 0x24B, 0x304])
            self.assertEqual(at[lo + 0x11], ("mov", "r14d,esi"))
            # the three family leas read r14 = the code: none is reachable from a later r14 write
            after_later = reachable(succ, {t for w in r14_writes[1:] for t in succ[w]})
            for site in (lo + 0x3A, lo + 0xB0, lo + 0x314):
                self.assertEqual(at[site], ("lea", "eax,[r14-0x15]"))
                self.assertIn(site, reachable(succ, {lo}))
                self.assertNotIn(site, after_later)
            # bucket per arm: PRIMARY bt jae -> AUX test; AUX bt jae -> else arm
            self.assertEqual(at[lo + 0x2E], ("jae", f"{lo + 0x53:x}"))
            self.assertEqual(at[lo + 0x5C], ("jae", f"{lo + 0x30A:x}"))
            key, xor, bpl1, bpl2 = lo + 0x11D, lo + 0x1D, lo + 0x62, lo + 0x322
            self.assertEqual(at[key], ("movzx", "edx,bpl"))
            primary_arm, aux_arm, else_arm = lo + 0x30, lo + 0x62, lo + 0x30A
            # PRIMARY set: no bpl write after the entry xor on any path to the key
            from_primary = reachable(succ, {primary_arm})
            self.assertIn(key, from_primary)
            self.assertFalse({xor, bpl1, bpl2} & from_primary)
            # AUX set: starts at mov bpl,1; neither other write follows
            from_aux = reachable(succ, {aux_arm})
            self.assertIn(key, from_aux)
            self.assertFalse({xor, bpl2} & from_aux)
            # else: mov bpl,2 lies on every path from the arm to the key; no other write
            from_else = reachable(succ, {else_arm})
            self.assertIn(key, from_else)
            self.assertNotIn(key, reachable(succ, {else_arm}, {bpl2}))
            self.assertFalse({xor, bpl1} & from_else)
        for k, b in enumerate(bodies[1:], 1):
            self.assertEqual(b, bodies[0], f"wrapper {WRAPPERS[k][0]:#x} differs after normalisation")

    @unittest.skipUnless(gnu("objdump"), "GNU objdump missing")
    def test_objdump_db_home_bucket_values(self):
        # copy 1 (0x332eba0): the formatted byte is the constant 2, and the function
        # writes "EvmState" (0x20af38, len 8) itself.
        ins = listing(0x332EBA0, 0x332EDBB)
        at = {a: (mn, op) for a, _n, mn, op in ins}
        self.assertEqual([a for a, _n, _m, op in ins if "[rsp+0x7]" in op],
                         [0x332EC1E, 0x332ED2A])
        self.assertEqual(at[0x332EC1E], ("mov", "BYTE PTR [rsp+0x7],0x2"))
        self.assertEqual(at[0x332EC51][0], "lea")
        self.assertRegex(at[0x332EC51][1], r"^rsi,\[rip\+0x[0-9a-f]+\]\s+# 20af38$")
        self.assertEqual(at[0x332EC5D], ("mov", "edx,0x8"))
        # copy 2 (0x459b500): the formatted byte comes from a 2-byte array {0, 1}
        ins = listing(0x459B500, 0x459C2AA)
        succ, preds = cfg(ins)
        live = reachable(succ, {0x459B500})
        at = {a: (mn, op) for a, _n, mn, op in ins}
        self.assertEqual([a for a, _n, _m, op in ins if "0x1a0]" in op or "0x1a1]" in op],
                         [0x459B583, 0x459B5F5])
        self.assertEqual(at[0x459B583], ("mov", "WORD PTR [rsp+0x1a0],0x100"))
        self.assertEqual(at[0x459B5F5], ("movzx", "eax,BYTE PTR [rsp+rax*1+0x1a0]"))
        self.assertEqual([a for a, _n, _m, op in ins if "[rsp+0xe]" in op], [0x459B5FD, 0x459C170])
        # the array read is entered from the index-0 jmp and the index-1 back-edge only
        self.assertEqual(preds[0x459B5F5] & live, {0x459B5D6, 0x459B5EF})
        self.assertEqual(at[0x459B5CF], ("xor", "eax,eax"))
        self.assertEqual(at[0x459B5E0], ("mov", "eax,0x1"))
        self.assertEqual(preds[0x459B5E0] & live, {0x459C0CC, 0x459C0DD})

    @unittest.skipUnless(gnu("objdump"), "GNU objdump missing")
    def test_objdump_template_walker_rules(self):
        # the capacity pass of 0x1344760 whose rules _walk_template mirrors
        ins = listing(0x13447A0, 0x1344813)
        self.assertEqual([(mn, op) for _a, _n, mn, op in ins], [
            # 0x13447a0: bit7-clear byte = literal length: skip that many bytes
            ("movzx", "edx,dl"), ("add", "r12,rdx"), ("add", "rcx,rdx"),
            # 0x13447a9: next byte; 0x00 ends the template
            ("movzx", "edx,BYTE PTR [rcx]"), ("test", "dl,dl"), ("je", "134481b"),
            ("inc", "rcx"), ("test", "dl,dl"), ("jns", "13447a0"),
            # bit 7 set: neg overflows only for 0x80 -> u16 literal length
            ("mov", "esi,edx"), ("neg", "sil"), ("jno", "13447cd"),
            ("movzx", "edx,WORD PTR [rcx]"), ("add", "r12,rdx"), ("add", "rcx,rdx"),
            ("add", "rcx,0x2"), ("jmp", "13447a9"),
            # 0x13447cd: other bit-7 bytes = argument slot: flag 'argument before any
            # literal', then skip 4*b0 + 2*b1 + 2*b2 + 2*b3 option bytes
            ("test", "r12,r12"), ("sete", "sil"), ("or", "al,sil"), ("mov", "esi,edx"),
            ("shl", "sil,0x7"), ("mov", "edi,edx"), ("shl", "dil,0x5"), ("and", "dil,0x40"),
            ("or", "dil,sil"), ("shr", "dil,0x5"), ("movzx", "esi,dil"), ("mov", "edi,edx"),
            ("shr", "dil,1"), ("and", "dil,0x2"), ("movzx", "edi,dil"), ("shr", "dl,0x2"),
            ("and", "dl,0x2"), ("movzx", "edx,dl"), ("add", "rcx,rdi"), ("add", "rcx,rdx"),
            ("add", "rcx,rsi"), ("jmp", "13447a9")])

    @unittest.skipUnless(gnu("objdump"), "GNU objdump missing")
    def test_text_census_counts(self):
        # Instruction-aligned census over the whole of .text: exact totals and
        # in-wrapper hits for the nine shapes, and the inline tag-shaped immediates.
        def inw(a):
            return any(lo <= a < hi for lo, hi in WRAPPERS)

        rxs = {k: re.compile(r"\t" + k + r"$") for k in CENSUS}
        total, inside = Counter(), Counter()
        tagimm = {int.from_bytes(t.encode(), "little"): t for t in TAGS}
        mov_w = re.compile(r"\tmov    WORD PTR \[[^\]]*\],0x([0-9a-f]+)$")
        cmp_w = re.compile(r"\tcmp    WORD PTR \[[^\]]*\],0x([0-9a-f]+)$")
        movs, cmps, n = Counter(), Counter(), 0
        tag_inside = 0
        p = subprocess.Popen(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", "-j", ".text", str(BIN)],
                             stdout=subprocess.PIPE, text=True, bufsize=1 << 20)
        try:
            for line in p.stdout:
                if line[:1] != " " or ":\t" not in line:
                    continue
                try:
                    a = int(line[:line.index(":")], 16)
                except ValueError:
                    continue
                n += 1
                for k, rx in rxs.items():
                    if rx.search(line):
                        total[k] += 1
                        inside[k] += inw(a)
                        break
                for rx, ctr in ((mov_w, movs), (cmp_w, cmps)):
                    m = rx.search(line)
                    if m and int(m.group(1), 16) in tagimm:
                        ctr[tagimm[int(m.group(1), 16)]] += 1
                        tag_inside += inw(a)
        finally:
            p.stdout.close()
            p.wait()
        self.assertEqual(n, TEXT_INSTRUCTIONS)
        self.assertEqual(dict(total), CENSUS)
        self.assertEqual(dict(inside), {k: 6 for k in CENSUS})
        self.assertEqual(dict(movs), {"ts": 10, "et": 9, "de": 3})
        self.assertEqual(dict(cmps), {"Ea": 4, "Eb": 4, "Ec": 4, "oh": 5})
        self.assertEqual(tag_inside, 0)


class DbCodeTableOfflineTests(unittest.TestCase):
    """Run with or without the pinned binary present."""

    def test_missing_binary_exits_two(self):
        p = subprocess.run([sys.executable, "-B", str(ROOT / "tools/db_code_table.py"),
                            "--binary", str(ROOT / "artifacts/node/94/does-not-exist")],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("cannot read", p.stderr)

    def test_digest_guard_rejects_wrong_bytes(self):
        with self.assertRaises(dct.EvidenceError):
            dct.build(b"\x7fELF\x02\x01" + b"\x00" * 120)  # default expected sha256 -> mismatch

    def test_non_elf_rejected_even_with_matching_digest(self):
        blob = b"not an elf at all" * 4
        with self.assertRaises(dct.EvidenceError):
            dct.build(blob, expected_sha256=hashlib.sha256(blob).hexdigest())

    def test_template_walker_rules(self):
        # synthetic bytes, no binary: literal / u16 literal / argument + option bytes / end
        class Fake:
            def __init__(self, b):
                self.b = b + b"\x00" * dct.TEMPLATE_LIMIT

            def read(self, va, n):
                return self.b[va:va + n]

        pieces, raw = dct._walk_template(Fake(b"\x04dhs/\xc0\x00"), 0)
        self.assertEqual((pieces, raw), (["dhs/", None], b"\x04dhs/\xc0\x00"))
        pieces, _ = dct._walk_template(Fake(b"\x80\x03\x00abc\xc1XXXX\xcf" + b"Y" * 10 + b"\x00"), 0)
        self.assertEqual(pieces, ["abc", None, None])
        with self.assertRaises(dct.EvidenceError):
            dct._walk_template(Fake(b"\x02\x01\x02\x00"), 0)        # non-printable literal


if __name__ == "__main__":
    unittest.main()
