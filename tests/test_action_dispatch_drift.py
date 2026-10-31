"""RE-014 tests: pinned output, determinism, wrong-binary, tamper and unit controls, binutils cross-checks."""
import bisect
import copy
import contextlib
import hashlib
import importlib.util
import io
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
spec = importlib.util.spec_from_file_location("action_dispatch_drift", ROOT / "tools/action_dispatch_drift.py")
ad = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ad)
PACKET = ROOT / "research/work-items/RE-014-action-dispatch-drift"
OUTPUT_SHA256 = "fc00a6b751588761dbca7d4cbc2e887e815d912442a2a3d48ec15c802fa6a75d"
_CACHE = {}


def _is_elf(p):
    try:
        with open(p, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


HAVE_BINARIES = _is_elf(ad.TARGET) and _is_elf(ad.TARGET_115)


def gnu(tool):
    path = shutil.which(tool)
    if not path:
        return None
    try:
        v = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return path if v.startswith(f"GNU {tool}") else None


OBJDUMP, READELF = gnu("objdump"), gnu("readelf")


def data(rel):
    if rel not in _CACHE:
        _CACHE[rel] = (ad.TARGET if rel == "94" else ad.TARGET_115).read_bytes()
    return _CACHE[rel]


def profile(rel):
    return ad.PROFILE_94 if rel == "94" else ad.PROFILE_115


def analyzed(rel):
    """analyze() of the pinned binary; shared by the tests, which must not modify it."""
    if ("t", rel) not in _CACHE:
        _CACHE[("t", rel)] = ad.analyze(data(rel), profile(rel), hashlib.sha256(data(rel)).hexdigest())
    return _CACHE[("t", rel)]


def result():
    if "result" not in _CACHE:
        _CACHE["result"] = ad.combine(analyzed("94"), analyzed("115"))
        _CACHE["text"] = ad.render(_CACHE["result"])
    return _CACHE["result"]


def text():
    result()
    return _CACHE["text"]


def ctx(rel):
    return analyzed(rel)["_ctx"]


def tgt(rel):
    return result()["targets"][rel]


def inst(rel, n=0):
    return tgt(rel)["execute_instances"][n]


def row(name):
    return next(r for r in result()["variant_join"] if r["name"] == name)


def anchor(rel, path):
    return next(a for a in tgt(rel)["anchors"] if a["path"] == path)


def qual(path):
    return next(q for q in result()["catalogue_paths"] if q["path"] == path)


def patch(rel, va, new, buf=None):
    buf = bytearray(data(rel) if buf is None else buf)
    o = ctx(rel).elf.off(va)
    buf[o:o + len(new)] = new
    return bytes(buf)


def rel32_to(rel, site, field, target):
    """Bytes for the rel32 at site+field so that the instruction at site (ending at site+field+4) reaches target."""
    return struct.pack("<i", target - (site + field + 4))


def rebuild(rel, buf, **kw):
    """combine() with one mutated release, its own digest accepted (tamper controls)."""
    t = ad.analyze(buf, profile(rel), hashlib.sha256(buf).hexdigest())
    return ad.combine(t, analyzed("115"), **kw) if rel == "94" else ad.combine(analyzed("94"), t, **kw)


def rela_entries(rel):
    """r_offset -> file offset of its .rela.dyn entry."""
    key = ("rela", rel)
    if key not in _CACHE:
        _va, off, size = ctx(rel).elf.sections[".rela.dyn"]
        d = data(rel)
        _CACHE[key] = {struct.unpack_from("<Q", d, o)[0]: o for o in range(off, off + size, 24)}
    return _CACHE[key]


def set_str_slot(rel, buf, slot, addend, length):
    """Point the RELATIVE &str slot at (addend, length) in a copy of the binary."""
    buf = bytearray(buf)
    e = rela_entries(rel)[slot]
    buf[e + 16:e + 24] = struct.pack("<q", addend)
    o = ctx(rel).elf.off(slot + 8)
    buf[o:o + 8] = struct.pack("<Q", length)
    return bytes(buf)


def objdump_rows(rel, lo, hi):
    out = subprocess.run([OBJDUMP, "-d", "-M", "intel", "--no-show-raw-insn", f"--start-address={lo:#x}",
                          f"--stop-address={hi:#x}", str(ad.TARGET if rel == "94" else ad.TARGET_115)],
                         check=True, capture_output=True, text=True).stdout
    rows = {}
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t(\S+)\s*(.*)$", line)
        if m:
            rows[int(m.group(1), 16)] = (m.group(2), re.sub(r"\s*<[^>]*>", "", m.group(3)).strip())
    return rows


class FakeElf:
    def __init__(self, mem):
        self.mem = mem          # {va: bytes}

    def read(self, va, n):
        for base, b in self.mem.items():
            if base <= va < base + len(b):
                return b[va - base:va - base + n]
        raise ad.EvidenceError(f"{va:#x} not file-backed")


def fake_ctx(mem, relocs=None, sec=None):
    c = object.__new__(ad.Ctx)
    c.elf = FakeElf(mem)
    c.relocs = relocs or {}
    c.starts, c.ends, c.leas, c.transfers = [], [], {}, {}
    c.sec = sec or {".text": (0x1000, 0, 0x1000), ".rodata": (0x2000, 0, 0x1000), ".data.rel.ro": (0x3000, 0, 0x100)}
    return c


@unittest.skipUnless(HAVE_BINARIES, "pinned #94/#115 binaries not present")
class Pinned(unittest.TestCase):
    def test_output_hash_and_packet_json(self):
        self.assertEqual(hashlib.sha256(text()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "action-dispatch-drift.json").read_bytes(), text())

    def test_variants_tables(self):
        for rel, n, starts, bounds in (
                ("94", 88, [0x56C46E0, 0x56E8BD0, 0x5733130], [0x56C4C60, 0x56E9150, 0x57336B0]),
                ("115", 92, [0x644CC40, 0x6467F98, 0x649BAC8], [0x644D200, 0x6468558, 0x649C088])):
            v = tgt(rel)["variants"]
            self.assertEqual(v["count"], n)
            self.assertEqual([c["start"] for c in v["copies"]], starts)
            self.assertEqual([c["bound_slot"] for c in v["copies"]], bounds)
            self.assertEqual({c["bound_text"] for c in v["copies"]}, {f"variant index 0 <= i < {n}"})
            self.assertEqual([c["bound_slot"] - c["start"] for c in v["copies"]], [16 * n] * 3)
            self.assertEqual(v["names"][:3], ["noop", "approveAgent", "batchModify"])
            self.assertEqual(v["default_index_name"], "VoteGlobalAction")
            # distinct arrays, but 15 slots point at the same string in all three copies
            self.assertEqual(v["pairwise_equal_ptr_counts"], [[n, 15, 15], [15, n, 15], [15, 15, n]])
            self.assertEqual(len(v["slots_with_ptr_shared_by_all_copies"]), 15)
            self.assertIn(62, v["slots_with_ptr_shared_by_all_copies"])      # cDeposit is shared
            self.assertNotIn(1, v["slots_with_ptr_shared_by_all_copies"])    # approveAgent is not
        self.assertEqual(tgt("94")["variants"]["names"][-1], "voteL1Hash")
        self.assertEqual(tgt("115")["variants"]["names"][-2:], ["outcomeDeploy", "cDeposit2"])

    def test_join(self):
        c = result()["variant_join_counts"]
        self.assertEqual((c["names_94"], c["names_115"], c["common"], c["same_index"], c["shifted"]),
                         (88, 92, 86, 46, 40))
        self.assertEqual(c["shift_histogram"], {"+1": 25, "-1": 15})
        self.assertEqual(c["rust_ident_changed_common"], 0)
        rows = result()["variant_join"]
        self.assertEqual([(r["name"], r["index_94"]) for r in rows if r["class"] == "removed"],
                         [("voteAppHash", 48), ("SystemAlignedQuoteSupplyDeltaAction", 72)])
        self.assertEqual([(r["name"], r["index_115"]) for r in rows if r["class"] == "added"],
                         [("validatorL1Status", 23), ("voteAbciDigest", 87), ("activateOutcomeDeployer", 88),
                          ("trailingStop", 89), ("outcomeDeploy", 90), ("cDeposit2", 91)])
        self.assertEqual(row("vaultTransfer")["index_delta"], 1)
        self.assertEqual(row("userOutcome")["index_delta"], -1)

    def test_idiom_survey(self):
        for rel, counts in (
                ("94", {"bias_block_occurrences": 59, "bias_block_occurrences_dispatcher_register_form": 34,
                        "cmov:cmovae": 51, "cmov:cmovb": 8, "direct_tables_with_entry_n_in_function": 7,
                        "n_entry_tables": 33, "n_entry_tables_with_entry_n_in_function": 18,
                        "role:execute": 3, "role:no_table": 4, "role:other": 41, "role:serializer": 11,
                        "shape:after_bounds_check": 22, "shape:after_gap": 18, "shape:direct": 14,
                        "shape:direct_with_stores": 1, "shape:no_table": 4}),
                ("115", {"bias_block_occurrences": 68, "bias_block_occurrences_dispatcher_register_form": 26,
                         "cmov:cmovae": 56, "cmov:cmovb": 12, "direct_tables_with_entry_n_in_function": 11,
                         "n_entry_tables": 38, "n_entry_tables_with_entry_n_in_function": 20,
                         "role:execute": 3, "role:no_table": 6, "role:other": 45, "role:sentinel_other_base": 3,
                         "role:serializer": 11, "shape:after_bounds_check": 24, "shape:after_gap": 19,
                         "shape:direct": 19, "shape:no_table": 6})):
            self.assertEqual(tgt(rel)["idiom_site_counts"], counts)
        # the inverted cmov (cmovb I,D with D = 0x14): consecutive sites, their tables and distinct targets
        for rel, want in (
                ("94", [(0x282EEA4, "tag rax, index r8, default rax, cmovb", "direct", 0x3F2C78, 18),
                        (0x335ECD3, "tag rax, index rsi, default rcx, cmovb", "after_gap", 0x588A7C, 4),
                        (0x3360AB3, "tag rax, index rsi, default rcx, cmovb", "after_gap", 0x588E9C, 7),
                        (0x3362E64, "tag rax, index r8, default rax, cmovb", "direct", 0x5892BC, 7),
                        (0x3362F37, "tag rax, index rsi, default rcx, cmovb", "after_gap", 0x58941C, 5),
                        (0x3363373, "tag rax, index rsi, default rcx, cmovb", "after_gap", 0x58983C, 3),
                        (0x48F58A4, "tag rax, index r8, default rax, cmovb", "direct", 0x6FFEE4, 18),
                        (0x48F5A34, "tag rax, index r8, default rax, cmovb", "direct", 0x700044, 18)]),
                ("115", [(0x2BDB5B8, "tag r8, index r8, default rax, cmovb", "direct", 0x60A080, 36),
                         (0x2BDB924, "tag r8, index r8, default rax, cmovb", "direct", 0x60A1F0, 19),
                         (0x36C2FA3, "tag rsi, index rsi, default rcx, cmovb", "after_gap", 0x79AB60, 4),
                         (0x36C3034, "tag r8, index r8, default rax, cmovb", "direct", 0x79AE40, 8),
                         (0x36C30F3, "tag rsi, index rsi, default rcx, cmovb", "after_gap", 0x79AFB0, 7),
                         (0x36C5687, "tag rsi, index rsi, default rcx, cmovb", "after_gap", 0x79B400, 5),
                         (0x36C5B03, "tag rsi, index rsi, default rcx, cmovb", "after_gap", 0x79B850, 3),
                         (0x3D985E2, "tag rax, index rax, default rcx, cmovb", None, None, None),
                         (0x4D90BA4, "tag r8, index r8, default rax, cmovb", "direct", 0x914EB8, 19),
                         (0x4D90D44, "tag r8, index r8, default rax, cmovb", "direct", 0x915028, 19),
                         (0x4E0FD1C, "tag r8, index r8, default rax, cmovb", "direct", 0x915B34, 36),
                         (0x4E1008C, "tag r8, index r8, default rax, cmovb", "direct", 0x915CA4, 36)])):
            n = tgt(rel)["variants"]["count"]
            got = [s for s in tgt(rel)["idiom_sites"] if s["cmov"] == "cmovb"]
            self.assertEqual([(s["site"], s["registers"], s.get("shape"), s.get("table"), s.get("distinct_entries"))
                              for s in got], want)
            for s in got:
                self.assertEqual(s["role"], "other" if s["kind"] == "jump_table" else "no_table")
                if s["kind"] == "jump_table":
                    self.assertEqual((s["entries_read"], s["entries_in_function"], s["index_register"]),
                                     (n, n, s["tag_register"] if rel == "115" else s["temp_register"]))
        self.assertIn("is not a single bounds check followed by ja",
                      next(s for s in tgt("115")["idiom_sites"] if s["site"] == 0x3D985E2)["stop"])
        # the bias directly followed by the cmov, its default register not loaded in the matched bytes
        for rel, sites in (("94", [0x282EECD, 0x335ED07, 0x3360AE7, 0x3362E8D, 0x3362F67, 0x33633A7, 0x3994E61,
                                   0x45487A1, 0x48F58CD, 0x48F5A5D]),
                           ("115", [0x2BDB5E0, 0x2BDB94C, 0x36C2FD7, 0x36C305C, 0x36C3127, 0x36C56B7, 0x36C5B37,
                                    0x3C3D203, 0x3D9858A, 0x4D90BCC, 0x4D90D6C, 0x4E0FD48, 0x4E100B8, 0x57BC1E1])):
            de = tgt(rel)["idiom_default_elsewhere"]
            self.assertEqual(([r["site"] for r in de["sites"]], de["count"], de["cmov_counts"]),
                             (sites, len(sites), {"cmovb": len(sites)}))
            surveyed = {s["site"] for s in tgt(rel)["idiom_sites"]}
            self.assertFalse(surveyed & set(sites))
        self.assertEqual(next(r for r in tgt("94")["idiom_default_elsewhere"]["sites"] if r["site"] == 0x282EECD)
                         ["registers"], "tag r8, index r9, default rax, cmovb")
        # the dispatchers' register allocation alone (the first survey's denominator)
        self.assertEqual(tgt("94")["idiom_register_forms"]["tag rax, index rax, temp rcx"], {
            "dispatcher_register_form": True, "sites": 34, "role:execute": 3, "role:no_table": 2, "role:other": 18,
            "role:serializer": 11, "shape:after_bounds_check": 12, "shape:after_gap": 9, "shape:direct": 10,
            "shape:direct_with_stores": 1, "shape:no_table": 2})
        self.assertEqual(tgt("115")["idiom_register_forms"]["tag rax, index rcx"], {
            "dispatcher_register_form": True, "sites": 26, "role:execute": 3, "role:no_table": 2, "role:other": 7,
            "role:sentinel_other_base": 3, "role:serializer": 11, "shape:after_gap": 12, "shape:direct": 12,
            "shape:no_table": 2})
        self.assertEqual({k: v["sites"] for k, v in tgt("94")["idiom_register_forms"].items()}, {
            "tag rax, index rax, temp r9": 1, "tag rax, index rax, temp rcx": 34, "tag rax, index rax, temp rdi": 2,
            "tag rax, index rax, temp rdx": 2, "tag rax, index rcx, temp rdx": 10, "tag rax, index rdx, temp rcx": 1,
            "tag rdi, index rdi, temp r8": 1, "tag rax, index r8, default rax, cmovb": 4,
            "tag rax, index rsi, default rcx, cmovb": 4})
        self.assertEqual({k: v["sites"] for k, v in tgt("115")["idiom_register_forms"].items()}, {
            "tag rax, index r9": 2, "tag rax, index rcx": 26, "tag rax, index rdi": 1, "tag rcx, index rax": 25,
            "tag rdx, index rcx": 2, "tag r8, index r8, default rax, cmovb": 7,
            "tag rax, index rax, default rcx, cmovb": 1, "tag rsi, index rsi, default rcx, cmovb": 4})
        s94 = {s["site"]: s for s in tgt("94")["idiom_sites"]}
        self.assertEqual([k for k, s in s94.items() if s["kind"] == "no_table"],
                         [0x1E8E041, 0x335ECB3, 0x4C5C362, 0x4C5CAF2])
        b = s94[0x16EF79E]          # dec rax; cmp rax,0x52; ja; mov rbx,rdi; table of 0x53 entries
        self.assertEqual((b["shape"], b["index_decrements"], b["bounds_check"]["cmp_imm"], b["entries_read"],
                          b["table"], b["gap_sites"]), ("after_bounds_check", 1, 0x52, 83, 0x294A50,
                                                        [0x16EF7AF, 0x16EF7B2, 0x16EF7B6, 0x16EF7BC]))
        b = s94[0x1D3FEEE]          # another register allocation: index rcx, the same 0x53-entry bounded shape
        self.assertEqual((b["registers"], b["shape"], b["bounds_check"]["cmp_imm"], b["entries_read"], b["table"],
                          b["dispatcher_register_form"]),
                         ("tag rax, index rcx, temp rdx", "after_bounds_check", 0x52, 83, 0x3BB710, False))
        g = s94[0x281E858]          # one 'mov rbx,rdi' before the table
        self.assertEqual((g["shape"], g["gap_sites"], g["table"], g["role"]),
                         ("after_gap", [0x281E869], 0x3F2244, "serializer"))
        self.assertEqual(s94[0x3341EB8]["shape"], "direct_with_stores")
        for site, table, gap in ((0x335EDDE, 0x588D3C, 0x335EDEF), (0x3360B5F, 0x588FFC, 0x3360B70)):
            x = s94[site]           # 'mov r13/r14,QWORD PTR [rsp+d32]' before an 88-way table that is no serializer
            self.assertEqual((x["registers"], x["gap_sites"], x["table"], x["distinct_entries"], x["role"],
                              x["arms_storing_variant_name"]), ("tag rax, index rax, temp rdi", [gap], table, 88,
                                                                "other", 0))
        self.assertEqual((s94[0x333FCC7]["gap_sites"], s94[0x333FCC7]["table"]), ([0x333FCD8], 0x587A3C))
        s115 = {s["site"]: s for s in tgt("115")["idiom_sites"]}
        self.assertEqual([k for k, s in s115.items() if s["kind"] == "no_table"],
                         [0x2D3D5AD, 0x36B1573, 0x36C2033, 0x3D985E2, 0x59219F7, 0x5922397])
        self.assertEqual(s115[0x36C3003]["table_regs"], "base rdx, dest rcx, index rcx")
        b = s115[0x189F8BE]         # bounded tables exist in #115 too: dec rax; cmp rax,0x59; ja; 0x5a entries
        self.assertEqual((b["registers"], b["shape"], b["bounds_check"]["cmp_imm"], b["entries_read"], b["table"]),
                         ("tag rcx, index rax", "after_bounds_check", 0x59, 90, 0x4B05B8))
        x = s115[0x36C319F]
        self.assertEqual((x["registers"], x["table"], x["distinct_entries"], x["role"], x["arms_storing_variant_name"]),
                         ("tag rax, index rdi", 0x79B120, 92, "other", 0))
        for rel in ("94", "115"):
            for s in tgt(rel)["idiom_sites"]:
                self.assertEqual(s["dispatcher_register_form"],
                                 bytes.fromhex(tgt(rel)["profile"]["bias_block_hex"])
                                 == ctx(rel).elf.read(s["site"], s["idiom_length"]), hex(s["site"]))
        for rel in ("94", "115"):
            n = tgt(rel)["variants"]["count"]
            for s in tgt(rel)["idiom_sites"]:
                if s["role"] in ("execute", "serializer", "sentinel_other_base"):
                    self.assertEqual((s["entries_read"], s["entries_in_function"], s["distinct_entries"],
                                      s["bounds_check"], s["index_decrements"]), (n, n, n, None, 0), hex(s["site"]))

    def test_serializers(self):
        for rel, base0, base8 in (
                ("94", [0x2821000, 0x2825C00, 0x334F770, 0x48E3B50, 0x48EAF00],
                 [0x281E850, 0x2823450, 0x334CFA0, 0x3351BC0, 0x48E5FA0, 0x48E8750]),
                ("115", [0x2BC95F0, 0x2BD0EF0, 0x36AEF70, 0x4D81E00, 0x4D89700],
                 [0x2BCBBF0, 0x2BCE570, 0x36B1600, 0x36B3F80, 0x4D84400, 0x4D86D80])):
            t = tgt(rel)
            n = t["variants"]["count"]
            got = {s["function"]: s for s in t["serializers"]}
            self.assertEqual(sorted(got), sorted(base0 + base8))
            self.assertEqual([f for f in sorted(got) if got[f]["stack_base"] == 0], base0)
            self.assertEqual([f for f in sorted(got) if got[f]["stack_base"] == 8], base8)
            c0, c1, c2 = (c["start"] for c in t["variants"]["copies"])
            copies = [got[f]["name_ptrs_equal_variants_copies"] for f in sorted(got)]
            self.assertEqual(copies, [[c0]] * 4 + [[c1]] * 3 + [[c2]] * 4)        # each matches one copy
            for s in t["serializers"]:
                self.assertEqual(s["arms_storing_variant_name"], n)
                self.assertEqual(s["name_offset"], s["stack_base"] + 0x30)
                self.assertEqual(sorted(s["name_ptr_matches_per_copy"]), [15, 15, n])
                self.assertTrue(s["rust_idents_equal_first_serializer"])
                self.assertEqual((s["type_idents"], s["tag_strs"]), (["Action"], ["type"]))
            cen = t["census"]["tables"]
            self.assertEqual(cen["serializer_functions"], sorted(got))
            self.assertTrue(cen["serializers_equal_idiom_serializers"])
        self.assertEqual((tgt("94")["census"]["tables"]["n_way_tables"],
                          tgt("115")["census"]["tables"]["n_way_tables"]), (79, 85))
        i94, i115 = tgt("94")["rust_idents"], tgt("115")["rust_idents"]
        self.assertEqual([i94[k] for k in (1, 37, 38, 68, 75)],
                         ["ApproveAgent3", "TopUpStrictIsolatedMargin", "UpdateUserLeverage", "Hip3Deploy", "Bole"])
        self.assertEqual(i115[89:], ["TrailingStopOrder", "OutcomeDeploy", "CDeposit2"])

    def test_execute_instances(self):
        for rel, rows in (("94", [(0x2759240, 0x275A376, 0x3EDE28, False), (0x4D83050, 0x4D84164, 0x712DFC, False),
                                  (0x4D84170, 0x4D85284, 0x712F5C, False)]),
                          ("115", [(0x2BDBAA0, 0x2BDCB65, 0x60A360, False), (0x55F99B0, 0x55FAA79, 0x927B08, True),
                                   (0x55FAA80, 0x55FBB49, 0x927C78, False)])):
            got = [(i["start"], i["end"], i["table"], i["entry_n_in_function"]) for i in tgt(rel)["execute_instances"]]
            self.assertEqual(got, rows)
            self.assertEqual({i["tag_base"] for i in tgt(rel)["execute_instances"]}, {"r12"})
            self.assertEqual({i["tag_register"] for i in tgt(rel)["execute_instances"]
                              + tgt(rel)["sentinel_other_base_instances"]}, {"rax"})
            self.assertEqual([i["unresolved_indices"] for i in tgt(rel)["execute_instances"]], [[], [], []])
        self.assertEqual([i["extended_decoder_indices"] for i in tgt("94")["execute_instances"]], [[], [], []])
        self.assertEqual([i["extended_decoder_indices"] for i in tgt("115")["execute_instances"]], [[], [52], [52]])
        for n in range(3):
            self.assertEqual(inst("94", n)["via_counts"], {"call": 84, "entry_branch": 1, "none": 1, "slot_call": 2})
            self.assertEqual(inst("115", n)["via_counts"], {"call": 87, "entry_branch": 1, "none": 1,
                                                            "shared_arm_tail": 1, "slot_call": 2})
        a = inst("115", 1)["arms"][52]
        self.assertEqual((a["arm"], a["path_end"]["site"], a["resolution"]["handler"],
                          a["extended_decoder"]["encodings"]), (0x55FA72E, 0x55FA757, 0x55F99B0, ["0f4x", "31", "3d"]))
        self.assertIn("unsupported opcode 3d at 0x55fa739", a["extended_decoder"]["strict_error"])
        d94, d115 = tgt("94")["handler_distinctness"]["execute"], tgt("115")["handler_distinctness"]["execute"]
        self.assertEqual((d94["arms_resolved_in_all_instances"], d94["arms_with_pairwise_distinct_handlers"]), (87, 84))
        self.assertEqual((d115["arms_resolved_in_all_instances"], d115["arms_with_pairwise_distinct_handlers"]),
                         (91, 88))
        for d in (d94, d115):
            self.assertEqual([x["name"] for x in d["exceptions"]],
                             ["RegisterValidatorAction", "ValidatorSignWithdrawalAction", "cUserModify"])
        self.assertEqual(tgt("94")["instance_size_spread"],
                         {"arms_with_all_instance_sizes": 87, "arms_with_differing_instance_sizes": 23})
        self.assertEqual(tgt("115")["instance_size_spread"],
                         {"arms_with_all_instance_sizes": 91, "arms_with_differing_instance_sizes": 29})

    def test_sentinel_other_base_family(self):
        self.assertEqual(tgt("94")["sentinel_other_base_instances"], [])
        fam = tgt("115")["sentinel_other_base_instances"]
        self.assertEqual([(i["start"], i["end"], i["table"], i["tag_base"]) for i in fam],
                         [(0x2BDA7C0, 0x2BDB225, 0x609F00, "r15"), (0x54A2F90, 0x54A39F8, 0x92671C, "r15"),
                          (0x54A3A00, 0x54A4468, 0x92688C, "r15")])
        self.assertEqual([i["via_counts"] for i in fam], [{"call": 92}] * 3)
        d = tgt("115")["handler_distinctness"]["sentinel_other_base"]
        self.assertEqual((d["arms_resolved_in_all_instances"], d["arms_with_pairwise_distinct_handlers"]), (92, 92))
        rel = tgt("115")["sentinel_other_base_relation"]
        self.assertEqual([r["handlers_shared_with_execute_family"] for r in rel], [0, 0, 0])
        self.assertEqual([r["arms_whose_handler_transfers_to_same_index_execute_handler"] for r in rel], [57, 60, 60])
        self.assertEqual([r["arms_whose_handler_transfers_to_same_index_execute_handler_rel32_only"] for r in rel],
                         [54, 57, 57])
        self.assertEqual([r["arms_same_index_only_through_rip_slot"] for r in rel], [[16, 41, 63]] * 3)
        self.assertEqual([r["arms_whose_handler_transfers_to_other_index_execute_handler"] for r in rel], [[], [], []])
        self.assertIn("not also a handler of arm K", tgt("115")["sentinel_other_base_relation_rule"])
        into = [[(x["index"], x["handler"], x["dispatcher"]) for x in r["handlers_transferring_to_execute_instance"]]
                for r in rel]
        self.assertEqual(into, [[(52, 0x2C12690, 0x2BDBAA0)], [(52, 0x551CB40, 0x55FAA80)],
                                [(52, 0x5536770, 0x55F99B0)]])
        self.assertEqual((fam[0]["arms"][62]["resolution"]["handler"], fam[0]["arms"][91]["resolution"]["handler"]),
                         (0x2C17820, 0x2C0F810))
        reach = {a["path"]: a for a in tgt("115")["sentinel_other_base_anchor_reach"]}
        self.assertEqual({p for p, a in reach.items() if a["holds_all_instances"]},
                         {"l1/action/user_outcome.rs", "l1/action/vault_transfer.rs", "l1/action/withdraw3.rs"})
        self.assertEqual(reach["l1/action/user_outcome.rs"]["depths"], [1])
        self.assertEqual(reach["l1/exchange/impl_outcome_deploy.rs"]["reached_names"], [])

    def test_dispatcher_references_and_sentinel_census(self):
        refs = {r["start"]: r for rel in ("94", "115") for r in tgt(rel)["dispatcher_references"]}
        for r in refs.values():
            self.assertEqual((r["reloc_slots"], r["lea_sites"]), ([], []))
        for start in (0x2759240, 0x4D83050, 0x4D84170, 0x2BDA7C0, 0x54A2F90, 0x54A3A00):
            outside = [s for s in refs[start]["rel32_sources"] if not s["arm_handler_of"]]
            self.assertEqual((len(outside), len({s["function"] for s in outside})), (5, 3), hex(start))
        for start, wrapper in ((0x2BDBAA0, 0x2C12690), (0x55F99B0, 0x5536770), (0x55FAA80, 0x551CB40)):
            src = refs[start]["rel32_sources"]
            self.assertEqual(sorted(s["function"] for s in src), sorted([start, wrapper]))
            w = next(s for s in src if s["function"] == wrapper)
            self.assertEqual([(x["family"], x["index"]) for x in w["arm_handler_of"]], [("sentinel_other_base", 52)])
        thunk = next(s for s in refs[0x2759240]["rel32_sources"] if s["function"] == 0x282EE50)
        self.assertEqual([(x["family"], x["instance"], x["index"]) for x in thunk["arm_handler_of"]],
                         [("execute", 0, 52)])
        for rel, occ, before in (("94", 12, 3), ("115", 15, 6)):
            s = tgt(rel)["census"]["sentinel"]
            self.assertEqual((s["occurrences"], s["before_tag_load_and_idiom"]), (occ, before))
        bases = sorted((x["function"], x["tag_load_then_idiom"]) for x in tgt("115")["census"]["sentinel"]["sites"]
                       if x["tag_load_then_idiom"])
        self.assertEqual(bases, [(0x2BDA7C0, "r15"), (0x2BDBAA0, "r12"), (0x54A2F90, "r15"), (0x54A3A00, "r15"),
                                 (0x55F99B0, "r12"), (0x55FAA80, "r12")])
        for rel in ("94", "115"):
            regs = {x["tag_register"] for x in tgt(rel)["census"]["sentinel"]["sites"] if x["tag_load_then_idiom"]}
            self.assertEqual(regs, {"rax"})

    def test_key_arms(self):
        r = row("cDeposit2")
        self.assertEqual(r["via_115"], ["shared_arm_tail"] * 3)
        self.assertEqual(r["handlers_115"], row("cDeposit")["handlers_115"])
        a = inst("115")["arms"][91]
        self.assertEqual((a["arm"], a["path_end"]["target"], a["resolution"]["shared_with_index"]),
                         (0x2BDBB82, 0x2BDC457, 62))
        self.assertEqual(row("cDeposit")["handlers_115"][0], 0x2C6BBF0)
        m = row("multiSig")
        self.assertEqual((m["handlers_94"][0], m["handler_sizes_94"][0], m["reenters_94"]),
                         (0x282EE50, 66, [True, True, True]))
        self.assertEqual((m["handlers_115"], m["handler_sizes_115"], m["reenters_115"], m["via_115"]),
                         ([0x2BDBAA0, 0x55F99B0, 0x55FAA80], [4293, 4297, 4297], [True] * 3, ["call"] * 3))
        self.assertEqual(m["extended_decoder_115"], [False, True, True])
        self.assertEqual(row("noop")["via_94"] + row("noop")["via_115"], ["none"] * 6)
        self.assertEqual(row("cUserModify")["via_94"][0], "entry_branch")
        self.assertEqual(row("voteAppHash")["handlers_94"][0], 0x1E5F5D0)
        self.assertEqual(row("SystemAlignedQuoteSupplyDeltaAction")["handlers_94"][0], 0x1E64AC0)
        self.assertEqual(row("validatorL1Status")["handlers_115"][0], 0x2B91050)
        self.assertEqual(row("outcomeDeploy")["handlers_115"][0], 0x283C2D0)

    def test_anchors(self):
        holds = {rel: {a["path"]: a["holds_all_instances"] for a in tgt(rel)["anchors"]} for rel in ("94", "115")}
        self.assertEqual(holds["94"], {
            "l1/action/c_deposit.rs": True, "l1/action/evm_raw_tx.rs": True, "l1/action/user_outcome.rs": False,
            "l1/action/vault_transfer.rs": True, "l1/action/vote_global.rs": False, "l1/action/withdraw3.rs": True,
            "l1/exchange/impl_outcome_deploy.rs": False})
        self.assertEqual(holds["115"], {
            "l1/action/c_deposit.rs": False, "l1/action/evm_raw_tx.rs": False, "l1/action/user_outcome.rs": True,
            "l1/action/vault_transfer.rs": True, "l1/action/vote_global.rs": False, "l1/action/withdraw3.rs": True,
            "l1/exchange/impl_outcome_deploy.rs": True})
        self.assertEqual(anchor("94", "l1/action/vote_global.rs")["instances_reached_by_expected"], [1, 2])
        self.assertEqual(anchor("115", "l1/action/vote_global.rs")["reached_by"], [])
        cd = anchor("94", "l1/action/c_deposit.rs")
        self.assertEqual(cd["owners"], [0x1F65F80, 0x47B8300, 0x47B83F0])
        self.assertEqual({(x["slot"], x["line"], x["col"], x["form"]) for x in cd["locations"]},
                         {(0x56914C0, 9, 18, "absolute"), (0x572FB78, 9, 18, "absolute")})
        uo = anchor("115", "l1/action/user_outcome.rs")
        self.assertEqual(sorted({(x["line"], x["form"]) for x in uo["locations"]}),
                         [(55, "relative"), (59, "relative")])
        od = anchor("115", "l1/exchange/impl_outcome_deploy.rs")
        self.assertEqual([(h["instance"], h["depth"], h["site"], h["owner"]) for h in od["reached_by"]][0],
                         (0, 1, 0x283C5B6, 0x2C59960))
        callers = {c["owner"]: sorted((s["site"], s["function"]) for s in c["sources"]) for c in od["owner_callers"]}
        self.assertEqual(callers, {0x2C59960: [(0x283C5B6, 0x283C2D0), (0x2913A2D, 0x2913750)],
                                   0x55CFE90: [(0x4FEA0F7, 0x4FE9D90), (0x50D4214, 0x50D3F40)],
                                   0x55D1FF0: [(0x4FEA4D7, 0x4FEA170), (0x50D3804, 0x50D3530)]})
        self.assertEqual(anchor("94", "l1/action/vault_transfer.rs")["expected_index"], 43)
        self.assertEqual(anchor("115", "l1/action/vault_transfer.rs")["expected_index"], 44)
        self.assertEqual(anchor("94", "l1/action/withdraw3.rs")["expected_index"], 47)
        self.assertEqual(anchor("115", "l1/action/withdraw3.rs")["expected_index"], 48)

    def test_locations(self):
        self.assertEqual(tgt("94")["first_party_crates"], list(ad.FIRST_PARTY_CRATES))
        self.assertEqual(tgt("94")["location_record_classes"],
                         {"first_party_absolute": 1186, "other_absolute": 6379, "relative_other_dir:src": 10})
        self.assertEqual(tgt("115")["location_record_classes"],
                         {"absolute_other_dir:z_vendor": 5101, "first_party_relative": 1359, "other_absolute": 1303,
                          "relative_other_dir:z_forks": 712})
        self.assertEqual((tgt("94")["location_record_count"], tgt("115")["location_record_count"]), (7575, 8475))
        # records that pass every rule except line != 0 and col != 0 (all of them have col 0)
        self.assertEqual([tgt(rel)["location_records_excluded_line_or_col_zero"] for rel in ("94", "115")],
                         [{"count": 533, "line_zero": 0, "col_zero": 533, "first_party_paths": ["base/lu.rs"]},
                          {"count": 571, "line_zero": 0, "col_zero": 571, "first_party_paths": ["base/lu.rs"]}])
        self.assertEqual(ctx("94").elf.read(0x566ECA0 + 16, 8), struct.pack("<II", 2, 0))   # base/src/lu.rs:2:0
        self.assertEqual(ctx("115").elf.read(0x64013D8 + 16, 8), struct.pack("<II", 2, 0))
        recs = ad.location_records(ctx("94"))
        self.assertEqual({r["path"] for r in recs if r["path"].startswith("src/")}, {"src/hl_node.rs"})
        self.assertEqual(sum(1 for r in recs if r["path"] == "/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs"), 53)

    def test_catalogue_qualification(self):
        self.assertEqual({q["path"]: q["qualification"] for q in result()["catalogue_paths"]}, {
            "l1/action/c_deposit.rs": "absent_path_surviving_variant",
            "l1/action/evm_raw_tx.rs": "absent_path_surviving_variant",
            "l1/action/user_outcome.rs": "added_path_existing_variant",
            "l1/exchange/impl_outcome_deploy.rs": "added_path_new_variant"})
        for path, present in (("l1/action/c_deposit.rs", "94"), ("l1/action/evm_raw_tx.rs", "94"),
                              ("l1/action/user_outcome.rs", "115"), ("l1/exchange/impl_outcome_deploy.rs", "115")):
            other = "115" if present == "94" else "94"
            q = qual(path)
            self.assertEqual(q["location_count"][other], 0)          # path control, both forms
            self.assertEqual(q["basename_occurrences"][other], 0)     # basename absent from the whole file
            self.assertEqual(q["source_path_occurrences"][other], 0)
            self.assertGreater(q["location_count"][present], 0)
            self.assertEqual(q["source_path_occurrences"][present], 1)
        self.assertEqual(qual("l1/action/c_deposit.rs")["variant_handlers"]["115"][0]["handler_location_files"],
                         ["l1/exchange/impl_abstraction.rs"])
        self.assertEqual(qual("l1/exchange/impl_outcome_deploy.rs")["owner_callers_outside_execute_family"],
                         [0x2913750, 0x50D3530, 0x50D3F40])
        self.assertEqual(qual("l1/action/user_outcome.rs")["owner_callers_outside_execute_family"],
                         [0x2C19F20, 0x5503280, 0x55225F0])
        self.assertEqual(qual("l1/action/c_deposit.rs")["owner_callers_outside_execute_family"], [])

    def test_re010_crosscheck(self):
        c = result()["re010_crosscheck"]
        self.assertEqual((c["cases_compared"], c["mismatched_indices"]), (88, []))
        self.assertEqual(c["label_counts"], {
            "claims": 76, "rust_variant_equals_ident_plus_Action": 74, "wire_type_differs": 25,
            "wire_type_differs_but_equals_rust_ident": 20, "wire_type_equals_rust_ident": 20,
            "wire_type_equals_serde_name": 51})
        self.assertEqual([x["index"] for x in c["rust_variant_differences"]], [37, 38])
        self.assertEqual([x["serde_name"] for x in c["unclaimed_cases"]], [
            "sendToEvmWithData", "userPortfolioMargin", "userSetAbstraction", "agentSetAbstraction", "userOutcome",
            "gossipPriorityBid", "agentSendAsset", "hip3LiquidatorTransfer", "l1ValidatorVoteBridgeDeposit",
            "authorizeAqav2Role", "stakingLinkDisableTradingUser", "voteL1Hash"])
        for note in (c["unclaimed_cases_note"], c["label_counts_note"], result()["contribution_note"]):
            self.assertIn("open PR #226 (head ad161cb7dde4e9e6246f831e5fba4c90c8600dee", note)
        self.assertIn("inference I2", c["unclaimed_cases_note"])
        self.assertIn("inference I2", result()["variant_join_counts"]["arm_to_name_binding"])
        self.assertEqual([x for x in c["wire_type_differences"] if x["index"] == 68],
                         [{"index": 68, "reconstruction_wire_type": "Hip3Deploy", "rust_ident": "Hip3Deploy",
                           "serde_name": "perpDeploy"}])

    def test_drift_reach_and_sizes(self):
        d = result()["location_drift_reach"]
        self.assertEqual((d["absent115"]["path_count"], d["absent115"]["with_owners"], d["absent115"]["reached"]),
                         (24, 24, 6))
        self.assertEqual((d["added115"]["path_count"], d["added115"]["with_owners"], d["added115"]["reached"]),
                         (35, 35, 7))
        kinds = {k for lst in d.values() for r in lst["paths"] for k in r["transfer_kinds"]}
        self.assertEqual(kinds, {"call", "handler", "slot_call"})       # no rel32 jmp edge is used
        s = result()["handler_size_ratios"]
        self.assertEqual((s["usable_pairs"], s["within_band"]), (84, 60))
        self.assertEqual({p["name"]: p["excluded"] for p in s["pairs"] if p["excluded"]},
                         {"noop": "no_resolved_handler", "multiSig": "first_call_reenters_dispatcher"})
        self.assertEqual({k: v["within_band"] for k, v in s["by_instance_pair"].items()},
                         {"0/0": 60, "0/1": 54, "0/2": 54, "1/0": 58, "1/1": 54, "1/2": 54, "2/0": 58, "2/1": 54,
                          "2/2": 54})
        self.assertEqual({v["usable_pairs"] for v in s["by_instance_pair"].values()}, {84})
        self.assertEqual(s["within_band_range"], [54, 60])

    def test_catalogue_lists_consistent(self):
        totals = json.loads((ROOT / "research/catalogue/components.json").read_text())["path_totals"]
        for path, listed in ad.CATALOGUE_PATHS:
            self.assertIn(path, totals[listed])
        d = result()["location_drift_reach"]
        absent = {r["path"] for r in d["absent115"]["paths"]}
        added = {r["path"] for r in d["added115"]["paths"]}
        self.assertTrue(absent <= set(totals["absent115"]))
        self.assertEqual(sorted(set(totals["absent115"]) - absent),
                         ["base/err_dur_guard.rs", "base/latency_sampler.rs", "base/raw_mdg.rs", "l1/time.rs"])
        self.assertEqual(added, set(totals["added115"]))


@unittest.skipUnless(HAVE_BINARIES, "pinned #94/#115 binaries not present")
class Determinism(unittest.TestCase):
    def test_hashseed_invariance(self):
        outs = set()
        for seed in ("0", "7", "99"):
            p = subprocess.run([sys.executable, "-B", str(ROOT / "tools/action_dispatch_drift.py")],
                               env=dict(os.environ, PYTHONHASHSEED=seed), capture_output=True, check=True)
            outs.add(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, {OUTPUT_SHA256})

    def test_cli_rejects_wrong_binary(self):
        p = subprocess.run([sys.executable, "-B", str(ROOT / "tools/action_dispatch_drift.py"),
                            "--binary", str(ad.TARGET_115), "--binary-115", str(ad.TARGET)], capture_output=True)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, b"")

    def test_cli_missing_input_exits_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = ad.main(["--binary", str(ROOT / "artifacts/node/94/does-not-exist")])
        self.assertEqual(rc, 2)
        self.assertIn("does-not-exist", err.getvalue())


@unittest.skipUnless(HAVE_BINARIES, "pinned #94/#115 binaries not present")
class WrongBinary(unittest.TestCase):
    def test_flipped_byte_rejected(self):
        d = data("94")
        with self.assertRaisesRegex(ad.EvidenceError, "release 94: binary sha256"):
            ad.build(d[:-1] + bytes([d[-1] ^ 1]), data("115"))
        d = data("115")
        with self.assertRaisesRegex(ad.EvidenceError, "release 115: binary sha256"):
            ad.build(data("94"), d[:-1] + bytes([d[-1] ^ 1]))

    def test_swapped_releases_rejected(self):
        with self.assertRaisesRegex(ad.EvidenceError, "release 94: binary sha256"):
            ad.build(data("115"), data("94"))

    def test_cross_target_profiles_fail_closed(self):
        # #94 constants against #115 bytes (and the reverse) must fail closed, even with the digest accepted
        # and even when the VARIANTS count is set to the other release's value.
        for rel, prof, n in (("115", ad.PROFILE_94, 92), ("94", ad.PROFILE_115, 88)):
            sha = hashlib.sha256(data(rel)).hexdigest()
            with self.assertRaisesRegex(ad.EvidenceError, f"VARIANTS count {n} != {prof['variants_count']}"):
                ad.analyze(data(rel), prof, sha)
            with self.assertRaisesRegex(ad.EvidenceError, f"release {prof['release']}: bias block not found"):
                ad.analyze(data(rel), dict(prof, variants_count=n), sha)

    def test_dispatcher_family_counts_are_pinned(self):
        sha = hashlib.sha256(data("115")).hexdigest()
        with self.assertRaisesRegex(ad.EvidenceError, "expected 2 sentinel_other_base instances, found 3"):
            ad.analyze(data("115"), dict(ad.PROFILE_115, sentinel_other_base_instances=2), sha)

    def test_truncated_or_non_elf_input_fails_closed(self):
        for rel in ("94", "115"):
            for buf in (data(rel)[:len(data(rel)) // 2], b"\0" * 4096):
                with self.assertRaises(ad.EvidenceError):
                    ad.analyze(buf, profile(rel), hashlib.sha256(buf).hexdigest())

    def test_re010_json_pin(self):
        raw = ad.RE010_JSON.read_bytes()
        with self.assertRaisesRegex(ad.EvidenceError, "RE-010 JSON sha256"):
            ad.combine(analyzed("94"), analyzed("115"), re010_json=raw.replace(b'"0x1e5f770"', b'"0x1e5f771"', 1))

    def test_profile_self_check(self):
        with self.assertRaisesRegex(ad.EvidenceError, "bias/default not encoded"):
            ad.analyze(data("94"), dict(ad.PROFILE_94, bias=0x75), ad.EXPECTED_SHA256)
        # numeric fields that disagree with the bias block bytes, even when bias agrees with the fields
        fields = ((3, "<b", -0x75), (7, "<B", 0x75), (9, "<I", 0x14))
        with self.assertRaisesRegex(ad.EvidenceError, "bias block field at 3"):
            ad.analyze(data("94"), dict(ad.PROFILE_94, bias=0x75, bias_block_fields=fields), ad.EXPECTED_SHA256)
        bad_tail = ad.PROFILE_94["bias_block"][:-4] + bytes.fromhex("480f42c1")      # cmovb, not cmovae
        with self.assertRaisesRegex(ad.EvidenceError, "does not end in 'cmovae"):
            ad.analyze(data("94"), dict(ad.PROFILE_94, bias_block=bad_tail), ad.EXPECTED_SHA256)
        # fields and tail agree, but 'lea rax,[rax-0x74]' (X == R; Z = rcx) is no instance of the idiom form
        same_reg = bytes.fromhex("488d408c" "4883f874" "b914000000" "480f43c8")
        with self.assertRaisesRegex(ad.EvidenceError, "is not an instance of idiom form lea_cmp"):
            ad.analyze(data("94"), dict(ad.PROFILE_94, bias_block=same_reg), ad.EXPECTED_SHA256)
        with self.assertRaisesRegex(ad.EvidenceError, "is not an instance of idiom form sub"):
            ad.analyze(data("94"), dict(ad.PROFILE_94, idiom_form="sub"), ad.EXPECTED_SHA256)
        self.assertEqual((ad._check_profile(ad.PROFILE_94), ad._check_profile(ad.PROFILE_115)), (0, 1))


@unittest.skipUnless(HAVE_BINARIES, "pinned #94/#115 binaries not present")
class Tamper(unittest.TestCase):
    def test_table_base_shift_fails_closed(self):
        for rel, lea, delta, site in (("94", 0x27592AD, 4, 0x275929C), ("94", 0x27592AD, -4, 0x275929C),
                                      ("115", 0x2BDBB1F, 4, 0x2BDBB10)):
            rel32 = ctx(rel).i32(lea + 3)
            with self.assertRaisesRegex(ad.EvidenceError, f"sentinel site {site:#x} has no "
                                                          f"{88 if rel == '94' else 92}-way in-FDE jump table"):
                rebuild(rel, patch(rel, lea + 3, struct.pack("<i", rel32 + delta)))

    def test_115_bias_0x74_fails_closed(self):
        self.assertEqual(ctx("115").elf.read(0x2BDBB10, 6), bytes.fromhex("482d86000000"))
        with self.assertRaisesRegex(ad.EvidenceError, "expected 3 execute instances, found 2"):
            rebuild("115", patch("115", 0x2BDBB12, b"\x74"))

    def test_one_variants_copy_tampered(self):
        slot = 0x56E8BD0 + 16 * 62 + 8          # len of 'cDeposit' in the second #94 copy
        with self.assertRaisesRegex(ad.EvidenceError, "copies differ"):
            rebuild("94", patch("94", slot, struct.pack("<Q", 7)))

    def test_bound_text_tampered(self):
        with self.assertRaisesRegex(ad.EvidenceError, "88 names but bound 87"):
            rebuild("94", patch("94", 0x3F4076 + 23, b"87"))

    def test_bound_text_must_end_at_the_count(self):
        # one more byte ('s' of the next string) after 'variant index 0 <= i < 88' is not a bound slot
        self.assertEqual(ctx("94").elf.read(0x3F4076 + 25, 1), b"s")
        c = ad.Ctx(patch("94", 0x56C4C60 + 8, struct.pack("<Q", 26)))
        with self.assertRaisesRegex(ad.EvidenceError, "lea-referenced slot 0x56c4c60 inside VARIANTS run 0x56c46e0"):
            ad.find_variants(c, ad.PROFILE_94)

    def test_variants_structure_rules(self):
        c = ctx("94")
        with self.assertRaisesRegex(ad.EvidenceError, "expected 2 VARIANTS copies, found 3"):
            ad.find_variants(c, dict(ad.PROFILE_94, variants_copies=2))
        for change, msg in (
                (lambda leas: leas.__setitem__(0x56C46E0 + 16 * 5, [0x1000]), "lea-referenced slot 0x56c4730 inside"),
                (lambda leas: leas.pop(0x56C4C60), "bound slot is not lea-referenced"),
                (lambda leas: leas.pop(0x56C46E0), "has no lea-referenced start")):
            c2 = copy.copy(c)
            c2.leas = dict(c.leas)
            change(c2.leas)
            with self.assertRaisesRegex(ad.EvidenceError, msg):
                ad.find_variants(c2, ad.PROFILE_94)

    def test_variants_name_rules(self):
        buf = data("94")
        dup, ident = buf, buf
        for start in (0x56C46E0, 0x56E8BD0, 0x5733130):
            a62 = ctx("94").relocs[start + 16 * 62]
            dup = set_str_slot("94", dup, start + 16 * 61, a62, 8)            # cWithdraw -> cDeposit
            ident = set_str_slot("94", ident, start + 16 * 62, 0x3F4076, 8)   # 'variant ' (with a space)
        with self.assertRaisesRegex(ad.EvidenceError, "or duplicate names"):
            ad.find_variants(ad.Ctx(dup), ad.PROFILE_94)
        with self.assertRaisesRegex(ad.EvidenceError, "is not an identifier: 'variant '"):
            ad.find_variants(ad.Ctx(ident), ad.PROFILE_94)

    def test_bias_block_outside_every_fde(self):
        c = copy.copy(ctx("94"))
        k = c.starts.index(0x16EF790)
        c.starts, c.ends = c.starts[:k] + c.starts[k + 1:], c.ends[:k] + c.ends[k + 1:]
        with self.assertRaisesRegex(ad.EvidenceError, "bias block at 0x16ef79e outside every FDE"):
            ad.survey_idiom(c, ad.PROFILE_94, tgt("94")["variants"]["names"])

    def test_swapping_two_names_breaks_serializer_binding(self):
        # Swap 'cWithdraw' (61) and 'cDeposit' (62) consistently in all three #94 VARIANTS copies: the
        # copies still agree, but no serializer stores VARIANTS[K] at every arm any more.
        buf = data("94")
        for start in (0x56C46E0, 0x56E8BD0, 0x5733130):
            a, b = start + 16 * 61, start + 16 * 62
            ra, rb = ctx("94").relocs[a], ctx("94").relocs[b]
            buf = set_str_slot("94", buf, a, rb, 8)
            buf = set_str_slot("94", buf, b, ra, 9)
        with self.assertRaisesRegex(ad.EvidenceError, "no arm-wise VARIANTS serializer"):
            rebuild("94", buf)

    def test_swapped_names_break_location_anchors(self):
        # Same swap applied to the derived name list only: the anchors must notice.
        t = analyzed("94")
        names = list(t["variants"]["names"])
        names[61], names[62] = names[62], names[61]
        insts = [dict(i, arms=[dict(r, name=names[r["index"]]) for r in i["arms"]]) for i in t["execute_instances"]]
        locs = ad.location_records(t["_ctx"])
        a = {x["path"]: x for x in ad.anchor_table(t["_ctx"], insts, names, locs)}
        self.assertFalse(a["l1/action/c_deposit.rs"]["holds_all_instances"])
        self.assertEqual(a["l1/action/c_deposit.rs"]["reached_names"], ["cWithdraw"])
        self.assertTrue(a["l1/action/evm_raw_tx.rs"]["holds_all_instances"])

    def test_misaligned_table_breaks_location_anchors(self):
        # In-memory analogue of a mis-read table base (shift 1) or of reading #115 with the #94 bias
        # (0x86 - 0x74 = 18 entries): every anchor that holds on the real alignment must fail.
        for rel, shifts in (("94", (1, -1)), ("115", (1, 0x86 - 0x74))):
            t = analyzed(rel)
            names = t["variants"]["names"]
            locs = ad.location_records(t["_ctx"])
            held = [a["path"] for a in t["anchors"] if a["holds_all_instances"]]
            self.assertEqual(len(held), 4)
            for s in shifts:
                insts = []
                for i in t["execute_instances"]:
                    arms = [dict(i["arms"][(k + s) % len(names)], index=k, name=names[k]) for k in range(len(names))]
                    insts.append(dict(i, arms=arms))
                a = {x["path"]: x for x in ad.anchor_table(t["_ctx"], insts, names, locs)}
                self.assertEqual([p for p in held if a[p]["holds_all_instances"]], [], (rel, s))

    def test_location_lea_retarget(self):
        # 0x1f65fda: lea rax,[rip+..] -> 0x56914c0 (c_deposit.rs). Point it 0x18 further, at 0x56914d8 (withdraw3.rs).
        rel32 = ctx("94").i32(0x1F65FDD)
        r = rebuild("94", patch("94", 0x1F65FDD, struct.pack("<i", rel32 + 0x18)))
        a = {x["path"]: x for x in r["targets"]["94"]["anchors"]}
        self.assertEqual(a["l1/action/c_deposit.rs"]["instances_reached_by_expected"], [1, 2])
        self.assertFalse(a["l1/action/c_deposit.rs"]["holds_all_instances"])
        self.assertEqual(a["l1/action/withdraw3.rs"]["reached_names"], ["cDeposit", "withdraw3"])
        self.assertEqual(sorted({(h["name"], h["instance"]) for h in a["l1/action/withdraw3.rs"]["reached_by"]}),
                         [("cDeposit", 0), ("withdraw3", 0), ("withdraw3", 1), ("withdraw3", 2)])
        self.assertEqual(a["l1/action/withdraw3.rs"]["instances_reached_by_expected"], [0, 1, 2])
        self.assertFalse(a["l1/action/withdraw3.rs"]["holds_all_instances"])      # exclusivity, not coverage
        q = {x["path"]: x["qualification"] for x in r["catalogue_paths"]}
        self.assertIsNone(q["l1/action/c_deposit.rs"])
        self.assertEqual(q["l1/action/evm_raw_tx.rs"], "absent_path_surviving_variant")

    def test_outcome_deploy_call_removed(self):
        self.assertEqual(ctx("115").elf.read(0x283C5B6, 1), b"\xe8")
        r = rebuild("115", patch("115", 0x283C5B6, b"\x90" * 5))
        a = {x["path"]: x for x in r["targets"]["115"]["anchors"]}
        self.assertEqual(a["l1/exchange/impl_outcome_deploy.rs"]["instances_reached_by_expected"], [1, 2])
        q = {x["path"]: x["qualification"] for x in r["catalogue_paths"]}
        self.assertIsNone(q["l1/exchange/impl_outcome_deploy.rs"])
        self.assertEqual(q["l1/action/user_outcome.rs"], "added_path_existing_variant")

    def test_user_outcome_arm_call_retarget(self):
        # 0x2bdbbaf: call 0x283b5b0 (userOutcome arm, instance 0). Send it to the vaultTransfer handler instead.
        self.assertEqual(ctx("115").elf.read(0x2BDBBAF, 1), b"\xe8")
        r = rebuild("115", patch("115", 0x2BDBBB0, rel32_to("115", 0x2BDBBAF, 1, 0x283C6B0)))
        a = {x["path"]: x for x in r["targets"]["115"]["anchors"]}
        self.assertEqual(a["l1/action/user_outcome.rs"]["instances_reached_by_expected"], [1, 2])
        self.assertEqual(a["l1/action/vault_transfer.rs"]["reached_names"], ["userOutcome", "vaultTransfer"])
        self.assertEqual(a["l1/action/vault_transfer.rs"]["instances_reached_by_expected"], [0, 1, 2])
        self.assertFalse(a["l1/action/vault_transfer.rs"]["holds_all_instances"])
        q = {x["path"]: x["qualification"] for x in r["catalogue_paths"]}
        self.assertIsNone(q["l1/action/user_outcome.rs"])

    def test_r15_relation_detects_a_cross_index_transfer(self):
        # 0x2c1a255: call 0x283b5b0 in the [r15] arm-79 (userOutcome) handler 0x2c19f20. Send it to the [r12]
        # vaultTransfer handler 0x283c6b0 (index 44): arm 79 loses its same-index transfer and becomes other-index.
        c = ctx("115")
        self.assertEqual((c.elf.read(0x2C1A255, 1), 0x2C1A25A + c.i32(0x2C1A256)), (b"\xe8", 0x283B5B0))
        buf = patch("115", 0x2C1A256, rel32_to("115", 0x2C1A255, 1, 0x283C6B0))
        rel = ad.analyze(buf, ad.PROFILE_115, hashlib.sha256(buf).hexdigest())["sentinel_other_base_relation"]
        self.assertEqual([r["arms_whose_handler_transfers_to_same_index_execute_handler"] for r in rel], [56, 60, 60])
        self.assertEqual([r["arms_whose_handler_transfers_to_other_index_execute_handler"] for r in rel],
                         [[79], [], []])

    def test_multisig_thunk_reentry_depends_on_call(self):
        self.assertEqual(ctx("94").elf.read(0x282EE7E, 1), b"\xe8")
        r = rebuild("94", patch("94", 0x282EE7E, b"\x90" * 5))
        j = next(x for x in r["variant_join"] if x["name"] == "multiSig")
        self.assertEqual(j["reenters_94"], [False, True, True])

    def test_cdeposit2_jump_retarget(self):
        rel32 = ctx("115").i32(0x2BDBB88)
        r = rebuild("115", patch("115", 0x2BDBB88, struct.pack("<i", rel32 + 1)))
        j = next(x for x in r["variant_join"] if x["name"] == "cDeposit2")
        self.assertEqual((j["via_115"][0], j["handlers_115"][0]), ("none", None))
        self.assertEqual(j["via_115"][1:], ["shared_arm_tail"] * 2)

    def test_cdeposit2_jump_into_own_path_is_not_a_shared_tail(self):
        r = rebuild("115", patch("115", 0x2BDBB88, rel32_to("115", 0x2BDBB87, 1, 0x2BDBB82)))
        j = next(x for x in r["variant_join"] if x["name"] == "cDeposit2")
        self.assertEqual((j["via_115"][0], j["handlers_115"][0]), ("none", None))

    def test_shared_tail_into_arm_without_call_fails_closed(self):
        # 0x2bdbb34 is the jmp of the noop arm (index 0), whose path has no call.
        self.assertEqual(ctx("115").elf.read(0x2BDBB34, 1), b"\xe9")
        with self.assertRaisesRegex(ad.EvidenceError, "shared tail 0x2bdbb34 does not end in a call"):
            rebuild("115", patch("115", 0x2BDBB88, rel32_to("115", 0x2BDBB87, 1, 0x2BDBB34)))

    def test_entry_branch_leaving_dispatcher_fails_closed(self):
        # 0x2759a83: jne rel32 inside the cUserModify arm of #94 instance 0; send it past the FDE end.
        self.assertEqual(ctx("94").elf.read(0x2759A83, 2), b"\x0f\x85")
        with self.assertRaisesRegex(ad.EvidenceError, "jcc at 0x2759a83 leaves dispatcher 0x2759240"):
            rebuild("94", patch("94", 0x2759A85, rel32_to("94", 0x2759A83, 2, 0x275A380)))

    def test_primary_instance_must_decode_strictly(self):
        # arm 1 of #94 instance 0: 'mov rdx,rsp' (48 89 e2) -> 'xor rdx,rdx' (48 31 d2), which only the
        # extended decoder accepts; an undecodable byte (06) leaves the arm unresolved.
        self.assertEqual(ctx("94").elf.read(0x27592D7, 3), bytes.fromhex("4889e2"))
        for new in (bytes.fromhex("4831d2"), b"\x06"):
            with self.assertRaisesRegex(ad.EvidenceError, "primary instance 0x2759240 has arms the strict walker"):
                rebuild("94", patch("94", 0x27592D7 if len(new) == 3 else 0x27592BD, new))

    def test_serializer_store_tamper(self):
        # 0x28226a4: mov QWORD PTR [rsp+0x38],0x8 (len of 'cDeposit') in serializer 0x2821000, arm 62.
        self.assertEqual(ctx("94").elf.read(0x28226A4, 9), bytes.fromhex("48c744243808000000"))
        r = rebuild("94", patch("94", 0x28226A9, b"\x07"))
        t = r["targets"]["94"]
        self.assertNotIn(0x2821000, [s["function"] for s in t["serializers"]])
        self.assertEqual(len(t["serializers"]), 10)
        site = next(s for s in t["idiom_sites"] if s["function"] == 0x2821000)
        self.assertEqual((site["role"], site["arms_storing_variant_name"]), ("other", 87))
        self.assertNotIn(0x2821000, t["census"]["tables"]["serializer_functions"])
        self.assertTrue(t["census"]["tables"]["serializers_equal_idiom_serializers"])

    def test_serializer_name_case_matters(self):
        # 0x2822698: lea rax,[rip+..] -> 0x20ab90 'cDeposit'. Point it at 0x20a640 'CDeposit' (the identifier).
        self.assertEqual(ctx("94").elf.read(0x20A640, 8), b"CDeposit")
        self.assertEqual(ctx("94").elf.read(0x20AB90, 8), b"cDeposit")
        r = rebuild("94", patch("94", 0x282269B, rel32_to("94", 0x2822698, 3, 0x20A640)))
        t = r["targets"]["94"]
        self.assertNotIn(0x2821000, [s["function"] for s in t["serializers"]])
        site = next(s for s in t["idiom_sites"] if s["function"] == 0x2821000)
        self.assertEqual((site["role"], site["arms_storing_variant_name"]), ("other", 87))

    def test_first_call_retarget_seen_by_re010_crosscheck(self):
        arm = inst("94")["arms"][3]
        site, old = arm["path_end"]["site"], arm["path_end"]["target"]
        new = inst("94")["arms"][4]["path_end"]["target"]
        rel32 = ctx("94").i32(site + 1)
        r = rebuild("94", patch("94", site + 1, struct.pack("<i", rel32 + new - old)))
        self.assertEqual(r["re010_crosscheck"]["mismatched_indices"], [3])
        self.assertEqual(next(x for x in r["variant_join"] if x["name"] == "cancel")["handlers_94"][0], new)


@unittest.skipUnless(HAVE_BINARIES, "pinned #94/#115 binaries not present")
class Re010Fields(unittest.TestCase):
    """Each compared RE-010 field, and each identity check, with the JSON digest re-pinned."""

    def cross(self, mutate):
        d = json.loads(ad.RE010_JSON.read_bytes())
        mutate(d)
        raw = json.dumps(d).encode()
        return ad.re010_crosscheck(analyzed("94"), raw, expected_json_sha256=hashlib.sha256(raw).hexdigest())

    def test_unchanged_reserialized_json_matches(self):
        self.assertEqual(self.cross(lambda d: None)["mismatched_indices"], [])

    def test_each_field_is_compared(self):
        def case(d, k):
            return next(c for c in d["cases"] if c["index"] == k)

        def bump(x, key):
            x[key] = f"{int(x[key], 16) + 1:#x}"

        mutations = {
            "arm": lambda d: bump(case(d, 5), "arm"),
            "arm_path_end": lambda d: bump(case(d, 5)["arm_path_end"], "site"),
            "arm_path_insns": lambda d: case(d, 5).__setitem__("arm_path_insns", case(d, 5)["arm_path_insns"] + 1),
            "entry_branches": lambda d: bump(case(d, 63)["entry_branches"][0], "target"),
            "first_call": lambda d: bump(case(d, 5)["first_call"], "target"),
        }
        for name, m in mutations.items():
            k = 63 if name == "entry_branches" else 5
            self.assertEqual(self.cross(m)["mismatched_indices"], [k], name)

    def test_identity_checks(self):
        for mutate, msg in (
                (lambda d: d["dispatcher"].__setitem__("start", "0x4d83050"), "dispatcher/jump table differ"),
                (lambda d: d.__setitem__("jump_table", "0x712dfc"), "dispatcher/jump table differ"),
                (lambda d: d.__setitem__("binary_sha256", ad.EXPECTED_SHA256_115), "another binary or table length"),
                (lambda d: d.__setitem__("table_entries", 87), "another binary or table length")):
            with self.assertRaisesRegex(ad.EvidenceError, msg):
                self.cross(mutate)


@unittest.skipUnless(HAVE_BINARIES, "pinned #94/#115 binaries not present")
class Qualification(unittest.TestCase):
    """qualify() on in-memory variants of the real targets: each presence condition is required."""

    def q(self, t94=None, t115=None):
        return {x["path"]: x["qualification"] for x in ad.qualify(t94 or analyzed("94"), t115 or analyzed("115"))}

    @staticmethod
    def without(rel, name):
        t = analyzed(rel)
        names = [n if n != name else name + "Gone" for n in t["variants"]["names"]]
        return dict(t, variants=dict(t["variants"], names=names))

    @staticmethod
    def with_locations(rel, path):
        t = analyzed(rel)
        donor = next(a for a in analyzed("94" if rel == "115" else "115")["anchors"] if a["path"] == path)
        anchors = [dict(a, locations=donor["locations"]) if a["path"] == path else a for a in t["anchors"]]
        return dict(t, anchors=anchors)

    def test_real(self):
        self.assertEqual(self.q(), {q["path"]: q["qualification"] for q in result()["catalogue_paths"]})

    def test_absent_path_needs_variant_in_115(self):
        self.assertIsNone(self.q(t115=self.without("115", "cDeposit"))["l1/action/c_deposit.rs"])

    def test_absent_path_needs_no_115_locations(self):
        self.assertIsNone(self.q(t115=self.with_locations("115", "l1/action/c_deposit.rs"))["l1/action/c_deposit.rs"])

    def test_added_path_variant_presence_decides_existing_or_new(self):
        self.assertEqual(self.q(t94=self.without("94", "userOutcome"))["l1/action/user_outcome.rs"],
                         "added_path_new_variant")
        q = self.q(t94=self.with_locations("94", "l1/action/user_outcome.rs"))
        self.assertIsNone(q["l1/action/user_outcome.rs"])


@unittest.skipUnless(HAVE_BINARIES, "pinned #94/#115 binaries not present")
class Roles(unittest.TestCase):
    """assign_roles / check_serializers / execute_instance / resolve_arm on in-memory inputs."""

    def sites(self, rel):
        key = ("sites", rel)
        if key not in _CACHE:
            t = analyzed(rel)
            v = ad.find_variants(t["_ctx"], profile(rel))
            _CACHE[key] = (ad.survey_idiom(t["_ctx"], profile(rel), v[0]["names"]), v)
        sites, v = _CACHE[key]
        return copy.deepcopy(sites), v

    def test_serializer_and_sentinel_shapes_are_exclusive(self):
        sites, v = self.sites("94")
        s = next(x for x in sites if x["function"] == 0x2821000)
        s["sentinel_base"] = "r12"
        with self.assertRaisesRegex(ad.EvidenceError, "both serializer and sentinel shaped"):
            ad.assign_roles(ctx("94"), [s], v)
        b = next(x for x in sites if x["site"] == 0x16EF79E)
        b["sentinel_base"] = "r12"
        with self.assertRaisesRegex(ad.EvidenceError, "has no 88-way in-FDE jump table"):
            ad.assign_roles(ctx("94"), [b], v)

    def test_role_needs_distinct_in_fde_entries(self):
        sites, v = self.sites("115")
        s = next(x for x in sites if x["function"] == 0x2BDBAA0)
        s["distinct_entries"] = 91
        with self.assertRaisesRegex(ad.EvidenceError, "has no 92-way in-FDE jump table"):
            ad.assign_roles(ctx("115"), [s], v)
        with self.assertRaisesRegex(ad.EvidenceError, "table entries not 92 distinct in-FDE arms"):
            ad.execute_instance(ctx("115"), s, v[0]["names"], set())

    def test_census_compares_with_the_idiom_serializers(self):
        _sites, v = self.sites("94")
        all11 = [s["function"] for s in tgt("94")["serializers"]]
        self.assertTrue(ad.table_census(ctx("94"), v, all11)["serializers_equal_idiom_serializers"])
        self.assertFalse(ad.table_census(ctx("94"), v, all11[1:])["serializers_equal_idiom_serializers"])

    def test_serializer_name_offset_needs_room_for_the_quadruple(self):
        # two synthetic arms that store 'ab' / 'cd' at [rsp+off] and call 0x1800
        def arm(at, ptr, off):
            return (b"\x48\x8d\x05" + struct.pack("<i", ptr - (at + 7)) + bytes((0x48, 0x89, 0x44, 0x24, off))
                    + bytes((0x48, 0xC7, 0x44, 0x24, off + 8)) + struct.pack("<i", 2)
                    + b"\xe8" + struct.pack("<i", 0x1800 - (at + 26)))

        variants = [{"names": ["ab", "cd"], "_ptrs": [0x2000, 0x2002], "start": 0x3000}]
        for off, serializer in ((0x10, False), (0x30, True)):
            code = bytearray(0x1000)
            code[0:26], code[0x100:0x126] = arm(0x1000, 0x2000, off), arm(0x1100, 0x2002, off)
            c = fake_ctx({0x1000: bytes(code), 0x2000: b"abcd" + b"\0" * 0xFFC})
            c.starts, c.ends = [0x1800], [0x1810]
            got = ad.serializer_check(c, [0x1000, 0x1100], variants)
            self.assertEqual((got["arms_storing_variant_name"], got["name_offset"]), (2, off))
            self.assertEqual("stack_base" in got, serializer, hex(off))
        self.assertEqual((got["stack_base"], got["type_idents"], got["name_ptrs_equal_variants_copies"]),
                         (0, ["<missing>"], [0x3000]))

    def test_check_serializers(self):
        good = {"rust_idents": ["A", "B"], "type_idents": ["Action"], "tag_strs": ["type"]}
        self.assertEqual(ad.check_serializers([good, dict(good)]), ["A", "B"])
        for bad, msg in (([], "no arm-wise"), ([good, dict(good, rust_idents=["A", "C"])], "inconsistent"),
                         ([dict(good, rust_idents=["A", None])], "inconsistent"),
                         ([dict(good, rust_idents=["A", "A"])], "inconsistent"),
                         ([dict(good, rust_idents=["A", "b c"])], "inconsistent"),
                         ([dict(good, type_idents=["<missing>", "Action"])], "Action/type"),
                         ([dict(good, tag_strs=["Type"])], "Action/type")):
            with self.assertRaisesRegex(ad.EvidenceError, msg):
                ad.check_serializers(bad)

    def test_resolve_arm_entry_branches(self):
        def br(target):
            return {"site": 0, "target": 0, "path_end": {"kind": "rel32", "site": 0, "target": target}}

        h1, h2 = inst("94")["arms"][1]["resolution"]["handler"], inst("94")["arms"][2]["resolution"]["handler"]
        base = {"index": 7, "path_end": {"kind": "jmp", "site": 0, "target": 0x1}}
        one = ad.resolve_arm(ctx("94"), dict(base, entry_branches=[br(h1), br(h1)]), [], {}, 0, set())
        self.assertEqual((one["via"], one["handler"]), ("entry_branch", h1))
        two = ad.resolve_arm(ctx("94"), dict(base, entry_branches=[br(h1), br(h2)]), [], {}, 0, set())
        self.assertEqual((two["via"], two["handler"]), ("ambiguous_entry_branches", None))
        none = ad.resolve_arm(ctx("94"), dict(base, entry_branches=[]), [], {}, 0, set())
        self.assertEqual((none["via"], none["handler"]), ("none", None))


class Units(unittest.TestCase):
    """Synthetic byte-level controls for the decoders and slot readers (no binaries needed)."""

    def test_inside_is_half_open(self):
        self.assertTrue(ad._inside((0x10, 0x20), 0x10))
        self.assertTrue(ad._inside((0x10, 0x20), 0x1F))
        self.assertFalse(ad._inside((0x10, 0x20), 0x20))
        self.assertFalse(ad._inside((0x10, 0x20), 0xF))

    def test_str_slot(self):
        ro = b"cDeposit" + b"\0" * (0x1000 - 8)
        slot = struct.pack("<QQ", 0, 8)
        c = fake_ctx({0x2000: ro, 0x3000: slot + struct.pack("<QQ", 0, 0) + struct.pack("<QQ", 0, 256)
                      + struct.pack("<QQ", 0, 8) + b"\0" * (0x100 - 64)}, relocs={0x3000: 0x2000, 0x3010: 0x2000,
                                                                                   0x3020: 0x2000, 0x3030: 0x1000,
                                                                                   0x30F8: 0x2000})
        self.assertEqual(ad._str_slot(c, 0x3000), b"cDeposit")
        self.assertIsNone(ad._str_slot(c, 0x3010))      # len 0
        self.assertIsNone(ad._str_slot(c, 0x3020))      # len 256
        self.assertIsNone(ad._str_slot(c, 0x3030))      # pointer outside .rodata
        self.assertIsNone(ad._str_slot(c, 0x3040))      # no relocation
        self.assertIsNone(ad._str_slot(c, 0x30F8))      # slot + 15 leaves .data.rel.ro
        c.relocs[0x3000] = 0x2FFC                       # string end leaves .rodata
        self.assertIsNone(ad._str_slot(c, 0x3000))

    def test_stack_strs(self):
        ro = b"Action" + b"type" + b"cDeposit" + b"\0" * (0x1000 - 18)

        def run(*ins):
            code, addrs, a = bytearray(0x1000), [], 0x1000
            for h in ins:
                b = bytes.fromhex(h)
                code[a - 0x1000:a - 0x1000 + len(b)] = b
                addrs.append(a)
                a += len(b)
            return ad._stack_strs(fake_ctx({0x1000: bytes(code), 0x2000: ro}), addrs)

        lea_r8 = "4c8d05f90f0000"           # at 0x1000: lea r8,[rip+0xff9] -> 0x2000 'Action'
        self.assertEqual(run(lea_r8, "4c89442430", "48c744243806000000"), {0x30: (0x2000, "Action")})
        self.assertEqual(run(lea_r8, "4c890424", "48c744240806000000"), {0x00: (0x2000, "Action")})
        # the store names r8 (REX.R); rax holds another pointer: 'cDepos', not 'Action', would be a REX.R slip
        self.assertEqual(run(lea_r8, "488d05fc0f0000", "4c89442430", "48c744243806000000"),
                         {0x30: (0x2000, "Action")})
        # a non-RIP lea (mod 10, rm 101 = [rbp+disp32]) overwrites r8: no pointer is left to store
        self.assertEqual(run(lea_r8, "4c8d85f20f0000", "4c89442430", "48c744243806000000"), {})
        self.assertEqual(run(lea_r8, "4c8b07", "4c89442430", "48c744243806000000"), {})       # mov r8,[rdi]
        self.assertEqual(run(lea_r8, "4989f8", "4c89442430", "48c744243806000000"), {})       # mov r8,rdi
        self.assertEqual(run(lea_r8, "4c89442430", "48c744243800010000"), {})                 # len 256
        self.assertEqual(run("4c8d05f9ffffff", "4c89442430", "48c744243804000000"), {})       # ptr in .text
        self.assertEqual(run(lea_r8, "4c89442430"), {})                                       # no length store

    def test_gap_insn(self):
        g = ad._gap_insn
        self.assertEqual(g(bytes.fromhex("31c0") + b"\0" * 8, 6), ("zero_reg", 2, 0))           # xor eax,eax
        self.assertEqual(g(bytes.fromhex("33c9") + b"\0" * 8, 6), ("zero_reg", 2, 1))           # xor ecx,ecx (33 /r)
        self.assertEqual(g(bytes.fromhex("4531c0") + b"\0" * 8, 6), ("zero_reg", 3, 8))         # xor r8d,r8d
        self.assertIsNone(g(bytes.fromhex("31c8") + b"\0" * 8, 6))                              # xor eax,ecx
        self.assertIsNone(g(bytes.fromhex("4131c0") + b"\0" * 8, 6))                            # xor r8d,eax
        self.assertIsNone(g(bytes.fromhex("3100") + b"\0" * 8, 6))                              # xor [rax],eax
        self.assertEqual(g(bytes.fromhex("4889fb") + b"\0" * 8, 0), ("mov_reg", 3, 3))          # mov rbx,rdi
        self.assertEqual(g(bytes.fromhex("49bc0000000000000080") + b"\0" * 4, 0), ("mov_imm", 10, 12))
        self.assertEqual(g(bytes.fromhex("b001") + b"\0" * 8, 1), ("mov_imm", 2, 0))            # mov al,1
        self.assertEqual(g(bytes.fromhex("b401") + b"\0" * 8, 1), ("mov_imm", 2, 0))            # mov ah,1
        self.assertEqual(g(bytes.fromhex("b801000000") + b"\0" * 8, 1), ("mov_imm", 5, 0))
        self.assertEqual(g(bytes.fromhex("48ffc8") + b"\0" * 8, 0), ("dec_index", 3, 0))        # dec rax
        self.assertIsNone(g(bytes.fromhex("48ffc9") + b"\0" * 8, 0))                            # dec rcx, index rax
        self.assertEqual(g(bytes.fromhex("4883f852") + b"\0" * 8, 0), ("cmp_index_imm8", 4, None))
        self.assertIsNone(g(bytes.fromhex("4883f880") + b"\0" * 8, 0))                          # negative imm8
        self.assertIsNone(g(bytes.fromhex("488b07") + b"\0" * 8, 0))                            # load: not allowed
        self.assertEqual(g(bytes.fromhex("4c8bac2420110000") + b"\0" * 4, 0), ("load_stack", 8, 13))  # r13,[rsp+d32]
        self.assertEqual(g(bytes.fromhex("4c8b742408") + b"\0" * 4, 0), ("load_stack", 5, 14))       # r14,[rsp+8]
        self.assertIsNone(g(bytes.fromhex("498b742408") + b"\0" * 4, 0))                       # [r12+8]: not rsp
        self.assertIsNone(g(bytes.fromhex("488b0424") + b"\0" * 4, 0))                         # [rsp], mod 00
        self.assertEqual(g(bytes.fromhex("4c8d8000010000") + b"\0" * 4, 7), ("lea_reg_disp", 7, 8))  # r8,[rax+0x100]
        self.assertEqual(g(bytes.fromhex("488d442410") + b"\0" * 4, 1), ("lea_reg_disp", 5, 0))      # rax,[rsp+0x10]
        self.assertIsNone(g(bytes.fromhex("488d448810") + b"\0" * 4, 1))                       # indexed lea
        self.assertIsNone(g(bytes.fromhex("4a8d442410") + b"\0" * 4, 1))                       # REX.X: r12 is an index
        self.assertIsNone(g(bytes.fromhex("488d05f90f0000") + b"\0" * 4, 1))                   # RIP-relative lea
        self.assertIsNone(g(bytes.fromhex("6641be1201") + b"\0" * 8, 0))                        # 16-bit mov

    def test_table_at_and_find_table(self):
        # lea rcx,[rip+X]; movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax at 0x1010, table at 0x2000
        tbl = bytes.fromhex("488d0de90f0000" "48630481" "4801c8" "ffe0")
        pre_ok = bytes.fromhex("48ffc8" "4883f852" "7702" "4889fb")         # dec; cmp; ja; mov rbx,rdi
        pre_bad = bytes.fromhex("4889f8")                                    # mov rax,rdi overwrites the index
        for pre, want in ((pre_ok, "found"), (pre_bad, "overwrites the index register"),
                          (bytes.fromhex("4889fb") * 5, "no jump table within 4"),
                          (bytes.fromhex("4883f852" "4889fb"), "not a single bounds check"),
                          (bytes.fromhex("4883f852" "7702" "4883f852" "7702"), "not a single bounds check")):
            code = bytearray(0x1000)
            code[0x10 - len(pre):0x10] = pre
            code[0x10:0x10 + len(tbl)] = tbl
            c = fake_ctx({0x1000: bytes(code), 0x2000: b"\0" * 0x1000})
            t = ad._find_table(c, 0x1010 - len(pre), 0)
            if want == "found":
                self.assertEqual((t["table"], t["index_decrements"], t["bounds_check"]["cmp_imm"], len(t["gap_sites"]),
                                  t["table_regs"]), (0x2000, 1, 0x52, 4, "base rcx, dest rax, index rax"))
                self.assertIsNone(ad._table_at(c, 0x1010, 1))                # index register must match
                self.assertEqual(ad._table_at(c, 0x1010, None)["table"], 0x2000)
            else:
                self.assertIn(want, t["stop"])
        c = fake_ctx({0x1000: tbl + b"\0" * 0x100, 0x2000: b"\0" * 0x1000},
                     sec={".text": (0x1000, 0, 0x1000), ".rodata": (0x3000, 0, 0x10),
                          ".data.rel.ro": (0x4000, 0, 0x10)})
        self.assertIsNone(ad._table_at(c, 0x1000, 0))                        # table outside .rodata

    def test_idiom_at_any_register_allocation(self):
        p94, p115 = ad.PROFILE_94, ad.PROFILE_115
        for hexs, prof, want in (
                # (length, tag R, index I, lea destination X, default register D, cmov)
                ("488d488c" "4883f874" "b814000000" "480f43c1", p94, (17, 0, 0, 1, 0, "cmovae")),  # dispatcher form
                ("488d508c" "4883f874" "b914000000" "480f43ca", p94, (17, 0, 1, 2, 1, "cmovae")),  # cmovae rcx,rdx
                ("4d8d44248c" "4983fc74" "41b914000000" "4d0f43c8", p94, (19, 12, 9, 8, 9, "cmovae")),  # SIB 0x24
                ("4d8d44208c" "4983fc74" "41b914000000" "4d0f43c8", p94, None),            # SIB 0x20 is [r8-0x74]
                ("488d408c" "4883f874" "b914000000" "480f43c8", p94, None),                # X == R (Z = rcx)
                ("488d488c" "4883f874" "b914000000" "480f43c9", p94, None),                # Z == X
                ("488d488c" "4883f874" "b815000000" "480f43c1", p94, None),                # default 0x15
                ("4a8d488c" "4883f874" "b814000000" "480f43c1", p94, None),                # REX.X on the lea
                ("488d488c" "4883f875" "b814000000" "480f43c1", p94, None),                # cmp imm differs
                # the inverted cmov: cmovb X,D with D = 0x14 (D may be R, which the cmp no longer needs)
                ("4c8d408c" "4883f874" "b814000000" "4c0f42c0", p94, (17, 0, 8, 8, 0, "cmovb")),   # cmovb r8,rax
                ("488d708c" "4883f874" "b914000000" "480f42f1", p94, (17, 0, 6, 6, 1, "cmovb")),   # cmovb rsi,rcx
                ("488d708c" "4883f874" "b914000000" "480f42ce", p94, None),                # cmovb rcx,rsi: D,X
                ("488d708c" "4883f874" "be14000000" "480f42f6", p94, None),                # D == X
                ("488d708c" "4883f874" "b914000000" "480f46f1", p94, None),                # cmovbe
                ("488d488c" "4883f874" "b814000000" "480f47c1", p94, None),                # cmova
                ("488d708c" "4883f874" "b914000000" "0f42f1", p94, None),                  # 32-bit cmovb
                ("488d708c" "4883f874" "b914000000" "4a0f42f1", p94, None),                # REX.X on the cmov
                ("488d708c" "4883f874" "b914000000" "480f4231", p94, None),                # memory source
                ("482d86000000" "b914000000" "480f43c8", p115, (15, 0, 1, None, 1, "cmovae")),     # dispatcher form
                ("4881e986000000" "b814000000" "480f43c1", p115, (16, 1, 0, None, 0, "cmovae")),   # 81 /5 form
                ("4981ea86000000" "41bb14000000" "4d0f43da", p115, (17, 10, 11, None, 11, "cmovae")),
                ("482d86000000" "b814000000" "480f43c0", p115, None),                      # Z == R
                ("482d86000000" "b914000000" "480f42c1", p115, (15, 0, 0, None, 1, "cmovb")),      # cmovb rax,rcx
                ("4981e886000000" "b814000000" "4c0f42c0", p115, (16, 8, 8, None, 0, "cmovb")),    # cmovb r8,rax
                ("482d86000000" "b914000000" "480f42c8", p115, None),                      # cmovb rcx,rax: D,R
                ("482d86000000" "b914000000" "480f42d1", p115, None),                      # cmovb rdx,rcx: not R
                ("482d86000000" "b914000000" "480f43ca", p115, None),                      # cmovae rcx,rdx: not R
                ("482d86000000" "b814000000" "480f42c0", p115, None),                      # cmovb with D == R
                ("482d86000000" "b914000000" "0f43c8", p115, None)):                       # 32-bit cmovae
            b = bytes.fromhex(hexs) + b"\0" * 4
            self.assertEqual(ad._idiom_at(prof, b, 0), want, hexs)
        two = b"\x90" * 3 + bytes.fromhex("4d8d44248c4983fc7441b9140000004d0f43c8") + b"\xcc" + \
            bytes.fromhex("488d488c4883f874b814000000480f43c1") + b"\0" * 4
        self.assertEqual(ad._idiom_offsets(p94, two), [3, 23])
        self.assertEqual(ad._idiom_offsets(p115, two), [])

    def test_default_elsewhere_matcher(self):
        p94, p115 = ad.PROFILE_94, ad.PROFILE_115
        at = ad._idiom_default_elsewhere_at
        for hexs, prof, want in (
                ("4d8d488c" "4983f874" "4c0f42c8", p94, (12, 8, 9, 9, 0, "cmovb")),        # lea r9; cmovb r9,rax
                ("4d8d488c" "4983f874" "490f43c1", p94, (12, 8, 0, 9, 0, "cmovae")),       # cmovae rax,r9
                ("4d8d488c" "4983f874" "4d0f42c8", p94, None),                             # cmovb r9,r8: D == R
                ("4d8d488c" "4983f874" "4d0f42c9", p94, None),                             # cmovb r9,r9: D == X
                ("4d8d488c" "4983f874" "4d0f43c1", p94, None),                             # cmovae r8,r9: D == R
                ("4d8d488c" "4983f874" "4c0f42c0", p94, None),                             # cmovb r8,rax: not X
                ("4d8d488c" "4983f874" "480f43c1", p94, None),                             # cmovae rax,rcx: not X
                ("4d8d488c" "4983f874" "b814000000" "4c0f42c8", p94, None),                # the default is loaded
                ("4981e886000000" "4c0f42c0", p115, (11, 8, 8, None, 0, "cmovb")),         # sub r8; cmovb r8,rax
                ("482d86000000" "480f43c8", p115, (10, 0, 1, None, 1, "cmovae")),          # cmovae rcx,rax
                ("482d86000000" "480f42c0", p115, None),                                   # cmovb rax,rax
                ("482d86000000" "480f42c8", p115, None),                                   # cmovb rcx,rax: not R
                ("482d86000000" "0f42c1", p115, None)):                                    # 32-bit cmovb
            b = bytes.fromhex(hexs) + b"\0" * 4
            self.assertEqual(at(prof, b, 0), want, hexs)
            if want is not None:
                self.assertIsNone(ad._idiom_at(prof, b, 0), hexs)          # the two matchers are disjoint
        two = b"\x90" + bytes.fromhex("4d8d488c4983f8744c0f42c8") + bytes.fromhex("4c8d408c4883f874b8140000004c0f42c0")
        self.assertEqual((ad._idiom_offsets(p94, two, at), ad._idiom_offsets(p94, two)), ([1], [13]))

    def test_sentinel_rules_use_the_idiom_tag_register(self):
        # .text at 0x1000: mov ebp,0x3b9aca00; mov R,[r12]; then the #115 idiom with tag register T
        tag_rcx = "4881e986000000" "b814000000" "480f43c1"      # sub rcx,0x86; mov eax,0x14; cmovae rax,rcx
        tag_rax = "482d86000000" "b914000000" "480f43c8"        # sub rax,0x86; mov ecx,0x14; cmovae rcx,rax
        for load, idiom, base, census in (
                ("498b0c24", tag_rcx, "r12", ("r12", "rcx")),     # mov rcx,[r12], T = rcx: the tag load
                ("498b0424", tag_rcx, None, (None, None)),         # mov rax,[r12], T = rcx: another register
                ("498b0c24", tag_rax, None, (None, None)),         # mov rcx,[r12], T = rax
                ("498b0424", tag_rax, "r12", ("r12", "rax"))):
            code = ad.SENTINEL + bytes.fromhex(load + idiom) + b"\xcc" * 8
            c = fake_ctx({0x1000: code}, sec={".text": (0x1000, 0, len(code)), ".rodata": (0x2000, 0, 0x10),
                                              ".data.rel.ro": (0x3000, 0, 0x10)})
            c.data = code
            site = 0x1000 + len(ad.SENTINEL) + len(load) // 2
            tag = ad._idiom_at(ad.PROFILE_115, code, site - 0x1000)[1]
            self.assertEqual(ad._sentinel_base(c, site, tag), base, (load, idiom))
            s = ad.sentinel_census(c, ad.PROFILE_115)
            self.assertEqual((s["occurrences"], s["before_tag_load_and_idiom"]), (1, int(base is not None)))
            self.assertEqual((s["sites"][0]["tag_load_then_idiom"], s["sites"][0]["tag_register"]), census)

    def test_extended_decoder_accepts_exactly_three_encodings(self):
        for hexs, n in (("483d86000000", 6), ("3d86000000", 5), ("31d2", 2), ("4831d2", 3), ("0f43c8", 3),
                        ("480f43c1", 4), ("0f42c8", 3), ("4c0f4f442408", 6)):
            ins = ad._decode_ext(bytes.fromhex(hexs) + b"\0" * 10, 0, 0x1000)
            self.assertEqual((ins.size, ins.kind), (n, "other"), hexs)
        for hexs in ("06", "48ffc8", "33d2", "663d8600", "0f50c0", "483b05"):
            with self.assertRaises(ad.ed.EvidenceError, msg=hexs):
                ad._decode_ext(bytes.fromhex(hexs) + b"\0" * 10, 0, 0x1000)
        with self.assertRaises(ad.ed.EvidenceError):
            ad.ed.decode_one(bytes.fromhex("483d86000000") + b"\0" * 10, 0, 0x1000)    # the RE-010 decoder is strict
        self.assertIs(ad.ed_ext.decode_one, ad._decode_ext)        # only the private instance is wrapped
        self.assertIsNot(ad.ed.decode_one, ad._decode_ext)

    def test_rel32_sources_reports_calls_and_jumps(self):
        code = bytearray(0x200)
        code[0x10:0x15] = b"\xe8" + struct.pack("<i", 0x1100 - 0x1015)
        code[0x20:0x25] = b"\xe9" + struct.pack("<i", 0x1100 - 0x1025)
        code[0x30:0x35] = b"\xe8" + struct.pack("<i", 0x1101 - 0x1035)
        c = fake_ctx({0x1000: bytes(code)}, sec={".text": (0x1000, 0, 0x200), ".rodata": (0x2000, 0, 0x10),
                                                 ".data.rel.ro": (0x3000, 0, 0x10)})
        c.data = bytes(code)
        got = ad.rel32_sources(c, {0x1100})
        self.assertEqual([(x["site"], x["kind"]) for x in got[0x1100]], [(0x1010, "call"), (0x1020, "jmp")])

    def test_walk_maps_truncation_to_evidence_error(self):
        c = fake_ctx({0x1000: b"\x48"})
        with self.assertRaisesRegex(ad.EvidenceError, "arm walk from 0x1000"):
            c.walk(0x1000)
        with self.assertRaisesRegex(ad.EvidenceError, "extended arm walk from 0x1000"):
            c.walk_ext(0x1000)


@unittest.skipUnless(HAVE_BINARIES, "pinned #94/#115 binaries not present")
class Boundaries(unittest.TestCase):
    def test_handler_starts_off_by_one(self):
        for rel in ("94", "115"):
            c = ctx(rel)
            for i in tgt(rel)["execute_instances"] + tgt(rel)["sentinel_other_base_instances"]:
                for a in i["arms"]:
                    h = a["resolution"]["handler"]
                    if h is not None:
                        self.assertTrue(c.is_start(h))
                        self.assertFalse(c.is_start(h + 1))
                        self.assertFalse(c.is_start(h - 1))

    def test_dispatcher_end_exclusive(self):
        for rel in ("94", "115"):
            i = inst(rel)
            c = ctx(rel)
            self.assertEqual(c.containing(i["end"] - 1), (i["start"], i["end"]))
            self.assertNotEqual(c.containing(i["end"]), (i["start"], i["end"]))
            self.assertNotEqual(c.containing(i["start"] - 1), (i["start"], i["end"]))


@unittest.skipUnless(HAVE_BINARIES and OBJDUMP and READELF, "GNU objdump/readelf or binaries missing")
class Binutils(unittest.TestCase):
    def test_dispatcher_idioms(self):
        for rel, seq in (("94", ["mov", "mov", "lea", "cmp", "mov", "cmovae", "lea", "movsxd", "add", "jmp"]),
                         ("115", ["mov", "mov", "sub", "mov", "cmovae", "lea", "movsxd", "add", "jmp"])):
            fam = tgt(rel)["execute_instances"] + tgt(rel)["sentinel_other_base_instances"]
            self.assertEqual(len(fam), 3 if rel == "94" else 6)
            for i in fam:
                back = 9 if i["tag_base"] == "r12" else 8
                od = objdump_rows(rel, i["bias_site"] - back, i["bias_site"] + 40)
                rows = [od[a] for a in sorted(od)][:len(seq)]
                self.assertEqual([m for m, _o in rows], seq)
                self.assertEqual(rows[0][1], "ebp,0x3b9aca00")
                self.assertEqual(rows[1][1], f"rax,QWORD PTR [{i['tag_base']}]")
                lea = rows[-4][1]
                self.assertEqual(int(lea.split("#")[1].split()[0], 16), i["table"])

    def test_idiom_site_tables_are_instruction_starts(self):
        gaps = {}
        for rel in ("94", "115"):
            for s in tgt(rel)["idiom_sites"]:
                if s["kind"] != "jump_table":
                    continue
                od = objdump_rows(rel, s["function"], s["table_jmp_site"] + 3)
                for a in [s["site"]] + s["gap_sites"]:
                    self.assertIn(a, od, (rel, hex(a)))
                key = (rel, s["shape"], tuple(" ".join(od[a]) if od[a][0] != "ja" else "ja" for a in s["gap_sites"]))
                gaps[key] = gaps.get(key, 0) + 1
                self.assertEqual(od[s["table_lea_site"]][0], "lea", hex(s["site"]))
                self.assertEqual(int(od[s["table_lea_site"]][1].split("#")[1].split()[0], 16), s["table"])
                self.assertEqual(od[s["table_jmp_site"]][0], "jmp", hex(s["site"]))
                if s["bounds_check"]:
                    b = s["bounds_check"]
                    self.assertEqual(od[b["cmp_site"]], ("cmp", f"{s['index_register']},{b['cmp_imm']:#x}"))
                    self.assertEqual(od[s["bounds_check"]["ja_site"]][0], "ja")
        self.assertEqual(gaps, {
            ("94", "direct", ()): 14, ("94", "direct_with_stores", ()): 1, ("94", "after_gap", ("mov rbx,rdi",)): 9,
            ("94", "after_gap", ("movabs r12,0x8000000000000000",)): 1, ("94", "after_gap", ("mov eax,0x1",)): 1,
            ("94", "after_gap", ("lea r8,[rax+0x100]",)): 1,
            ("94", "after_gap", ("mov r13,QWORD PTR [rsp+0x1120]",)): 1,
            ("94", "after_gap", ("mov r14,QWORD PTR [rsp+0x8c0]",)): 1,
            ("94", "after_gap", ("mov al,0x2",)): 1, ("94", "after_gap", ("xor eax,eax",)): 3,
            ("94", "after_bounds_check", ("dec rax", "cmp rax,0x52", "ja", "mov rbx,rdi")): 12,
            ("94", "after_bounds_check", ("dec rcx", "cmp rcx,0x52", "ja", "mov rbx,rdi")): 7,
            ("94", "after_bounds_check", ("dec rcx", "cmp rcx,0x52", "ja")): 3,
            ("115", "direct", ()): 19, ("115", "after_gap", ("mov rbx,rdi",)): 11,
            ("115", "after_gap", ("movabs r12,0x8000000000000000",)): 1, ("115", "after_gap", ("mov al,0x1",)): 1,
            ("115", "after_gap", ("mov eax,0x1",)): 1, ("115", "after_gap", ("mov r14,QWORD PTR [rsp+0x920]",)): 1,
            ("115", "after_gap", ("mov al,0x2",)): 1, ("115", "after_gap", ("xor eax,eax",)): 3,
            ("115", "after_bounds_check", ("dec rax", "cmp rax,0x59", "ja", "mov rbx,rdi")): 21,
            ("115", "after_bounds_check", ("dec rax", "cmp rax,0x59", "ja")): 1,
            ("115", "after_bounds_check", ("dec rcx", "cmp rcx,0x59", "ja", "mov rbx,rdi")): 2})

    def test_idiom_sites_decode_as_stated(self):
        r32 = dict(zip(ad.REG64, ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
                       + tuple(f"r{n}d" for n in range(8, 16))))
        for rel in ("94", "115"):
            p = profile(rel)
            for s in tgt(rel)["idiom_sites"] + tgt(rel)["idiom_default_elsewhere"]["sites"]:
                R, I, D = s["tag_register"], s["index_register"], s["default_register"]
                src = s["temp_register"] or R                   # the register that holds tag - bias
                if p["idiom_form"] == "lea_cmp":
                    want = [("lea", f"{src},[{R}-{p['bias']:#x}]"), ("cmp", f"{R},{p['bias']:#x}")]
                else:
                    want = [("sub", f"{R},{p['bias']:#x}")]
                if "idiom_length" in s:         # a surveyed site loads the default; a default_elsewhere one does not
                    want.append(("mov", f"{r32[D]},{p['default_index']:#x}"))
                want.append((s["cmov"], f"{I},{src}" if s["cmov"] == "cmovae" else f"{I},{D}"))
                end = s["site"] + (s["idiom_length"] if "idiom_length" in s else s["length"])
                od = objdump_rows(rel, s["function"], end + 1)
                k = sorted(od).index(s["site"])
                self.assertEqual([od[a] for a in sorted(od)[k:k + len(want)]], want, (rel, hex(s["site"])))
                self.assertEqual(sorted(od)[k + len(want) - 1] + 4, end, (rel, hex(s["site"])))   # 4-byte cmov

    def test_default_elsewhere_sites(self):
        # objdump: what follows each default_elsewhere site. Either movsxd/add/jmp through a base register, with a
        # consecutive cmovb site in the same function (same default register D, its table lea loads that base
        # register), or a compare of the index and a conditional jump back to before the site.
        r32 = dict(zip(ad.REG64, ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
                       + tuple(f"r{n}d" for n in range(8, 16))))
        for rel, n_redispatch, loops in (("94", 8, [0x3994E61, 0x45487A1]),
                                         ("115", 11, [0x3C3D203, 0x3D9858A, 0x57BC1E1])):
            consec = {}
            for s in tgt(rel)["idiom_sites"]:
                if s["cmov"] == "cmovb":
                    consec.setdefault(s["function"], []).append(s)
            redispatch, other = [], []
            for d in tgt(rel)["idiom_default_elsewhere"]["sites"]:
                end = d["site"] + d["length"]
                od = objdump_rows(rel, d["function"], end + 24)
                nxt = [od[a] for a in sorted(od) if a >= end][:4]
                if nxt[0] == ("xor", "eax,eax"):
                    nxt = nxt[1:]
                m = re.fullmatch(r"(\w+),DWORD PTR \[(\w+)\+(\w+)\*4\]", nxt[0][1]) if nxt[0][0] == "movsxd" else None
                if m and m.group(3) == d["index_register"] and nxt[1] == ("add", f"{m.group(1)},{m.group(2)}") \
                        and nxt[2] == ("jmp", m.group(1)):
                    same = [s for s in consec.get(d["function"], []) if s["default_register"] == d["default_register"]
                            and s.get("table_regs", "").startswith(f"base {m.group(2)},")]
                    self.assertEqual(len(same), 1, (rel, hex(d["site"])))
                    redispatch.append(d["site"])
                else:
                    i = d["index_register"]
                    on_index = (nxt[0][0] == "cmp" and nxt[0][1].startswith(i + ",")) or (
                        nxt[0][0] == "lea" and re.search(rf"\[(?:{i}|{r32[i]})-0x", nxt[0][1]) and nxt[1][0] == "cmp")
                    jcc = next(x for x in nxt if x[0].startswith("j") and x[0] != "jmp")
                    self.assertTrue(on_index and int(jcc[1].split()[0], 16) < d["site"], (rel, hex(d["site"]), nxt))
                    other.append(d["site"])
            self.assertEqual((len(redispatch), other), (n_redispatch, loops), rel)

    def test_idiom_survey_objdump_control(self):
        # Two nets over all of .text for a cmovcc of ANY condition and operand form, decoded by objdump (linear
        # sweep from the FDE start; a byte match may start one byte early, at a 40-4f byte that is no REX prefix):
        # (A) 'mov r32,0x14' (B8+r, or REX.W C7 C0+r) followed within 12 bytes by a cmovcc that names that
        #     register, with the bias as an immediate of a cmp/sub/lea/add among the 5 instructions before the mov
        #     and up to the cmov;
        # (B) a bias instruction on a 32- or 64-bit register (#94: cmp/sub r,0x74, add r,-0x74,
        #     lea r,[base-0x74]; #115: cmp/sub r,0x86, add r,-0x86, lea r,[base-0x86], lea r32,[base+0x7a])
        #     followed by a cmovcc among its next 4 instructions, with no jump, call or return in between.
        # Every hit is a surveyed site (either cmov), a default_elsewhere site, or one of the hits listed here.
        rex = rb"[\x40-\x4f]?"
        anchors = {
            "94": re.compile(rex + rb"(?:\x83[\xe8-\xef\xf8-\xff]\x74|\x83[\xc0-\xc7]\x8c|\x8d[\x40-\x7f]\x8c"
                             rb"|\x8d[\x44\x4c\x54\x5c\x64\x6c\x74\x7c].\x8c)", re.S),
            "115": re.compile(rb"(?:" + rex + rb"(?:\x81[\xe8-\xef\xf8-\xff]\x86\x00\x00\x00|[\x2d\x3d]\x86\x00\x00\x00"
                              rb"|\x81[\xc0-\xc7]\x7a\xff\xff\xff|\x05\x7a\xff\xff\xff|\x8d[\x80-\xbf]\x7a\xff\xff\xff"
                              rb"|\x8d[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].\x7a\xff\xff\xff)"
                              rb"|[\x40-\x47]?\x8d(?:[\x40-\x7f]|[\x44\x4c\x54\x5c\x64\x6c\x74\x7c].)\x7a)", re.S)}
        bias_text = {"94": re.compile(r",0x74$|-0x74\]$|,0xf+8c$"),
                     "115": re.compile(r",0x86$|-0x86\]$|,0xf+7a$|\+0x7a\]$")}
        mov14 = re.compile(rb"(?:[\x40\x41]?[\xb8-\xbf]|[\x48\x49]\xc7[\xc0-\xc7])\x14\x00\x00\x00", re.S)
        regs = {r: n for n, r in enumerate(ad.REG64)}
        regs.update({r: n for n, r in enumerate(("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"))})
        regs.update({f"r{n}d": n for n in range(8, 16)})
        # the 32-bit byte-truncated gate computation (lea e?x,[R+-bias]; cmp R,bias; movzx; mov e?x,0x14;
        # 'cmovae r32,r32'): #94 function 0x335ec90; #115 the entries of the three [r15] dispatchers and of execute
        # instance 0, two [r15] arm-52 handlers, and arm 52 of execute instances 1 and 2; and one unrelated #115
        # hit, 'cmp rax,0x86; mov edx,0x0; cmovne rdx,r8' (an equality test; no default, no biased value)
        listed = {"94": {0x335ECA2: ("cmovae", "eax,ecx")},
                  "115": {0x2BDA7F1: ("cmovae", "eax,ecx"), 0x2BDBAD3: ("cmovae", "eax,ecx"),
                          0x54A2FC1: ("cmovae", "eax,ecx"), 0x54A3A31: ("cmovae", "eax,ecx"),
                          0x551D1CF: ("cmovae", "ecx,eax"), 0x5536DFF: ("cmovae", "ecx,eax"),
                          0x55FA747: ("cmovae", "ecx,eax"), 0x55FB817: ("cmovae", "ecx,eax"),
                          0x4E417DE: ("cmovne", "rdx,r8")}}
        for rel in ("94", "115"):
            c, p = ctx(rel), profile(rel)
            t_va, text = c.sec_bytes(".text")
            cm_at = sorted({q for m in re.finditer(rb"\x0f[\x40-\x4f]", text) for q in (m.start() - 1, m.start())})
            cands = []
            for net, rx, span in (("A", mov14, 12), ("B", anchors[rel], 60)):
                for m in rx.finditer(text):
                    j = bisect.bisect_left(cm_at, m.end())
                    while j < len(cm_at) and cm_at[j] <= m.end() + span:
                        for s in ((m.start(), m.start() + 1) if 0x40 <= text[m.start()] <= 0x4F else (m.start(),)):
                            cands.append((net, t_va + s, t_va + cm_at[j]))
                        j += 1
            by_fn = {}
            for x in cands:
                fn = c.containing(x[1])
                if fn is not None and c.containing(x[2]) == fn:
                    by_fn.setdefault(fn, []).append(x)
            sites = [(s["site"], s["site"] + s["idiom_length"]) for s in tgt(rel)["idiom_sites"]]
            de = {d["site"] + d["length"] - 4: d["site"] for d in tgt(rel)["idiom_default_elsewhere"]["sites"]}
            covered, de_covered, other = set(), set(), {}
            for fn, xs in sorted(by_fn.items()):
                od = objdump_rows(rel, fn[0], max(x[2] for x in xs) + 8)
                addrs = sorted(od)
                idx = {a: n for n, a in enumerate(addrs)}
                for net, a, cm in xs:
                    if a not in od or cm not in od or not od[cm][0].startswith("cmov") or idx[cm] <= idx[a]:
                        continue
                    k, kc = idx[a], idx[cm]
                    mn, op = od[a]
                    if net == "A":
                        z = regs.get(op.split(",")[0]) if mn == "mov" and op.endswith(",0x14") else None
                        if z is None or z not in {regs.get(x) for x in od[cm][1].split(",")}:
                            continue
                        if not any(m2 in ("cmp", "sub", "lea", "add") and f"{p['bias']:#x}" in o2
                                   for m2, o2 in (od[x] for x in addrs[max(0, k - 5):kc + 1])):
                            continue
                    elif mn not in ("cmp", "sub", "lea", "add") or not bias_text[rel].search(op) or kc - k > 4 \
                            or any(od[x][0].startswith("j") or od[x][0] in ("call", "ret") for x in addrs[k + 1:kc]):
                        continue
                    hit = [lo for lo, hi in sites if lo <= cm < hi]
                    if hit:
                        covered.add(hit[0])
                    elif cm in de:
                        de_covered.add(de[cm])
                    else:
                        other[cm] = od[cm]
            self.assertEqual(covered, {lo for lo, _hi in sites}, rel)
            self.assertEqual(de_covered, set(de.values()), rel)
            self.assertEqual(other, listed[rel], rel)

    def test_primary_arm_paths(self):
        for rel in ("94", "115"):
            for i in (inst(rel),) + tuple(tgt(rel)["sentinel_other_base_instances"][:1]):
                od = objdump_rows(rel, i["start"], i["end"])
                addrs = sorted(od)
                c = ctx(rel)
                starts = [a["arm"] for a in i["arms"]] + [b["target"] for a in i["arms"] for b in a["entry_branches"]]
                for va in starts:
                    path, _j, term = c.walk(va)
                    k = addrs.index(path[0])
                    self.assertEqual(addrs[k:k + len(path)], path, hex(va))
                    mn, ops = od[term["site"]]
                    if term["kind"] == "rip_slot":
                        self.assertEqual((mn, int(ops.split("#")[1].split()[0], 16)), ("call", term["slot"]))
                    else:
                        self.assertEqual((mn, int(ops.split()[0], 16)),
                                         ("jmp" if term["kind"] == "jmp" else "call", term["target"]))

    def test_extended_decoder_arms(self):
        for n in (1, 2):
            i = inst("115", n)
            a = i["arms"][52]
            path, _j, term, _x = ctx("115").walk_ext(a["arm"])
            od = objdump_rows("115", i["start"], i["end"])
            addrs = sorted(od)
            k = addrs.index(path[0])
            self.assertEqual(addrs[k:k + len(path)], path)
            self.assertEqual([od[x][0] for x in path], ["mov", "mov", "lea", "cmp", "movzx", "mov", "cmovae", "lea",
                                                         "mov", "xor", "mov", "call"])
            self.assertEqual(od[term["site"]], ("call", f"{i['start']:x}"))

    def test_serializer_name_stores(self):
        for rel in ("94", "115"):
            c = ctx(rel)
            names = tgt(rel)["variants"]["names"]
            sers = tgt(rel)["serializers"]
            for s in [x for x in sers if x["stack_base"] == 0][:1] + [x for x in sers if x["stack_base"] == 8][:1]:
                od = objdump_rows(rel, s["function"], s["function_end"])
                no = s["name_offset"]
                for k in range(len(names)):
                    arm = s["table"] + c.i32(s["table"] + 4 * k)
                    path, _j, _t = c.walk(arm)
                    txt = [od[a] for a in path]
                    lens = [o for m, o in txt if m == "mov" and o.startswith(f"QWORD PTR [rsp+{no + 8:#x}],")]
                    self.assertEqual(lens, [f"QWORD PTR [rsp+{no + 8:#x}],{len(names[k]):#x}"], (rel, k))
                    j = next(n for n, (m, o) in enumerate(txt)
                             if m == "mov" and o.startswith(f"QWORD PTR [rsp+{no:#x}],"))
                    reg = txt[j][1].split(",")[1]
                    lea = [o for m, o in txt[:j] if m == "lea" and o.startswith(reg + ",[rip+")][-1]
                    ptr = int(lea.split("#")[1].split()[0], 16)
                    self.assertEqual(c.elf.read(ptr, len(names[k])).decode(), names[k], (rel, k))

    def test_entry_signatures(self):
        def sig(rel, lo, hi):
            out = []
            for _a, (mn, ops) in sorted(objdump_rows(rel, lo, hi).items()):
                if mn == "push" or (mn == "sub" and ops.startswith("rsp,")):
                    continue
                if mn.startswith("j") or mn == "call":
                    ops = "L" if re.fullmatch(r"[0-9a-f]+", ops) else re.sub(r"0x[0-9a-f]+\]\s+# [0-9a-f]+", "S]", ops)
                out.append(mn + " " + ops)
            return tuple(out)

        sigs = {}
        for rel in ("94", "115"):
            for fam in ("execute_instances", "sentinel_other_base_instances"):
                for n, i in enumerate(tgt(rel)[fam]):
                    back = 9 if i["tag_base"] == "r12" else 8
                    sigs[(rel, fam[:4], n)] = sig(rel, i["start"], i["bias_site"] - back)
        classes = sorted(sorted(k for k in sigs if sigs[k] == v) for v in set(sigs.values()))
        self.assertEqual(classes, [[("115", "exec", 0)],
                                   [("115", "exec", 1), ("115", "exec", 2), ("94", "exec", 0), ("94", "exec", 1),
                                    ("94", "exec", 2)],
                                   [("115", "sent", 0), ("115", "sent", 1), ("115", "sent", 2)]])

    def test_cited_sites(self):
        sites = [
            ("94", 0x282EE50, 0x282EE7E, "call", "2759240"),
            ("94", 0x48F5850, 0x48F587E, "call", "4d83050"),
            ("94", 0x48F5800, 0x48F582E, "call", "4d84170"),
            ("94", 0x2759240, 0x275A0F0, "call", "282ee50"),
            ("94", 0x1F65F80, 0x1F65FDA, "lea", "# 56914c0"),
            ("94", 0x47B8300, 0x47B835A, "lea", "# 572fb78"),
            ("94", 0x47B83F0, 0x47B844A, "lea", "# 572fb78"),
            ("94", 0x1F661C0, 0x1F67364, "lea", "# 5690288"),
            ("94", 0x1E5FB20, 0x1E5FB4C, "lea", "# 568eb20"),
            ("94", 0x1F67810, 0x1F6783C, "lea", "# 56914d8"),
            ("94", 0x3913400, 0x391402B, "lea", "# 5b681a"),
            ("94", 0x3913400, 0x3914032, "lea", "# 5713558"),
            ("94", 0x3913400, 0x391404A, "call", "2a68270"),
            ("115", 0x2BDBAA0, 0x2BDBB87, "jmp", "2bdc457"),
            ("115", 0x2BDBAA0, 0x2BDC460, "call", "2c6bbf0"),
            ("115", 0x2BDBAA0, 0x2BDC843, "call", "2bdbaa0"),
            ("115", 0x55F99B0, 0x55FA757, "call", "55f99b0"),
            ("115", 0x55FAA80, 0x55FB827, "call", "55faa80"),
            ("115", 0x2C12690, 0x2C129F7, "call", "2bdbaa0"),
            ("115", 0x5536770, 0x5536E14, "call", "55f99b0"),
            ("115", 0x551CB40, 0x551D1E4, "call", "55faa80"),
            ("115", 0x2C19F20, 0x2C1A255, "call", "283b5b0"),
            ("115", 0x283C2D0, 0x283C5B6, "call", "2c59960"),
            ("115", 0x2913750, 0x2913A2D, "call", "2c59960"),
            ("115", 0x4FE9D90, 0x4FEA0F7, "call", "55cfe90"),
            ("115", 0x50D3F40, 0x50D4214, "call", "55cfe90"),
            ("115", 0x4FEA170, 0x4FEA4D7, "call", "55d1ff0"),
            ("115", 0x50D3530, 0x50D3804, "call", "55d1ff0"),
            ("115", 0x2C59960, 0x2C59DB3, "lea", "# 644d8d0"),
            ("115", 0x2C59960, 0x2C5A91D, "lea", "# 644d8e8"),
            ("115", 0x283B5B0, 0x283B73D, "lea", "# 643baf0"),
            ("115", 0x283B5B0, 0x283BEED, "lea", "# 643bb08"),
            ("115", 0x283C6B0, 0x283C6DC, "lea", "# 643bb20"),
            ("115", 0x246CD10, 0x246CD3C, "lea", "# 64304d8"),
        ]
        for rel, fn, site, mn, frag in sites:
            od = objdump_rows(rel, fn, site + 16)       # linear sweep from the FDE start
            self.assertIn(site, od, (rel, hex(site)))
            self.assertEqual(od[site][0], mn, (rel, hex(site)))
            self.assertIn(frag, od[site][1], (rel, hex(site)))
        for rel in ("94", "115"):
            refs = [(r["start"], s) for r in tgt(rel)["dispatcher_references"] for s in r["rel32_sources"]]
            refs += [(c["owner"], s) for a in tgt(rel)["anchors"] for c in a["owner_callers"] for s in c["sources"]]
            self.assertEqual(len(refs), 39 if rel == "94" else 57)
            for target, s in refs:
                od = objdump_rows(rel, s["function"], s["site"] + 16)
                self.assertEqual(od[s["site"]], (s["kind"], f"{target:x}"), (rel, hex(s["site"])))

    def test_readelf_relocations(self):
        for rel in ("94", "115"):
            out = subprocess.run([READELF, "-rW", str(ad.TARGET if rel == "94" else ad.TARGET_115)],
                                 check=True, capture_output=True, text=True).stdout
            relocs = {}
            for line in out.splitlines():
                p = line.split()
                if len(p) == 4 and p[2] == "R_X86_64_RELATIVE":
                    relocs[int(p[0], 16)] = int(p[3], 16)
            c = ctx(rel)
            self.assertEqual(relocs, c.relocs)                  # every RELATIVE relocation, both readers
            v = tgt(rel)["variants"]
            for cp in v["copies"]:
                for k in range(v["count"] + 1):
                    self.assertIn(cp["start"] + 16 * k, relocs)

    def test_readelf_fde_bounds(self):
        for rel in ("94", "115"):
            out = subprocess.run([READELF, "-wf", str(ad.TARGET if rel == "94" else ad.TARGET_115)],
                                 check=True, capture_output=True, text=True).stdout
            fdes = {int(m.group(1), 16): int(m.group(2), 16)
                    for m in re.finditer(r" FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out)}
            t = tgt(rel)
            self.assertEqual(len(fdes), t["fde_count"])
            for i in t["execute_instances"] + t["sentinel_other_base_instances"]:
                self.assertEqual(fdes[i["start"]], i["end"])
                for a in i["arms"]:
                    r = a.get("resolution", {})
                    if r.get("handler") is not None:
                        self.assertEqual(fdes[r["handler"]] - r["handler"], r["handler_size"])
            for s in t["serializers"]:
                self.assertEqual(fdes[s["function"]], s["function_end"])


if __name__ == "__main__":
    unittest.main()
