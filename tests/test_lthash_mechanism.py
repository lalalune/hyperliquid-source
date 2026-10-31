import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-C-lthash-mechanism-94"
BIN = ROOT / "artifacts/node/94/hl-node"
OUTPUT_SHA256 = "fd44957c759ec48f8499ac966e89cfab7c92a5405ab3087a1476df3897b9339e"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tool = load("lthash_mechanism", ROOT / "tools/lthash_mechanism.py")
iv = load("re009c_independent_verify", PACKET / "independent_verify.py")


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = BIN.read_bytes()
        cls.extents = tool.leaf_extents(cls.data)
        t = next(s for s in tool.sections(cls.data) if s["name"] == ".text")
        cls.ta, cls.to = t["address"], t["offset"]

    def off(self, va):
        return va - self.ta + self.to


class PinnedOutput(Base):
    def test_exact_output_sha(self):
        text = tool.render(tool.analyse(self.data, extents=self.extents))
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "lthash-mechanism.json").read_text(), text)

    def test_exact_mechanism(self):
        r = tool.analyse(self.data, extents=self.extents, check_refs=False)
        self.assertEqual(r["counts"], {"leaves": 3, "lattice_loops": 6, "count_blocks": 3})
        self.assertEqual([L["leaf"] for L in r["leaves"]], ["0x37f3f00", "0x37f4280", "0x37f4610"])
        for L in r["leaves"]:
            a, b = L["lattice_entry_add"], L["lattice_merge_add"]
            self.assertEqual((a["index_start"], a["index_bound"], a["index_step"], a["iterations"],
                              a["lanes_per_iteration"], a["u16_words_total"], a["rol16_8_swaps"]),
                             (1, "0x401", 2, 512, 2, 1024, 6))
            self.assertEqual((b["index_start"], b["index_bound"], b["index_step"], b["iterations"],
                              b["u16_words_total"], b["rol16_8_swaps"]),
                             (0, "0x400", 2, 512, 1024, 6))
            self.assertEqual(a["addend_minus_accumulator"], "0x1020")
            self.assertEqual(b["addend_minus_accumulator"], "0x810")
            for x in (a, b):
                self.assertEqual((x["byte_order"], x["overflow"], x["bytes_covered"]),
                                 ("big-endian", "wrapping-mod-2^16", 0x800))
            self.assertEqual(L["blake3_slots"], {"platform_detect": "0x57700c0", "update": "0x57700c8",
                                                 "xof_fill": "0x57700b0"})
            self.assertEqual(L["count_add"]["u64_adds"], 2)
            self.assertEqual(L["count_add"]["overflow"], "saturating-u64")

    def test_independent_verify_clean(self):
        packet = json.loads((PACKET / "lthash-mechanism.json").read_text())
        self.assertEqual(iv.check(self.data, packet), [])
        self.assertEqual((len(iv.KEYS), len(iv.BLOBS)), (37, 9))

    def test_independent_verify_imports_nothing_from_tools(self):
        src = (PACKET / "independent_verify.py").read_text()
        self.assertNotIn("tools", [l.split()[1].split(".")[0] for l in src.splitlines()
                                   if l.startswith(("import ", "from "))])
        self.assertNotIn("sys.path", src)


class Determinism(unittest.TestCase):
    def test_hashseeds(self):
        outs = set()
        for seed in ("0", "7", "99"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = subprocess.run([sys.executable, "-O", "-B", str(ROOT / "tools/lthash_mechanism.py")],
                               capture_output=True, env=env, check=True)
            outs.add(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, {OUTPUT_SHA256})


class KeyVaTamper(Base):
    """Every pinned key VA and block must be caught on its own (sha gate off)."""

    def setUp(self):
        self.buf = bytearray(self.data)

    def flip(self, va):
        o = self.off(va)
        self.buf[o] ^= 0xFF
        return o

    def test_every_key_va_caught_by_independent_verify(self):
        for va, hx, _kind, _tgt, role in iv.KEYS:
            for i in range(len(hx) // 2):
                with self.subTest(va=hex(va), byte=i, role=role):
                    o = self.flip(va + i)
                    errs = iv.check(bytes(self.buf), require_sha=False)
                    self.buf[o] ^= 0xFF
                    self.assertTrue(any(f"{va:#x}" in e for e in errs), errs)

    def test_every_block_caught_by_independent_verify(self):
        for va, n, _sha, role in iv.BLOBS:
            for i in (0, n // 2, n - 1):
                with self.subTest(va=hex(va), byte=i, role=role):
                    o = self.flip(va + i)
                    errs = iv.check(bytes(self.buf), require_sha=False)
                    self.buf[o] ^= 0xFF
                    self.assertTrue(any(f"{va:#x}" in e for e in errs), errs)

    def test_every_key_va_caught_by_tool(self):
        for va, hx, _kind, _tgt, role in iv.KEYS:
            with self.subTest(va=hex(va), role=role):
                o = self.flip(va + len(hx) // 2 - 1)
                try:
                    out = tool.render(tool.analyse(bytes(self.buf), require_sha=False,
                                                   extents=self.extents, check_refs=False))
                    changed = hashlib.sha256(out.encode()).hexdigest() != OUTPUT_SHA256
                except ValueError:
                    changed = True
                self.buf[o] ^= 0xFF
                self.assertTrue(changed)

    def test_byte_swap_removed_is_rejected(self):
        va = 0x37f40d8                     # rol cx,0x8 in leaf1 entry loop
        o = self.off(va)
        self.assertEqual(self.buf[o:o + 4], bytes.fromhex("66c1c108"))
        self.buf[o:o + 4] = b"\x90" * 4
        with self.assertRaises(ValueError):
            tool.analyse(bytes(self.buf), require_sha=False, extents=self.extents, check_refs=False)

    def test_bound_change_changes_output(self):
        o = self.off(0x37f4120 + 2)        # cmp rax,0x401 imm32
        self.assertEqual(struct.unpack_from("<I", self.buf, o)[0], 0x401)
        struct.pack_into("<I", self.buf, o, 0x403)
        out = tool.analyse(bytes(self.buf), require_sha=False, extents=self.extents, check_refs=False)
        self.assertEqual(out["leaves"][0]["lattice_entry_add"]["u16_words_total"], 1026)

    def test_xof_len_change_rejected(self):
        o = self.off(0x37f408a + 1)
        struct.pack_into("<I", self.buf, o, 0x801)
        with self.assertRaises(ValueError):
            tool.analyse(bytes(self.buf), require_sha=False, extents=self.extents, check_refs=False)

    def test_sha_gate(self):
        with self.assertRaises(ValueError):
            tool.analyse(self.data[:-1] + bytes([self.data[-1] ^ 0xFF]), extents=self.extents, check_refs=False)



class ReferenceClosureTamper(Base):
    """A new reference into the closure, or a lost one, must fail both checkers."""
    INJECT = 0x1400000                     # arbitrary .text VA outside every pinned function

    def _with_call(self, site, target, op=0xE8):
        buf = bytearray(self.data)
        o = self.off(site)
        buf[o:o + 5] = bytes([op]) + struct.pack("<i", target - (site + 5))
        return bytes(buf)

    def test_injected_call_to_each_closure_function_rejected(self):
        for tgt in (0x37f3f00, 0x3443160, 0x38ba780, 0x3bc4a40, 0x32699c0, 0x3269ae0):
            for op in (0xE8, 0xE9):
                with self.subTest(target=hex(tgt), op=hex(op)):
                    data = self._with_call(self.INJECT, tgt, op)
                    with self.assertRaises(ValueError):
                        tool.analyse(data, require_sha=False, extents=self.extents)
                    errs = iv.check_refs(data)
                    self.assertTrue(any(f"{tgt:#x}: reference sites" in e for e in errs), errs)

    def test_removed_rayon_to_leaf_call_rejected(self):
        buf = bytearray(self.data)
        o = self.off(0x344320e)
        buf[o] = 0x90                      # e8 -> nop: leaf1 loses its only caller
        with self.assertRaises(ValueError):
            tool.analyse(bytes(buf), require_sha=False, extents=self.extents)
        errs = iv.check_refs(bytes(buf))
        self.assertTrue(any("0x37f3f00: reference sites" in e for e in errs), errs)

    def test_pinned_reference_constant_mutation_rejected(self):
        saved = iv.REFS[0x37f3f00]
        try:
            iv.REFS[0x37f3f00] = ((0x344320f, "call", 0x3443160),)
            self.assertTrue(any("0x37f3f00" in e for e in iv.check_refs(self.data)))
        finally:
            iv.REFS[0x37f3f00] = saved

    def test_exact_counts(self):
        rc = json.loads((PACKET / "lthash-mechanism.json").read_text())["reference_closure"]
        self.assertEqual(rc["counts"], {"closure_functions_per_leaf": [11, 11, 11],
                                        "closure_edges_per_leaf": [16, 16, 16],
                                        "writer_callers": 3, "top_function_callers": 2})
        self.assertEqual(rc["writer_refs"], [["0x326a2e0", "call", "0x3269ae0"],
                                             ["0x326aff3", "call", "0x326aec0"],
                                             ["0x32fc267", "call", "0x32fc190"]])
        self.assertEqual(len(iv.REFS), 32)
        self.assertEqual(sum(len(v) for v in iv.REFS.values()), 53)


class SlotLabels(Base):
    """The corrected GOT slot labels are pinned exactly; the old labels are rejected."""
    OLD = {0x57700c0: "blake3 new slot 0x57700c0", 0x57700b0: "blake3 finalize_xof slot 0x57700b0"}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.vf = load("re009c_verify", PACKET / "verify.py")
        cls.packet = json.loads((PACKET / "lthash-mechanism.json").read_text())

    def _relabel(self, slot, role):
        p = json.loads(json.dumps(self.packet))
        for row in p["blake3_slots"]:
            if row["slot"] == hex(slot):
                row["role"] = role
        return p

    def test_pinned_labels_accepted(self):
        self.assertEqual(self.vf.slot_errors(self.packet), [])
        self.assertEqual(iv.check_slots(self.data, self.packet), [])

    def test_old_labels_rejected(self):
        for slot, old in self.OLD.items():
            with self.subTest(slot=hex(slot)):
                p = self._relabel(slot, old)
                self.assertTrue(self.vf.slot_errors(p))
                self.assertTrue(any("blake3 slot table" in e for e in iv.check_slots(self.data, p)))

    def test_old_leaf_slot_keys_rejected(self):
        p = json.loads(json.dumps(self.packet))
        p["leaves"][0]["blake3_slots"] = {"new": "0x57700c0", "update": "0x57700c8",
                                          "finalize_xof": "0x57700b0"}
        self.assertTrue(any("slot keys" in e for e in self.vf.slot_errors(p)))

    def test_slot_relocation_retarget_rejected(self):
        secs = iv.section_table(self.data)
        _ra, ro, rz = secs[".rela.dyn"]
        buf = bytearray(self.data)
        for j in range(ro, ro + rz - 23, 24):
            if struct.unpack_from("<Q", buf, j)[0] == 0x57700c0:
                struct.pack_into("<q", buf, j + 16, 0x14fa221)
                break
        else:
            self.fail("slot relocation not found")
        self.assertTrue(any("0x57700c0" in e for e in iv.check_slots(bytes(buf))))
        with self.assertRaises(ValueError):
            tool.slot_table(bytes(buf))

    def test_slot_target_bytes_tamper_rejected(self):
        for va, hx in iv.SLOT_TARGET_BYTES:
            with self.subTest(va=hex(va)):
                buf = bytearray(self.data)
                buf[self.off(va)] ^= 0xFF
                self.assertTrue(any(f"{va:#x}" in e for e in iv.check_slots(bytes(buf))))


if __name__ == "__main__":
    unittest.main()
