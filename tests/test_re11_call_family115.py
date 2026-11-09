import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_call_family115 as t  # noqa: E402


class CallFamily115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())

    def detected(self, mut=frozenset(), override=None, only=None):
        # scan the case list in order until the first mismatch, so rare paths are not sampled away
        _, bad, _ = t.evaluate(self.image, override=override, mut=mut, stop_on_first=True, only=only)
        return bad > 0

    def test_wrong_digest_rejected(self):
        data = bytearray(t.BINARY.read_bytes())
        data[self.image.text["offset"] + 1] ^= 0x40
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_code_outside_text_rejected(self):
        end = self.image.text["address"] + self.image.text["size"]
        with self.assertRaises(t.ToolError):
            self.image.code(end + 0x10, 4)
        with self.assertRaises(t.ToolError):
            self.image.code(end - 2, 4)

    def test_static_constants(self):
        consts, decoded = t.static_evidence(self.image)
        self.assertEqual(sorted(decoded), sorted(list(t.EXTENTS) + [t.HELPER]))
        self.assertEqual(consts["functions"]["0x299a8f0"]["fde_end"], "0x299ac93")
        self.assertEqual(consts["functions"]["0x29998f0"]["fde_bytes"], 525)
        for entry in t.EXTENTS:
            self.assertIn("0x29998f0", consts["direct_calls"][f"{entry:#x}"].values())
        slots = consts["opcode_table_slots"]
        self.assertEqual(slots["0x6441210+0x788"], {"opcode": "0xf1", "family": "CALL", "table": "alt", "target": "0x299a8f0"})
        self.assertEqual(slots["0x6441f00+0x7d0"]["target"], "0x2999e70")
        self.assertEqual(consts["got_slots"]["0x64e6e08"], "0x546c330")
        self.assertEqual(consts["got_slots"]["0x64e6e00"], "0x4335cf0")
        self.assertEqual(consts["got_slots"]["0x64df508"], "memcpy")

    def test_twin_bodies_differ_only_in_host_slot(self):
        consts, _ = t.static_evidence(self.image)
        for fam, row in consts["alt_vs_ordinary"].items():
            self.assertTrue(row["same_instruction_lengths"], fam)
            self.assertEqual(row["differing_after_masking_displacements"], [], fam)
            self.assertEqual(row["indirect_call_slots_that_differ"], ["0x64e6e08->0x64e6e00"], fam)

    def test_wrong_opcode_slot_rejected(self):
        saved = dict(self.image.relative)
        try:
            self.image.relative[0x6441210 + 8 * 0xf1] = 0x299aca0
            with self.assertRaises(t.ToolError):
                t.static_evidence(self.image)
        finally:
            self.image.relative = saved

    def test_address_is_big_endian_160_bits(self):
        self.assertEqual(t.addr20((1 << 160) | 0x0102), bytes(18) + b"\x01\x02")
        self.assertEqual(t.addr20(0xaa << 152 | 1), b"\xaa" + bytes(18) + b"\x01")

    def test_range_model_examples(self):
        # words are given top first: input offset, input length, output offset, output length
        ok = t.range_model([5, 10, 7, 3], 100, 0x20, [])
        self.assertEqual(ok[:2], ("ok", (0x25, 0x2f, 7, 10)))
        self.assertEqual(ok[2], [])
        # an empty range yields the all-ones sentinel for both ends and ignores the offset
        self.assertEqual(t.range_model([1 << 200, 0, 0, 0], 0, 0, [])[:2], ("ok", (t.M64, t.M64, t.M64, t.M64)))
        # growth is asked for ceil(end / 32) words only when that exceeds the current size
        self.assertEqual(t.range_model([0, 33, 0, 0], 1, 0, [0])[2], [("expand", 2)])
        self.assertEqual(t.range_model([0, 33, 0, 0], 2, 0, [])[2], [])
        # a failing grow returns its status; a long length is 0x24; offset+length overflow panics
        self.assertEqual(t.range_model([0, 40, 0, 0], 0, 0, [0x21])[:2], ("err", 0x21))
        self.assertEqual(t.range_model([0, 1 << 64, 0, 0], 0, 0, [])[:2], ("err", 0x24))
        self.assertEqual(t.range_model([t.M64, 2, 0, 0], 1 << 60, 0, [])[:2], ("panic", "overflow"))

    def test_model_status_arms(self):
        s = t.Stream("unit")
        c = t.make_case(s, "CALL", "alt", 4)
        c.update(n=2, stack=[1, 2])
        self.assertEqual(t.model(c)["ret"], ("ret", 0x2c))
        c = t.make_case(s, "DELEGATECALL", "alt", 4)
        it = bytearray(c["interp"])
        it[t.I_SPEC] = 0
        c["interp"] = bytes(it)
        self.assertEqual(t.model(c)["ret"], ("ret", 0x2b))

    def test_sample_matches(self):
        m = t.Machine(self.image)
        bad = 0
        for i, c in enumerate(t.all_cases()):
            if i % 11:
                continue
            bad += not t.compare(t.model(c), t.run_case(m, c))
        self.assertEqual(bad, 0)

    def test_every_body_reaches_success_and_error_arms(self):
        seen = {}
        for c in t.all_cases():
            seen.setdefault((c["fam"], c["tbl"]), set()).add(t.outcome(c, t.model(c)).split("/")[0])
        for key, outs in seen.items():
            self.assertTrue({"action-queued", "stack-underflow", "range-too-large", "host-error"} <= outs, (key, outs))

    def test_model_mutants_are_detected(self):
        for name in ("addr_le", "no_shift", "dg_tag0", "keep_old", "overflow_clamp", "pops_minus"):
            self.assertTrue(self.detected(frozenset([name])), name)

    def test_unused_mutant_name_is_not_a_detection(self):
        self.assertFalse(self.detected(frozenset(["not-a-mutant"]), only={("CALL", "alt")}))

    def test_code_mutants_are_detected(self):
        for va, old, new, what, bodies in t.BYTE_MUTANTS[::6]:
            self.assertEqual(self.image.code(va, 1)[0], old, what)
            self.assertTrue(self.detected(override={va: new}, only=set(bodies)), what)

    def test_hole_bytes_follow_the_stack_fill(self):
        res = t.hole_check(self.image, count=60)
        self.assertTrue(res["match"], res)

    @staticmethod
    def success_case(fam, pend="none", static=0, value=5, tag=0):
        c = t.make_case(t.Stream("unit-success"), fam, "alt", 4)
        it = bytearray(c["interp"])
        it[t.I_SPEC] = 9
        it[t.I_STATIC] = static
        t.put(it, t.I_MEMWORDS, 8, 1 << 40)
        t.put(it, t.I_SHIFT, 8, 0x100)
        words = [0x40, 8, 0x10, 4, value, 0x1234, 1000]  # bottom first: out len/off, in len/off, value, address, gas
        if t.FAMILY[fam]["pops"] == 2:
            words = words[:4] + [0x1234, 1000]
        t.put(it, t.I_STACK_LEN, 8, len(words))
        if pend == "none":
            it[t.I_PSTATE] = 0x38
        elif pend == "arc":
            it[t.I_PSTATE] = 0
            t.put(it, t.I_PENDING, 8, 1)
        elif pend == "vt":
            it[t.I_PSTATE] = 7
            t.put(it, t.I_PENDING, 8, t.VT_AT)
        c.update(interp=bytes(it), n=len(words), stack=words, expand=[0, 0], alloc_fail=False)
        c["host"] = dict(c["host"], tag=tag)
        return c

    def test_success_arm_and_record_fields(self):
        for fam in t.FAMILY:
            c = self.success_case(fam)
            w = t.model(c)
            self.assertEqual(w["ret"], ("ret", 4), fam)
            rec = w["box"]
            self.assertEqual(rec[0], t.FAMILY[fam]["tag"], fam)
            self.assertEqual(rec[0xce], t.FAMILY[fam]["scheme"], fam)
            self.assertEqual(bytes(rec[0x90:0xa4]), t.addr20(0x1234), fam)
            self.assertEqual(int.from_bytes(bytes(rec[0x58:0x60]), "little"), 4 + 0x100, fam)  # input offset plus the +0x18 shift value
            self.assertEqual(t.u(w["interp"], t.I_PENDING, 8), 1)
            self.assertEqual(t.u(w["interp"], t.I_PSTATE, 1), 0)
            self.assertEqual(w["events"][-2:], [("alloc", 0xd0), ("memcpy", 0xd0)], fam)
            self.assertTrue(t.compare(w, t.run_case(t.Machine(self.image), dict(c, tbl="alt"))), fam)

    def test_host_flags_per_family(self):
        flags = {fam: t.model(self.success_case(fam))["events"][0][3:5] for fam in t.FAMILY}
        self.assertEqual(flags, {"CALL": (1, 1), "CALLCODE": (1, 0), "DELEGATECALL": (0, 0), "STATICCALL": (0, 0)})

    def test_static_value_only_blocks_call(self):
        self.assertEqual(t.model(self.success_case("CALL", static=1))["ret"], ("ret", 0x27))
        self.assertEqual(t.model(self.success_case("CALL", static=2))["ret"], ("ret", 4))
        self.assertEqual(t.model(self.success_case("CALL", static=1, value=0))["ret"], ("ret", 4))
        self.assertEqual(t.model(self.success_case("CALLCODE", static=1))["ret"], ("ret", 4))

    def test_pending_action_retirement(self):
        self.assertEqual(t.model(self.success_case("CALL", "arc"))["events"][-1], ("arc_drop", t.u(self.success_case("CALL", "arc")["interp"], t.I_PENDING + 8, 8)))
        self.assertEqual(t.model(self.success_case("CALL", "vt"))["events"][-1][0], "vt_drop")
        self.assertNotIn("vt_drop", [e[0] for e in t.model(self.success_case("CALL", "none"))["events"]])

    def test_host_error_returns_first_byte(self):
        c = self.success_case("STATICCALL", tag=2)
        c["host"] = dict(c["host"], w0=0x1234)
        w = t.model(c)
        self.assertEqual(w["ret"], ("ret", 0x34))
        self.assertEqual(w["events"][-1][0], "host")
        self.assertTrue(t.compare(w, t.run_case(t.Machine(self.image), c)))

    def test_frame_layout_table_is_contiguous(self):
        rows = [r.split("\t") for r in t.frame_layout()[1:]]
        cursor = 0
        for off, ln, _ in rows:
            off, ln = int(off, 16), int(ln)
            self.assertEqual(off, cursor)
            cursor = off + ln
        self.assertEqual(cursor, t.FRAME)

    def test_unknown_family_rejected(self):
        c = dict(t.make_case(t.Stream("x"), "CALL", "alt", 0), fam="NOP")
        with self.assertRaises(KeyError):
            t.run_case(t.Machine(self.image), c)


if __name__ == "__main__":
    unittest.main()
