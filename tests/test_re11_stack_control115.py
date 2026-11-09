import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_stack_control115 as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-011-stack-control-flow-115"


def ps_case(op, length, words=None, spec=0x14, code=b"", ptr=0):
    if words is None:
        words = {i: 0x1000 + i for i in range(max(0, length - t.PS_WINDOW), length)}
    return {"op": op, "spec": spec, "mode": "unit", "len": length, "words": words, "ptr": ptr,
            "code": code + bytes(t.PS_TRAIL)}


class StackControl115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.cases = {fam.key: fam.cases() for fam in t.FAMILIES}
        cls.full = {}
        for fam in t.FAMILIES:
            cls.full[fam.key] = t.evaluate(fam, cls.image, cases=cls.cases[fam.key])

    def detected(self, fam, mut=frozenset(), override=None):
        # scan the full case list until the first mismatch, so rare paths are not sampled away
        _, bad, _ = t.evaluate(fam, self.image, override=override, mut=mut, stop_on_first=True,
                               cases=self.cases[fam.key])
        return bad > 0

    # ---------------------------------------------------------------- shared input checks
    def test_wrong_digest_rejected(self):
        data = bytearray(self.image.data)
        data[self.image.text["offset"] + 1] ^= 0x40
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_code_outside_text_rejected(self):
        end = self.image.text["address"] + self.image.text["size"]
        for va, n in ((end, 1), (end + 0x10, 4), (end - 2, 4)):
            with self.assertRaises(t.ToolError):
                self.image.code(va, n)

    def test_family_rejects_other_opcodes(self):
        for op in (0x5e, 0xa0, 0x00):
            with self.assertRaises(t.ToolError):
                t.ps_kind(op)

    def test_shared_layout(self):
        layout = t.shared_layout()
        self.assertEqual(layout["code_cursor"], "0x118")
        self.assertEqual(layout["spec_byte"], "0x1a9")
        self.assertEqual(layout["stack_limit"], "0x400")
        saved = t.SHARED_LAYOUT["code_cursor"]
        try:
            t.SHARED_LAYOUT["code_cursor"] = (0x118, 0x120)
            with self.assertRaises(t.ToolError):
                t.shared_layout()
        finally:
            t.SHARED_LAYOUT["code_cursor"] = saved

    # ---------------------------------------------------------------- PUSH / DUP / SWAP static evidence
    def test_ps_static_constants(self):
        consts, decoded = t.ps_static_evidence(self.image)
        funcs = consts["functions"]
        self.assertEqual(len(funcs), 64)
        self.assertNotIn("0x2995ab0", funcs)
        self.assertEqual(funcs["0x2997060"]["instructions"], 19)
        self.assertEqual(funcs["0x29965c0"]["instructions"], 26)
        self.assertEqual(funcs["0x2995bf0"]["instructions"], 16)
        self.assertEqual(funcs["0x2997060"]["derived"]["spec_gate"], 0xa)
        self.assertEqual(funcs["0x2997060"]["derived"]["length_compare"], 0x400)
        self.assertEqual(funcs["0x2995d70"]["derived"]["length_compare"], 1007)
        self.assertEqual(funcs["0x2996dc0"]["derived"]["stack_offsets"], [-544, -528, -32, -16])
        for op in t.PS_OPS:
            d = funcs[f"{t.PS_BODIES[op]:#x}"]["derived"]
            if 0x60 <= op <= 0x7f:
                self.assertEqual(d["code_advance"], op - 0x5f)
        slots = consts["opcode_table_slots"]
        for op in list(t.PS_OPS) + [0x81]:
            self.assertEqual(slots[f"0x6441210+{8 * op:#x}"], slots[f"0x6441f00+{8 * op:#x}"])
        self.assertEqual(slots["0x6441210+0x408"], {"opcode": "0x81", "target": "0x2995ab0", "excluded": True})
        self.assertEqual(sorted(decoded), sorted(t.PS_BODIES.values()))

    def test_ps_wrong_opcode_slot_rejected(self):
        saved = dict(self.image.relative)
        try:
            self.image.relative[0x6441f00 + 8 * 0x90] = 0x2997020
            with self.assertRaises(t.ToolError):
                t.ps_opcode_slots(self.image)
        finally:
            self.image.relative = saved

    def test_ps_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x2997066 - sec["address"] + sec["offset"]] = 0x0b
        with self.assertRaises(t.ToolError):
            t.ps_static_evidence(t.Image(bytes(data), check=False))

    def test_ps_rejects_changed_family_constant(self):
        # PUSH17 advancing by 16 contradicts the family rule even though no CHECKED byte names it
        data = bytearray(self.image.data)
        sec = self.image.text
        start = t.PS_BODIES[0x70]
        body = self.image.code(start, 92)
        at = start + body.index(bytes.fromhex("4883c111"))
        data[at + 3 - sec["address"] + sec["offset"]] = 0x10
        with self.assertRaises(t.ToolError):
            t.ps_static_evidence(t.Image(bytes(data), check=False))

    def test_ps_reconstruction_examples(self):
        w = t.ps_model(ps_case(0x62, 5, code=bytes.fromhex("0a0b0c")))
        self.assertEqual((w["ret"], w["len"], w["ptr"], w["words"][5], w["reads"]), (0, 6, 3, 0x0a0b0c, [0, 1, 2]))
        self.assertEqual(t.ps_model(ps_case(0x5f, 3, spec=9))["ret"], t.PS_R_NOT_ACTIVATED)
        self.assertEqual(t.ps_model(ps_case(0x5f, 1024))["ret"], t.PS_R_OVERFLOW)
        self.assertEqual(t.ps_model(ps_case(0x5f, 1025))["ret"], t.PS_R_OK)  # equality check only
        self.assertEqual(t.ps_model(ps_case(0x60, 1024, code=b"\x01"))["ret"], t.PS_R_OVERFLOW)
        self.assertEqual(t.ps_model(ps_case(0x80, 0))["ret"], t.PS_R_OVERFLOW)  # DUP underflow reported as 0x2d
        self.assertEqual(t.ps_model(ps_case(0x8f, 15))["ret"], t.PS_R_OVERFLOW)
        self.assertEqual(t.ps_model(ps_case(0x8f, 16))["words"][16], 0x1000)
        self.assertEqual(t.ps_model(ps_case(0x8f, 1024))["ret"], t.PS_R_OVERFLOW)
        self.assertEqual(t.ps_model(ps_case(0x90, 1))["ret"], t.PS_R_UNDERFLOW)
        s = t.ps_model(ps_case(0x9f, 17))
        self.assertEqual((s["ret"], s["len"], s["words"][16], s["words"][0]), (0, 17, 0x1000, 0x1010))
        self.assertEqual(t.ps_model(ps_case(0x9f, 1500))["ret"], t.PS_R_OK)  # no upper check

    def test_ps_unit_cases_match_bytes(self):
        m = t.ps_CodeMachine(self.image)
        units = [ps_case(0x62, 5, code=bytes.fromhex("0a0b0c"), ptr=0), ps_case(0x5f, 1025), ps_case(0x80, 0),
                 ps_case(0x9f, 17), ps_case(0x7f, 7, code=bytes(range(1, 33))), ps_case(0x5f, 3, spec=9)]
        for c in units:
            with self.subTest(op=hex(c["op"]), length=c["len"]):
                self.assertTrue(t.ps_compare(c, t.ps_model(c), t.ps_run_case(m, c)))

    def test_ps_all_cases_and_full_coverage(self):
        rows, bad, m = self.full[t.PS.key]
        self.assertEqual((len(rows), bad), (6400, 0))
        seen = {t.ps_outcome(c, got) for _, c, want, got, _ in rows}
        for want in ("PUSH0/ok", "PUSH0/not-activated", "PUSH0/overflow", "PUSH0/ok-beyond-1024", "PUSH1/overflow",
                     "PUSH32/ok", "DUP1/underflow-reported-as-overflow", "DUP16/overflow", "DUP3/ok",
                     "SWAP1/underflow", "SWAP16/ok", "SWAP16/ok-beyond-1024"):
            self.assertIn(want, seen)
        _, decoded = t.ps_static_evidence(self.image)
        missed = [va for body in decoded.values() for va, fm in body if fm is not None and va not in m.seen]
        self.assertEqual(missed, [])

    def test_ps_corrupted_results_detected(self):
        c = dict(self.cases[t.PS.key][0])
        want = t.ps_model(c)
        got = t.ps_run_case(t.ps_CodeMachine(self.image), c)
        self.assertTrue(t.ps_compare(c, want, got))
        self.assertFalse(t.ps_compare(c, want, dict(got, stack_raw=bytes([got["stack_raw"][0] ^ 1])
                                                    + got["stack_raw"][1:])))
        self.assertFalse(t.ps_compare(c, want, dict(got, ptr=got["ptr"] + 1)))
        self.assertFalse(t.ps_compare(c, want, dict(got, code_reads=got["code_reads"] + [99])))

    # ---------------------------------------------------------------- control flow static evidence
    def test_cf_static_evidence(self):
        consts, _ = t.cf_static_evidence(self.image)
        funcs = consts["functions"]
        self.assertEqual(len(funcs), 11)
        self.assertEqual(funcs["0x2999610"]["instructions"], 46)
        self.assertEqual(funcs["0x2997120"]["calls"], 1)
        self.assertEqual(funcs["0x2999580"]["calls"], 0)
        self.assertEqual(sum(f["instructions"] for f in funcs.values()), 251)
        self.assertEqual(funcs["0x2995e10"]["spec_gate"], "0xe")
        self.assertEqual(len(consts["opcode_table_slots"]), 22)
        self.assertEqual(consts["undefined_opcode_count"], 102)
        self.assertEqual(consts["decode_single_accepted"], 219)
        self.assertEqual(consts["decode_pair_accepted"], 210)
        self.assertEqual(consts["decode_pair_panic_immediates"], [])
        self.assertNotIn(t.CF_PANIC_SLOT, self.image.imports)

    def test_cf_changed_checked_byte_fails(self):
        va = t.CF_CHECKED[5][0]
        data = bytearray(self.image.data)
        data[self.image.text["offset"] + va - self.image.text["address"]] ^= 1
        with self.assertRaises(t.ToolError):
            t.cf_static_evidence(t.Image(bytes(data), check=False))

    def test_cf_wrong_table_slot_fails(self):
        bad = t.Image(self.image.data)
        bad.relative = dict(bad.relative)
        bad.relative[t.OP_TABLES[1] + 8 * 0xe7] = 0x2995e10
        with self.assertRaises(t.ToolError):
            t.cf_static_evidence(bad)

    def test_cf_all_cases_match(self):
        rows, bad, m = self.full[t.CF.key]
        self.assertEqual((len(rows), bad), (6000, 0))
        _, decoded = t.cf_static_evidence(self.image)
        for start, insns in decoded.items():
            for va, f in insns:
                if f is None:
                    continue
                if va in t.EXPECTED_NOT_EXECUTED:
                    self.assertNotIn(va, m.seen)
                else:
                    self.assertIn(va, m.seen, f"{va:#x} in {start:#x} not executed")

    def test_cf_immediate_decoders(self):
        self.assertEqual(t.cf_decode_single(0x00), 0x91)
        self.assertEqual(t.cf_decode_single(0x5a), 0xeb)
        self.assertIsNone(t.cf_decode_single(0x5b))
        self.assertIsNone(t.cf_decode_single(0x7f))
        self.assertEqual(t.cf_decode_single(0x80), 0x11)
        self.assertEqual(t.cf_decode_single(0xff), 0x90)
        self.assertEqual(t.cf_decode_pair(0x8f), (0, 29))
        self.assertEqual(t.cf_decode_pair(0x51), (13, 15))
        self.assertEqual(t.cf_decode_pair(0x80), (0, 0x10))
        self.assertIsNone(t.cf_decode_pair(0x52))
        for x in range(256):
            pair = t.cf_decode_pair(x)
            if pair is not None:
                self.assertLess(pair[0], pair[1])

    # ---------------------------------------------------------------- negative controls of both families
    def test_model_mutants_detected(self):
        for fam in t.FAMILIES:
            for nm in fam.model_mutants:
                with self.subTest(family=fam.key, name=nm):
                    self.assertTrue(self.detected(fam, mut=frozenset([nm])))

    def test_code_mutants_detected(self):
        for fam in t.FAMILIES:
            for va, byte, _ in fam.byte_mutants:
                with self.subTest(family=fam.key, va=hex(va)):
                    self.assertNotEqual(self.image.code(va, 1)[0], byte)
                    self.assertTrue(self.detected(fam, override={va: byte}))

    def test_input_controls_detected(self):
        rows = t.input_controls(self.image)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r[3] == 1 for r in rows))

    def test_evidence_files_reproduce(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, PYTHONHASHSEED="7", TZ="Asia/Seoul")
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "re11_stack_control115.py"), "--out", tmp],
                               env=env, capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            names = sorted(os.listdir(tmp))
            self.assertEqual(names, sorted(p.name for p in FOLDER.iterdir()
                                           if p.name not in ("README.md", "MANIFEST.sha256")))
            for name in names:
                self.assertEqual((pathlib.Path(tmp) / name).read_bytes(), (FOLDER / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main()
