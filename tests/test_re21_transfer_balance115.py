import itertools
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re21_transfer_balance115 as t  # noqa: E402


def tiny_case(frm, to, value, fbal, tbal, fflag=0, tflag=0, jlen=0, jcap=4, fill=0x21):
    a, b = bytes([1]) * 20, bytes([2]) * 20
    accts = {a: {"bal": fbal, "flag": fflag}}
    if to != frm:
        accts[b] = {"bal": tbal, "flag": tflag}
    return {"mode": "unit", "from": a if frm else b, "to": a if to == frm else b, "value": value, "accts": accts,
            "items": len(accts), "jcap": jcap, "jlen": jlen, "jold": bytes(range(256)) * 2,
            "jbig": bytes([t.JBIG_FILL]) * (t.BIGCAP * t.E_SIZE), "fill": fill, "buckets": 16, "secret": 1, "seed": 3,
            "order": list(accts), "tombs": [], "decoys": [], "same_ptr": False}


class Transfer115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())

    def detected(self, mut=frozenset(), override=None, trace=False):
        run = t.evaluate_trace if trace else t.evaluate
        _, bad, _ = run(self.image, override=override, mut=mut, stop_on_first=True, keep=False)
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
        self.assertEqual(consts["direct_calls"]["0x4322860"]["0x4322ad0"], "0x4323270")
        self.assertEqual(consts["direct_calls"]["0x3ed7e80"], {})
        self.assertEqual(consts["functions"]["0x3ed7e80"]["instructions"], 70)
        self.assertEqual(consts["functions"]["0x4322860"]["instructions"], 285)
        self.assertEqual(consts["functions"]["0x4323270"]["instructions"], 140)
        self.assertEqual(consts["hash_seed"]["target"], "0x64ffe90")
        self.assertFalse(consts["hash_seed"]["target_section_has_file_bytes"])
        self.assertEqual(sorted(decoded), sorted(t.FUNCS))

    def test_changed_check_byte_rejected(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x4322ad7 - sec["address"] + sec["offset"]] = 0x02
        with self.assertRaises(t.ToolError):
            t.static_evidence(t.Image(bytes(data), check=False))

    def test_hash_examples(self):
        addr = bytes(range(1, 21))
        a0 = int.from_bytes(addr[0:8], "little")
        a1 = int.from_bytes(addr[8:16], "little") ^ 1
        p = a0 * a1
        self.assertEqual(t.addr_hash(addr, 0, 1), (p & t.M64) ^ int.from_bytes(addr[16:20], "little") ^ (p >> 64))
        self.assertNotEqual(t.addr_hash(addr, 5, 1), t.addr_hash(addr, 0, 1))
        self.assertEqual(t.addr_hash(addr, 5, 1, frozenset(["hash_no_secret"])), t.addr_hash(addr, 0, 1))

    def test_layout_needs_an_empty_slot(self):
        with self.assertRaises(t.ToolError):
            t.layout(16, [], [], [(i, 1, bytes(20)) for i in range(16)])

    def test_model_transfer_rules(self):
        ok = t.model(tiny_case(1, 0, 5, 9, 7))
        self.assertEqual(ok["ret"], ("ret", t.R_OK))
        self.assertEqual(sorted(v[0] for v in ok["accts"].values()), [4, 12])
        self.assertEqual(ok["head"], (4, 3, False))  # two touches and the transfer entry
        self.assertEqual(len(ok["events"]), 1)
        short = t.model(tiny_case(1, 0, 10, 9, 7))
        self.assertEqual(short["ret"], ("ret", t.R_INSUFFICIENT))
        self.assertEqual(short["head"][1], 1)  # the sender is touched even when the debit fails
        over = t.model(tiny_case(1, 0, 2, 9, t.M256 - 1))
        self.assertEqual(over["ret"], ("ret", t.R_OVERFLOW))
        self.assertEqual(sorted(v[0] for v in over["accts"].values()), [7, t.M256 - 1])  # debited, not credited
        exact = t.model(tiny_case(1, 0, 2, 9, t.M256 - 2))
        self.assertEqual(exact["ret"], ("ret", t.R_OK))
        zero = t.model(tiny_case(1, 0, 0, 0, 7))
        self.assertEqual(zero["head"][1], 1)  # only the receiver is touched
        self.assertEqual(zero["events"], [])
        selfok = t.model(tiny_case(1, 1, 9, 9, 0))
        self.assertEqual(selfok["ret"], ("ret", t.R_OK))
        self.assertEqual(selfok["head"][1], 0)
        self.assertEqual(t.model(tiny_case(1, 1, 10, 9, 0))["ret"], ("ret", t.R_INSUFFICIENT))
        grown = t.model(tiny_case(1, 0, 5, 9, 7, jlen=4, jcap=4))
        self.assertEqual(grown["head"], (t.BIGCAP, 7, True))
        touched = t.model(tiny_case(1, 0, 5, 9, 7, fflag=4, tflag=4))
        self.assertEqual(touched["head"][1], 1)  # already-touched accounts add no touch entries

    def test_model_journal_entry_layout(self):
        c = tiny_case(1, 0, 0x0102, 0x200, 7, fflag=4, tflag=4, fill=0x5a)
        res = t.model(c)
        entry = res["jold"][0:t.E_SIZE]
        self.assertEqual(entry[0], t.TAG_TRANSFER)
        self.assertEqual(entry[1:21], bytes([1]) * 20)
        self.assertEqual(entry[0x15:0x29], bytes([2]) * 20)
        self.assertEqual(entry[0x29:0x30], bytes([0x5a]) * 7)
        self.assertEqual(int.from_bytes(entry[0x30:0x50], "little"), 0x0102)
        self.assertEqual(entry[0x50:], c["jold"][0x50:t.E_SIZE])

    def test_trace_model_record(self):
        c = {"from": bytes([1]) * 20, "to": bytes([2]) * 20, "value": 0x0102, "level": 0x0e, "flag": 0, "vcap": 2,
             "vlen": 1, "vold": bytes(3 * t.REC), "vbig": bytes(t.VBIGCAP * t.REC), "p1": t.P1_AT + 0x10,
             "p2": t.P2_AT + 0x11, "p1mem": bytes(0x100), "p2mem": bytes(0x100), "fill": 0x33}
        res = t.trace_model(self.image, c)
        self.assertEqual(res["vec"], (2, 2, False))
        rec = res["vold"][t.REC:2 * t.REC]
        self.assertEqual(int.from_bytes(rec[0:8], "little"), 3)
        self.assertEqual(int.from_bytes(rec[0x30:0x38], "little"), t.P2_AT + 0x11)  # odd pointer kept as is
        self.assertEqual(rec[0x48:0x4c], bytes.fromhex("ffffffff")[:3] + b"\xfe")
        self.assertEqual(res["p2"][0x11:0x31], (0x0102).to_bytes(32, "big"))
        self.assertEqual(res["p1"][0x10:0x20], bytes.fromhex("ddf252ad1be2c89b69c2b068fc378daa"))
        self.assertEqual(res["p1"][0x10 + 0x2c:0x10 + 0x40], bytes([1]) * 20)
        even = t.trace_model(self.image, dict(c, p2=t.P2_AT + 0x10))
        self.assertEqual(int.from_bytes(even["vold"][t.REC + 0x30:t.REC + 0x38], "little"), t.P2_AT + 0x11)
        low = t.trace_model(self.image, dict(c, level=0x0d))
        self.assertEqual(low["vec"], (2, 1, False))
        gone = t.trace_model(self.image, dict(c, p2=None))
        self.assertEqual(gone["ret"], ("alloc-error", 0x20))

    def test_sample_matches(self):
        _, bad, _ = t.evaluate(self.image, cases=itertools.islice(t.all_cases(), 0, 12000, 7), keep=False)
        self.assertEqual(bad, 0)
        _, bad, _ = t.evaluate_trace(self.image, cases=itertools.islice(t.trace_cases(), 0, 6000, 7), keep=False)
        self.assertEqual(bad, 0)

    def test_outcome_families_present(self):
        seen = set()
        for c in itertools.islice(t.all_cases(), 400):
            got = t.run_case(t.Machine(self.image), c)
            seen.add(t.outcome(c, got))
        for want in ("panic/from-missing", "panic/to-missing", "panic/to-missing-zero", "panic/self-missing",
                     "self/sufficient", "self/insufficient", "transfer/insufficient", "transfer/overflow",
                     "transfer/transferred", "zero-value/ok"):
            self.assertIn(want, seen)

    def test_model_mutants_detected(self):
        for name in t.MODEL_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(self.detected(mut=frozenset([name])))
        for name in t.TRACE_MODEL_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(self.detected(mut=frozenset([name]), trace=True))

    def test_code_mutants_detected(self):
        for va, byte, _ in t.BYTE_MUTANTS:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertTrue(self.detected(override={va: byte}))
        for va, byte, _ in t.TRACE_BYTE_MUTANTS:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertTrue(self.detected(override={va: byte}, trace=True))


if __name__ == "__main__":
    unittest.main()
