import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_call_host115 as t  # noqa: E402


class CallHost115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.runs = {w: t.Run(cls.image, w) for w in ("alt", "ord")}

    def use(self, which):
        t.HOST_RANGE = (t.HOSTS[which]["start"], t.HOSTS[which]["start"] + t.HOST_LEN)
        return self.runs[which]

    def pool(self, which, n, label="test"):
        run = self.use(which)
        return run, [c for _, c in t.stream_cases(n, label + which, run.keccak_empty)]

    def test_wrong_digest_rejected(self):
        data = bytearray(t.BINARY.read_bytes())
        data[self.image.text["offset"] + 1] ^= 0x40
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_both_hosts_match_model(self):
        for which in ("alt", "ord"):
            run, cases = self.pool(which, 250)
            for i, c in enumerate(cases):
                obs, mod = run.observe(c), t.model(c, run.keccak_empty)
                self.assertIsNone(t.compare(c, obs, mod), (which, i))

    def test_outcome_kinds_are_exercised(self):
        run, cases = self.pool("alt", 300, "kinds")
        kinds = set()
        for c in cases:
            m = t.model(c, run.keccak_empty)
            kinds.add(m["kind"] if m["kind"] != "ok" else ("err" if m["out"]["err"] else "fill"))
        self.assertTrue({"err", "fill", "panic:ud2", "panic:64df570"} <= kinds, kinds)

    def test_model_mutants_detected(self):
        for which in ("alt", "ord"):
            run, cases = self.pool(which, 150, "ctl")
            obs = [run.observe(c) for c in cases]
            for mu in ("err36", "inc2", "spec6", "ge", "unsat", "div2", "flagneg", "off2"):
                hit = any(t.compare(c, o, t.model(c, run.keccak_empty, frozenset([mu]))) for c, o in zip(cases, obs))
                self.assertTrue(hit, (which, mu))

    def test_corrupted_code_byte_detected(self):
        run, cases = self.pool("alt", 150, "cor")
        sites = t.jcc_sites(self.image, "alt")
        va, op, _ = sites[0]
        bad = t.Run(self.image, "alt", override={va: op ^ 1})
        found = False
        for c in cases:
            try:
                found = bool(t.compare(c, bad.observe(c), t.model(c, run.keccak_empty)))
            except (t.ToolError, t.Boundary, KeyError, AssertionError):
                found = True
            if found:
                break
        self.assertTrue(found)

    def test_out_of_range_inputs_rejected(self):
        with self.assertRaises(t.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"] + 16, 4)
        with self.assertRaises(t.ToolError):
            t.decode(bytes([0x0f, 0x04]) + bytes(14), 0x1000)

    def test_extra_decode_forms(self):
        f = t.decode(bytes.fromhex("f0ff0e") + bytes(13), 0x1000)
        self.assertTrue(f["lock"] and f["len"] == 3)
        self.assertEqual(t.decode(bytes.fromhex("f6d2") + bytes(14), 0)["op"], 0x1f6)
        self.assertEqual(t.decode(bytes.fromhex("48f7f6") + bytes(13), 0)["op"], 0x1f7)
        self.assertEqual(t.decode(bytes.fromhex("660febc8") + bytes(12), 0)["op"], 0x0feb)
        self.assertEqual(t.decode(bytes.fromhex("0f50c8") + bytes(13), 0)["op"], 0x0f50)

    def test_signed_saturation(self):
        self.assertEqual(t.sat_s64((1 << 63) - 1, 1), (1 << 63) - 1)
        self.assertEqual(t.sat_s64(1 << 63, (1 << 64) - 1), 1 << 63)
        self.assertEqual(t.sat_s64(5, 7), 12)


if __name__ == "__main__":
    unittest.main()
