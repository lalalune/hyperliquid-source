import hashlib
import itertools
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_state_load_chain115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-016-state-load-chain-115"


class StateLoadChain115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.mat.Image(tool.BINARY.read_bytes())
        cls.ev, cls.calls, cls.drops, cls.decoded = tool.static_evidence(cls.image)
        cls.drops = sorted(set(cls.drops) | set(tool.mat.static_evidence(cls.image)[3]))
        cls.cases = list(itertools.islice(tool.all_cases(), 72))

    def test_regenerated_evidence_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(pathlib.Path(tmp))
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["cases"], 12000)
            self.assertEqual(summary["negative_controls"]["detected"], summary["negative_controls"]["total"])
            self.assertGreaterEqual(summary["negative_controls"]["total"], 30)
            names = sorted(p.name for p in PACKET.iterdir() if p.suffix in (".tsv", ".json"))
            self.assertEqual(names, sorted(p.name for p in pathlib.Path(tmp).iterdir()))
            for name in names:
                self.assertEqual((pathlib.Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_manifest(self):
        listed = {}
        for row in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = row.split("  ", 1)
            listed[name] = digest
        self.assertEqual(sorted(listed), sorted(p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"))
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_measure_matches_summary(self):
        measure = json.loads((PACKET / "measure.json").read_text())
        summary = json.loads((PACKET / "summary.json").read_text())
        self.assertEqual(measure["cases"], summary["cases"])
        self.assertEqual(measure["negative_controls"], summary["negative_controls"]["total"])
        self.assertEqual(measure["negative_detected"], summary["negative_controls"]["detected"])

    def test_static_slots_and_sizes(self):
        slots = self.ev["slots"]
        self.assertEqual(slots["loader"]["call_sites"], ["0x2b41f2d"])
        self.assertEqual(slots["boundary"]["call_sites"], ["0x3c128a2"])
        self.assertEqual(slots["materializer"]["call_sites"], ["0x3c13665"])
        self.assertIn("0x3c135c2", slots["builder"]["call_sites"])
        self.assertEqual(self.ev["sizes"], {"input": 0x27a8, "output": 0x42c8})
        self.assertEqual([self.ev["functions"][n]["fde_bytes"] for n in ("loader", "boundary", "builder")],
                         [757, 233, 221])

    def test_frame_offsets(self):
        self.assertEqual((tool.L, tool.A_COPY, tool.B_COPY, tool.O), (-0xb0, -0x120, -0x100, -0x4400))

    def test_model_agrees_with_machine_code(self):
        n, bad, classes, machine = tool.evaluate(self.image, self.drops, self.cases)
        self.assertEqual((n, bad), (72, 0))
        self.assertGreaterEqual(len(classes), 16)
        for outcome in ("ok/returned", "err/unwrap_failed", "neg-overflow/panic_neg", "ok-allocfail/alloc_error",
                        "ok-assertfail/assert_failed", "ok-once/returned"):
            self.assertIn(outcome, classes)

    def test_every_model_mutant_is_caught(self):
        for name in tool.MODEL_MUTANTS:
            _, bad, _, _ = tool.evaluate(self.image, self.drops, self.cases, mut=frozenset([name]), stop_on_first=True)
            self.assertTrue(bad, name)

    def test_code_byte_mutants_are_caught(self):
        for va, old, new, what in tool.BYTE_MUTANTS:
            self.assertEqual(self.image.code(va, 1)[0], old, what)
            _, bad, _, _ = tool.evaluate(self.image, self.drops, self.cases, override={va: new}, stop_on_first=True)
            self.assertTrue(bad, what)

    def test_saturation_and_flag_fields(self):
        by_mode = {}
        for c in self.cases:
            by_mode.setdefault(c["cmode"], c)
        calls, term, ret, heap, _ = tool.model(by_mode["ok-sat"])
        self.assertIsNone(term)
        self.assertEqual(ret, tool.HEAP_AT)
        self.assertEqual(int.from_bytes(heap[0x18:0x20], "little"), tool.M64)   # saturates instead of wrapping
        self.assertEqual(heap[0x39b0], 2)
        self.assertEqual(heap[0x3e28:0x3e2a], bytes(2))
        _, bad, _, _ = tool.evaluate(self.image, self.drops, [by_mode["ok-sat"]], mut=frozenset(["inc_wrap"]))
        self.assertEqual(bad, 1)

    def test_wrong_inputs_are_rejected(self):
        corrupt = bytearray(self.image.data)
        corrupt[self.image.text["offset"] + 7] ^= 1
        with self.assertRaises(tool.ToolError):
            tool.mat.Image(bytes(corrupt))
        with self.assertRaises(tool.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"] + 0x100, 4)

    def test_wrong_slot_target_is_rejected(self):
        saved = dict(self.image.relative)
        try:
            self.image.relative[tool.SLOT_BOUNDARY] = tool.BUILDER
            with self.assertRaises(tool.ToolError):
                tool.static_evidence(self.image)
        finally:
            self.image.relative.clear()
            self.image.relative.update(saved)

    def test_case_stream_is_deterministic(self):
        again = list(itertools.islice(tool.all_cases(), 18))
        for a, b in zip(self.cases, again):
            self.assertEqual(hashlib.sha256(a["in"] + a["composed"]).digest(), hashlib.sha256(b["in"] + b["composed"]).digest())
            self.assertEqual((a["w"], a["p"], a["n"], a["b"]), (b["w"], b["p"], b["n"], b["b"]))


if __name__ == "__main__":
    unittest.main()
