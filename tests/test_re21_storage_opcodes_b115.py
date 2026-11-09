import importlib.util
import itertools
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("re21_storage_opcodes_b115", ROOT / "tools" / "re21_storage_opcodes_b115.py")
tool = importlib.util.module_from_spec(spec)
sys.modules["re21_storage_opcodes_b115"] = tool
spec.loader.exec_module(tool)

FOLDER = ROOT / "research" / "work-items" / "RE-021-storage-opcodes-table-b-115"


def sample(every, kinds=None, limit=None):
    out = []
    for i, c in enumerate(tool.all_cases()):
        if i % every == 0 and (kinds is None or c["kind"] in kinds):
            out.append(c)
        if limit and i >= limit:
            break
    return out


class StorageOpcodes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.Image(tool.BINARY.read_bytes())

    def test_sample_matches_machine_code(self):
        cases = sample(5)
        n, bad, machine = tool.evaluate(self.image, cases=iter(cases))
        self.assertEqual((n, bad), (len(cases), 0))
        kinds = {c["kind"] for c in cases}
        self.assertEqual(kinds, {"sload", "sstore", "store", "tload", "tstore"})

    def test_real_handlers_are_executed_in_full(self):
        cases = sample(1)
        n, bad, machine = tool.evaluate(self.image, cases=iter(cases))
        self.assertEqual(bad, 0)
        _, decoded = tool.static_evidence(self.image)
        for start in (tool.SLOAD_B, tool.SLOAD_C, tool.SSTORE_B, tool.TLOAD_B, tool.TSTORE_B, tool.TLOAD_C, tool.TSTORE_C,
                      tool.STORE_B, tool.STORE_C, tool.COST_B):
            insns = [va for va, f in decoded[start] if f]
            self.assertTrue(all(va in machine.seen for va in insns), hex(start))

    def test_model_mutants_are_detected(self):
        for name in tool.MODEL_MUTANTS:
            n, bad, _ = tool.evaluate(self.image, mut=frozenset([name]), stop_on_first=True, cases=tool.all_cases())
            self.assertGreater(bad, 0, name)

    def test_code_mutants_are_detected(self):
        for va, byte, what in tool.BYTE_MUTANTS:
            self.assertNotEqual(self.image.code(va, 1)[0], byte, what)
            n, bad, _ = tool.evaluate(self.image, override={va: byte}, stop_on_first=True, cases=tool.all_cases())
            self.assertGreater(bad, 0, what)

    def test_unchanged_byte_is_refused_by_controls(self):
        va = tool.BYTE_MUTANTS[0][0]
        original = self.image.code(va, 1)[0]
        saved = tool.BYTE_MUTANTS[0]
        tool.BYTE_MUTANTS[0] = (va, original, "unchanged")
        try:
            with self.assertRaises(tool.ToolError):
                tool.controls(self.image, tool.all_cases)
        finally:
            tool.BYTE_MUTANTS[0] = saved

    def test_input_digest_and_range_are_enforced(self):
        corrupt = bytearray(self.image.data)
        corrupt[self.image.text["offset"] + 3] ^= 0x10
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(corrupt))
        with self.assertRaises(tool.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"], 4)

    def test_opcode_table_slots_and_pinned_bytes(self):
        consts, _ = tool.static_evidence(self.image)
        slots = consts["opcode_table_slots"]
        self.assertEqual(slots["B-first:SLOAD:0x54"]["handler"], "0x4330ea0")
        self.assertEqual(slots["B-second:SSTORE:0x55"]["handler"], "0x4331150")
        self.assertEqual(slots["C:SLOAD:0x54"]["handler"], "0x4f04140")
        self.assertEqual(slots["C:TSTORE:0x5d"]["handler"], "0x4f04dd0")
        self.assertEqual(len(consts["checked_bytes"]), len(tool.CHECKED))
        self.assertEqual(consts["functions"]["0x4331150"]["direct_calls"], ["0x4326080", "0x433c830", "0x433cac0"])
        if FOLDER.exists():
            self.assertEqual(json.loads((FOLDER / "constants.json").read_text()), json.loads(json.dumps(consts)))

    def test_wrong_pinned_bytes_are_refused(self):
        saved = tool.CHECKED
        tool.CHECKED = ((saved[0][0], "00 00", "wrong"),) + saved[1:]
        try:
            with self.assertRaises(tool.ToolError):
                tool.static_evidence(self.image)
        finally:
            tool.CHECKED = saved

    def test_price_and_refund_reconstruction(self):
        p = {off: 1 for off in tool.PARAM_OFFS}
        p.update({0xa0: 20000, 0xa8: 5000, 0xd0: 2100, 0xb0: 4800, 0x138: 19900, 0x140: 2800})
        self.assertEqual(tool.sstore_cost(p, 1, 0, 0, 7, 1), 22100)
        self.assertEqual(tool.sstore_cost(p, 1, 7, 7, 9, 0), 5000)
        self.assertEqual(tool.sstore_cost(p, 1, 7, 9, 8, 1), 2100)
        self.assertEqual(tool.sstore_refund(p, 1, 7, 7, 0), 4800)
        self.assertEqual(tool.sstore_refund(p, 1, 0, 5, 0), 19900 + 0)
        with self.assertRaises(tool.Panic):
            tool.sstore_cost({**p, 0xd0: tool.M64}, 1, 0, 0, 7, 1)

    def test_journal_entry_layout(self):
        c = next(c for c in tool.all_cases() if c["kind"] == "store" and c["found"] and c["tag"] < 2
                 and c["rec"][1] != c["value"] and not c["aflags"] & 4)
        want = tool.model(c)
        jb = want["R"]["jbuf"]
        host = want["R"]["host"]
        self.assertEqual(tool.u(host, tool.H_JOURNAL + 16, 8), c["jlen"] + 2)
        touch = jb[c["jlen"] * tool.ENTRY:(c["jlen"] + 1) * tool.ENTRY]
        write = jb[(c["jlen"] + 1) * tool.ENTRY:(c["jlen"] + 2) * tool.ENTRY]
        self.assertEqual((touch[0], bytes(touch[1:21])), (2, c["addr"]))
        key, old = tool.w32(c["key"]), tool.w32(c["rec"][1])
        self.assertEqual((write[0], bytes(write[1:21]), bytes(write[0x18:0x38]), bytes(write[0x38:0x58])), (8, c["addr"], key, old))
        self.assertEqual(bytes(write[0x15:0x18]), key[:3])
        self.assertEqual(want["R"]["rec"][32:64], tool.w32(c["value"]))

    def test_error_results_of_sload(self):
        base = next(c for c in tool.all_cases() if c["kind"] == "sload" and c["n"] == 1 and c["found"] and c["tag"] == 2)
        for spec, code in ((7, tool.R_OOG), (6, tool.R_FATAL)):
            c = dict(base, spec=spec)
            self.assertEqual(tool.model(c)["ret"], ("ret", code))
        self.assertEqual(tool.model(dict(base, n=0, stack=[]))["ret"], ("ret", tool.R_UNDERFLOW))

    def test_case_stream_is_deterministic_and_large(self):
        first = [c["key"] for c in itertools.islice(tool.all_cases(), 50)]
        second = [c["key"] for c in itertools.islice(tool.all_cases(), 50)]
        self.assertEqual(first, second)
        self.assertEqual(sum(1 for _ in tool.all_cases()), tool.TOTAL)
        self.assertGreaterEqual(tool.TOTAL, 10000)

    def test_generated_summary_if_present(self):
        path = FOLDER / "measure.json"
        if not path.exists():
            return  # the evidence folder is only present in a checkout that carries the packet
        m = json.loads(path.read_text())
        self.assertEqual((m["cases"], m["mismatches"]), (tool.TOTAL, 0))
        self.assertEqual(m["negative_controls"], m["negative_detected"])
        self.assertGreaterEqual(m["negative_controls"], 30)


if __name__ == "__main__":
    unittest.main()
