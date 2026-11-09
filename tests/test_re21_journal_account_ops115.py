import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re21_journal_account_ops115 as T  # noqa: E402

IMAGE = T.Image(T.BINARY.read_bytes())
T.prepare(IMAGE)


def run_some(fn, count, mut=frozenset(), override=None, stop=False):
    n, bad, m = T.evaluate(IMAGE, override=override, mut=mut, stop_on_first=stop, fn=fn, limit=count)
    return n, bad, m


class Identity(unittest.TestCase):
    def test_digest_is_checked(self):
        data = bytearray(T.BINARY.read_bytes())
        data[0x1000] ^= 1
        with self.assertRaises(T.ToolError):
            T.Image(bytes(data))

    def test_binary_hash(self):
        self.assertEqual(hashlib.sha256(T.BINARY.read_bytes()).hexdigest(), T.SHA256)

    def test_out_of_range_code_read(self):
        with self.assertRaises(T.ToolError):
            IMAGE.code(IMAGE.text["address"] + IMAGE.text["size"] + 0x40, 4)

    def test_functions_have_fde_extents(self):
        rows = T.ev.fde_rows(IMAGE, T.FUNCS)
        self.assertEqual(rows[T.LOOKUP][1] - rows[T.LOOKUP][0], 276)
        self.assertEqual(rows[T.TRANSFER][1] - rows[T.TRANSFER][0], 1180)
        self.assertEqual(rows[T.CREATE][1] - rows[T.CREATE][0], 910)
        self.assertEqual(rows[T.SET_CODE][1] - rows[T.SET_CODE][0], 351)

    def test_unknown_function_is_rejected(self):
        c = next(T.all_cases())
        c["fn"] = "nope"
        with self.assertRaises(T.ToolError):
            T.run_case(T.Mach(IMAGE), c, T.CONSTS, {})


class Constants(unittest.TestCase):
    def test_transfer_event_topic(self):
        self.assertEqual(T.CONSTS["topic0"].hex(),
                         "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

    def test_empty_code_hash(self):
        self.assertEqual(T.CONSTS["empty_hash"].hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_panic_sites_decode_to_the_named_strings(self):
        evidence, _ = T.static_evidence(IMAGE)
        self.assertEqual(len(evidence["panic_sites"]), len(T.PANIC_SITES))
        for site, row in evidence["panic_sites"].items():
            self.assertEqual(int(row["string_va"], 16), T.PANIC_STR[row["name"]], site)

    def test_got_slots_are_relative_relocations(self):
        evidence, _ = T.static_evidence(IMAGE)
        for name, row in evidence["got_slots"].items():
            self.assertEqual(row["relocation"], "RELATIVE", name)


class Decoder(unittest.TestCase):
    def test_lock_prefix_adds_a_byte(self):
        form = T.decode(bytes.fromhex("f048ff0875094889") + bytes(8), 0x43231fe)
        self.assertTrue(form["lock"])
        self.assertEqual(form["len"], 4)

    def test_por_movmskps_and_not(self):
        por = T.decode(bytes.fromhex("660febc8") + bytes(12), 0)
        self.assertEqual((por["op"], por["len"]), (0x0feb, 4))
        mov = T.decode(bytes.fromhex("0f50c0") + bytes(13), 0)
        self.assertEqual((mov["op"], mov["len"]), (0x0f50, 3))
        inv = T.decode(bytes.fromhex("41f6d5") + bytes(13), 0)
        self.assertEqual((inv["op"], inv["len"]), (0xf602, 3))

    def test_all_functions_decode_linearly(self):
        _, decoded = T.static_evidence(IMAGE)
        self.assertEqual(sorted(decoded), sorted(T.FUNCS))
        self.assertEqual(sum(1 for rows in decoded.values() for _, f in rows if f is not None), 70 + 285 + 121 + 89 + 140 + 211)


class Reconstruction(unittest.TestCase):
    def test_each_function_matches_the_machine_code(self):
        for fn, count in (("lookup", 120), ("transfer", 200), ("set_code", 120), ("create", 160), ("revert", 120), ("log", 80)):
            n, bad, _ = run_some(fn, count)
            self.assertEqual((n, bad), (count, 0), fn)

    def test_transfer_reaches_every_result(self):
        seen = set()

        def keep(i, c, want, got, ok):
            seen.add(want["ret"] if want["boundary"] is None else want["boundary"][0])
        T.evaluate(IMAGE, fn="transfer", limit=400, keep=keep)
        self.assertTrue({0, 1, 3, "panic"} <= seen, seen)

    def test_create_reaches_ok_and_both_errors(self):
        seen = set()

        def keep(i, c, want, got, ok):
            seen.add(T.outcome(c, want))
        T.evaluate(IMAGE, fn="create", limit=500, keep=keep)
        self.assertTrue({"create:ok", "create:err1", "create:err2"} <= seen, seen)

    def test_log_is_a_three_topic_transfer_event(self):
        for c in T.all_cases():
            if c["fn"] == "log" and c["spec"] >= 0xe and c["flag"] == 0 and int.from_bytes(c["inputs"]["v"], "little") and not c["oom"]:
                want = T.model(c, frozenset(), T.CONSTS)
                topics = want["blocks"][0][1]
                self.assertEqual(topics[:32], T.CONSTS["topic0"])
                self.assertEqual(topics[44:64], c["inputs"]["a"])
                self.assertEqual(topics[76:96], c["inputs"]["b"])
                self.assertEqual(want["blocks"][1][1], int.from_bytes(c["inputs"]["v"], "little").to_bytes(32, "big"))
                return
        self.fail("no emitting log case")

    def test_same_account_transfer_never_journals(self):
        count = 0
        for c in T.all_cases():
            if c["fn"] == "transfer" and c.get("scenario") == "same" and c["addrs"]:
                want = T.model(c, frozenset(), T.CONSTS)
                if want["boundary"] is None:
                    self.assertEqual(len(want["journal"]), len(c["journal"]))
                    count += 1
            if count >= 5:
                break
        self.assertEqual(count, 5)

    def test_revert_never_grows_state(self):
        for c in T.all_cases():
            if c["fn"] == "revert":
                want = T.model(c, frozenset(), T.CONSTS)
                self.assertLessEqual(len(want["journal"]), len(c["journal"]))
                self.assertLessEqual(len(want["logs"]), len(c["logs"]))
                break

    def test_empty_map_lookup_misses(self):
        for c in T.all_cases():
            if c["fn"] == "lookup" and not c["addrs"]:
                self.assertEqual(T.model(c, frozenset(), T.CONSTS)["ret"], 0)
                got = T.run_case(T.Mach(IMAGE), c, T.CONSTS, {})
                self.assertEqual(got["ret"], 0)
                return
        self.fail("no empty-map case")


class NegativeControls(unittest.TestCase):
    def test_model_mutants_are_detected(self):
        for name, fn in T.MODEL_MUTANTS:
            _, bad, _ = run_some(fn, 700, mut=frozenset([name]), stop=True)
            self.assertGreater(bad, 0, name)

    def test_code_mutants_are_detected(self):
        for va, byte, what, fn in T.BYTE_MUTANTS:
            self.assertNotEqual(IMAGE.code(va, 1)[0], byte, what)
            _, bad, _ = run_some(fn, 700, override={va: byte}, stop=True)
            self.assertGreater(bad, 0, what)

    def test_unmutated_model_is_clean(self):
        for fn in ("transfer", "create", "set_code"):
            self.assertEqual(run_some(fn, 100)[1], 0)

    def test_corrupt_input_binary_is_rejected(self):
        data = bytearray(T.BINARY.read_bytes())
        data[IMAGE.text["offset"] + 7] ^= 1
        with self.assertRaises(T.ToolError):
            T.Image(bytes(data))


if __name__ == "__main__":
    unittest.main()
