import pathlib
import random
import re
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import hl_quantities_deploy_dispatch_115 as tool  # noqa: E402

EMPTY_HASH = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


class FakeImage:
    """Just enough of an image for the models: the three constant tables at their addresses."""

    BASE = 0x400000

    def __init__(self, default_hash=EMPTY_HASH):
        self.blob = bytearray(0x60000)
        at = lambda va: va - self.BASE  # noqa: E731
        self.blob[at(0x4537F0):at(0x4537F0) + 16] = EMPTY_HASH[:16]
        self.blob[at(0x452020):at(0x452020) + 16] = EMPTY_HASH[16:]
        self.blob[at(0x4585A0):at(0x4585A0) + 32] = default_hash

    def offset(self, va):
        return va - self.BASE


def make(kind, seed, **fields):
    case = tool.make_case(random.Random(seed), seed, kind)
    case["fail"] = set()
    case.update(fields)
    return case


def model(case, image=None, env_class=tool.Env):
    mem = tool.Memory(None)
    tool.build(mem, case)
    env = env_class(mem, case)
    out = bytearray(bytes([tool.OUT_FILL]) * 0x80)
    image = image or FakeImage()
    if case["kind"] == "pair":
        tool.pair_model(env, out, tool.STATE, mem.bytes_at(tool.PARAM, 0x58), image)
    else:
        tool.dispatch_model(env, out, tool.STATE, tool.ACTION, image)
    return mem, env, out


def out_tag(out):
    return int.from_bytes(out[:2], "little")


class Fixed(tool.Env):
    """Env whose asset and account answers are chosen by the test."""

    asset_value = 0
    account_hash = EMPTY_HASH
    account_flag = 1

    def asset(self, ptr, length, value):
        self.log.append(("asset", ptr, length, value))
        block = bytearray(self.result("asset", self.asset_value))
        return bytes(block)

    def account(self, table, address):
        self.log.append(("account", table, address))
        block = bytearray(0x50)
        block[0x28] = self.account_flag
        block[0x29:0x49] = self.account_hash
        return bytes(block)

def with_asset(value):
    return type("A", (Fixed,), {"asset_value": value})


class Tables(unittest.TestCase):
    def test_arm_index_edges(self):
        n = tool.NICHE
        self.assertEqual([tool.arm_index(n + 13 + k) for k in range(7)], [0, 1, 2, 3, 4, 5, 6])
        self.assertEqual(tool.arm_index(n + 12), 5)
        self.assertEqual(tool.arm_index(0), 5)
        self.assertEqual(tool.arm_index(1 << 40), 5)
        self.assertNotEqual(tool.arm_index(n + 14), 0)
        self.assertNotEqual(tool.arm_index(n + 13), tool.arm_index(n + 12))

    def test_layout_and_contract_tables(self):
        for row in tool.LAYOUT:
            self.assertEqual(len(row), 4)
            self.assertTrue(row[1] >= 0 and row[2] > 0 and row[3])
        names = set(tool.DIRECT) | set(tool.GOT)
        for name, text in tool.CONTRACTS:
            self.assertIn(name, names)
            self.assertTrue(text)
        self.assertEqual(len(set(tool.FAKE.values())), len(tool.FAKE))

    def test_function_list(self):
        starts = [start for start, _ in tool.FUNCTIONS]
        self.assertEqual(len(starts), len(set(starts)))
        self.assertIn(tool.DISPATCH_FN, starts)
        self.assertIn(tool.PAIR_FN, starts)

    def test_no_server_paths_in_tool(self):
        source = pathlib.Path(tool.__file__).read_text()
        for prefix in ("/ho" + "me/", "/m" + "nt/", "/s" + "rv/", "/ro" + "ot/", "/t" + "mp/", "/o" + "pt/", "/v" + "ar/", "/e" + "tc/"):
            self.assertNotIn(prefix, source)


class Records(unittest.TestCase):
    def memory(self, capacity, head, length):
        mem = tool.Memory(None)
        mem.reset(tool.USED)
        mem.put_bytes(tool.DEQUE, struct.pack("<QQQQ", capacity, tool.RING, head, length))
        return mem

    def test_tree_record_stride(self):
        mem = self.memory(4, 0, 0)
        handle = struct.pack("<QQQ", 0x1000, 0, 3)
        self.assertEqual(tool.record_model(mem, handle), 0x1000 + 3 * 0xA0)
        self.assertNotEqual(tool.record_model(mem, handle), 0x1000 + 3 * 0xA8)

    def test_ring_record_wraps(self):
        mem = self.memory(4, 3, 3)
        for index, slot in ((0, 3), (1, 0), (2, 1)):
            handle = struct.pack("<QQQ", 0, tool.DEQUE, index)
            self.assertEqual(tool.record_model(mem, handle), tool.RING + slot * 0xA8 + 8)

    def test_ring_record_range_panic(self):
        mem = self.memory(4, 1, 2)
        with self.assertRaises(tool.Crash) as caught:
            tool.record_model(mem, struct.pack("<QQQ", 0, tool.DEQUE, 2))
        self.assertEqual(caught.exception.kind, "panic_str")
        self.assertEqual(caught.exception.payload, (0x9171A2, 0x14, 0x649CC08))
        tool.record_model(mem, struct.pack("<QQQ", 0, tool.DEQUE, 1))

    def test_insert_through_ring_raises_length(self):
        mem = self.memory(4, 0, 1)
        env = tool.Env(mem, dict(seed=1, fail=set()))
        content = bytes(range(0x99))
        words = struct.unpack("<QQQQ", tool.insert_model(env, struct.pack("<QQQQQ", 0, tool.DEQUE, 1, 77, 0), content))
        self.assertEqual(words, (0, tool.DEQUE, 1, 0))
        self.assertEqual(tool.u(mem, tool.DEQUE + 0x18), 2)
        self.assertEqual([row[0] for row in env.log], ["memcpy", "ring_insert"])
        self.assertEqual(env.log[1][3], struct.pack("<Q", 77) + content)

    def test_insert_through_tree_keeps_length(self):
        mem = self.memory(4, 0, 1)
        env = tool.Env(mem, dict(seed=1, fail=set()))
        tool.insert_model(env, struct.pack("<QQQQQ", 0x2000, 0, 0, 0, 0), bytes(0x99))
        self.assertEqual(tool.u(mem, tool.DEQUE + 0x18), 1)
        self.assertEqual([row[0] for row in env.log], ["tree_insert"])


class Dispatch(unittest.TestCase):
    def arm_case(self, arm, seed, **fields):
        case = make("dispatch", seed, arm=arm, tag=tool.ARM_TAGS[arm] if arm != 5 else 3, **fields)
        return case

    def test_asset_number_thresholds(self):
        wanted = {0: 0, 0x270F: 0x270F, 0x2710: 0x2710 + 100000, 0x5F45A5F: 0x5F45A5F + 100000, 0x5F45A60: 0xFFFFFFFF, 1 << 40: 0xFFFFFFFF}
        for value, asset in wanted.items():
            case = self.arm_case(0, 5, length=12, slack=0)
            _, env, out = model(case, env_class=with_asset(value))
            emits = [row for row in env.log if row[0] == "emit"]
            if tool.tag_of(bytes(out)) == tool.OK or emits:
                self.assertEqual(emits[0][2:], (0x35, struct.pack("<IB", asset, 1)))
                self.assertEqual(emits[0][1], tool.STATE)

    def test_name_length_limit(self):
        for length, rejected in ((0x64, False), (0x65, True), (0x100, True)):
            case = self.arm_case(0, 6, length=length, slack=2)
            _, env, out = model(case)
            self.assertEqual(out_tag(out) == 0x158 and env.log[0][0] == "dealloc", rejected)

    def test_slot_one_forwards_21_bytes(self):
        case = self.arm_case(1, 7)
        mem, env, out = model(case)
        self.assertEqual(env.log[0][:3], ("emit", tool.STATE, 0x2D))
        self.assertEqual(env.log[0][3], mem.bytes_at(tool.ACTION + 8, 21))

    def test_slot_six_bounds(self):
        for position, count, error in ((0, 1, False), (1, 1, True), (5, 3, True), (tool.M64, 3, True)):
            case = self.arm_case(6, 8, index=position, count=count)
            _, env, out = model(case)
            if error:
                self.assertEqual(out_tag(out), 0xFA)
                self.assertEqual(int.from_bytes(out[8:16], "little"), position)
            else:
                self.assertNotEqual(out_tag(out), 0xFA)

    def test_default_arm_copies_whole_action(self):
        case = self.arm_case(5, 9)
        mem, env, out = model(case)
        self.assertEqual(env.log[0][:2], ("memcpy", 0xB0))
        self.assertEqual(env.log[-1][0], "drop")
        self.assertEqual(env.log[-1][1], mem.bytes_at(tool.ACTION, 0xB0))

    def test_slot_three_marks_dex(self):
        hit = False
        for seed in range(60):
            case = self.arm_case(3, seed, length=9, flagged=1, dex_mask=0)
            mem, env, out = model(case)
            if any(row[0] == "lookup_b" for row in env.log) and out_tag(out) == tool.OK:
                dex = [row for row in env.log if row[0] == "vec_of"][0][1]
                self.assertEqual(mem.bytes_at(dex + 0x468, 1), b"\x02")
                hit = True
        self.assertTrue(hit)


class Pair(unittest.TestCase):
    def run_pair(self, image=None, env_class=Fixed, **fields):
        wanted = dict(index=0, same_ab=False, d_is_first=False, count=2, first_flag=1, set_len=0)
        wanted.update(fields)
        case = make("pair", wanted.pop("seed", 21), **wanted)
        return model(case, image=image, env_class=env_class)

    def test_error_tags(self):
        _, _, out = self.run_pair(index=1)
        self.assertEqual(out_tag(out), 0x101)
        _, _, out = self.run_pair(same_ab=True)
        self.assertEqual(out_tag(out), 0x166)
        _, _, out = self.run_pair(first_flag=2)
        self.assertEqual(out_tag(out), 0x167)
        _, _, out = self.run_pair(d_is_first=True)
        self.assertEqual(out_tag(out), 0x168)

    def test_empty_vector_panics(self):
        with self.assertRaises(tool.Crash) as caught:
            self.run_pair(count=0)
        self.assertEqual(caught.exception.payload, (0x64768D8,))

    def test_code_hash_gate(self):
        class Other(Fixed):
            account_hash = bytes(32)
        _, env, out = self.run_pair(env_class=Other)
        self.assertEqual(out_tag(out), 0x169)
        self.assertNotIn("map_find", [row[0] for row in env.log])
        _, env, _ = self.run_pair()
        self.assertIn("map_find", [row[0] for row in env.log])

    def test_default_hash_used_without_account(self):
        class Missing(Fixed):
            account_flag = 0
        _, env, _ = self.run_pair(env_class=Missing, image=FakeImage(default_hash=EMPTY_HASH))
        self.assertIn("map_find", [row[0] for row in env.log])
        _, env, out = self.run_pair(env_class=Missing, image=FakeImage(default_hash=bytes(32)))
        self.assertEqual(out_tag(out), 0x169)
        self.assertNotIn("map_find", [row[0] for row in env.log])

    def test_call_order_of_checks(self):
        _, env, _ = self.run_pair(same_ab=False)
        names = [row[0] for row in env.log]
        self.assertEqual(names[:2], ["cdd30", "cdd30"])
        self.assertEqual([row[3] for row in env.log[:2]], [0, 1])


class Search(unittest.TestCase):
    def spec(self, length, finger, back, needle):
        return struct.pack("<QQQQ", 0x1000, length, finger, back) + needle.ljust(8, b"\x00") + bytes([len(needle)])

    def test_single_byte(self):
        hay = b"ab:cd:e"
        hit, finger = tool.search_model(hay, self.spec(7, 0, 7, b":"))
        self.assertEqual((hit, finger), ((2, 3), 3))
        hit, finger = tool.search_model(hay, self.spec(7, finger, 7, b":"))
        self.assertEqual((hit, finger), ((5, 6), 6))
        hit, finger = tool.search_model(hay, self.spec(7, finger, 7, b":"))
        self.assertEqual((hit, finger), (None, 7))

    def test_multi_byte_needle_rejects_partial(self):
        hay = b"xa\xa9a\xc3\xa9"
        hit, _ = tool.search_model(hay, self.spec(len(hay), 0, len(hay), b"\xc3\xa9"))
        self.assertEqual(hit, (4, 6))
        hit, _ = tool.search_model(b"\xa9\xa9\xa9", self.spec(3, 0, 3, b"\xc3\xa9"))
        self.assertIsNone(hit)

    def test_guards(self):
        self.assertEqual(tool.search_model(b"::", self.spec(2, 0, 3, b":")), (None, 0))
        self.assertEqual(tool.search_model(b"::", self.spec(2, 2, 1, b":")), (None, 2))
        self.assertEqual(tool.search_model(b"::", self.spec(2, 1, 2, b":"))[0], (1, 2))

    def test_match_before_finger_is_not_returned(self):
        hit, _ = tool.search_model(b"a:b", self.spec(3, 2, 3, b":"))
        self.assertIsNone(hit)

    def test_wrong_reimplementations_differ(self):
        spec = self.spec(7, 0, 7, b":")
        right = tool.search_model(b"ab:cd:e", spec)
        self.assertNotEqual(right[0], (5, 6))
        self.assertNotEqual(right[0], (2, 2))
        self.assertNotEqual(right[1], 2)


class AddressSet(unittest.TestCase):
    def setup(self, count, first_key=bytes(20)):
        mem = tool.Memory(None)
        mem.reset(tool.USED)
        base = tool.STATE + 0x968
        mem.put_bytes(base, struct.pack("<QQQ", 0, tool.SETENT, count))
        mem.put_bytes(tool.SETENT + 0x48, first_key)
        return mem, base, tool.Env(mem, dict(seed=5, fail=set()))

    def test_empty_set_has_nothing(self):
        mem, base, env = self.setup(0)
        self.assertEqual(tool.set_has_model(env, base, bytes(range(20))), 0)
        self.assertEqual(env.log, [])

    def test_single_entry_compares_in_place(self):
        key = bytes(range(20))
        mem, base, env = self.setup(1, first_key=key)
        self.assertEqual(tool.set_has_model(env, base, key), 1)
        self.assertEqual(tool.set_has_model(env, base, bytes(20)), 0)
        self.assertEqual(env.log, [])

    def test_larger_set_hashes_then_probes(self):
        mem, base, env = self.setup(3)
        result = tool.set_has_model(env, base, bytes(range(20)))
        self.assertIn(result, (0, 1))
        self.assertEqual([row[0] for row in env.log], ["hash_key", "table_find"])
        self.assertEqual(env.log[1][1], base + 0x18)
        self.assertEqual(env.log[1][5], 3)


class Interpreter(unittest.TestCase):
    """The mutation mechanism on a two-instruction function: lea eax,[rdi+0x186a0]; ret."""

    CODE = bytes.fromhex("8d87a0860100") + bytes.fromhex("c3")

    def image(self):
        class Tiny:
            blob = bytearray(0x1000)

            def offset(self, va):
                return va - 0x1000

        image = Tiny()
        image.blob[0:len(self.CODE)] = self.CODE
        return image

    def test_unpatched_and_patched(self):
        image = self.image()
        self.assertEqual(tool.Machine(image).run(0x1000, {tool.RDI: 5}) & 0xFFFFFFFF, 5 + 100000)
        patched = tool.Machine(image, {0x1002: 0xA1})
        self.assertNotEqual(patched.run(0x1000, {tool.RDI: 5}) & 0xFFFFFFFF, 5 + 100000)

    def test_unmodelled_call_halts(self):
        class Tiny:
            blob = bytearray(bytes.fromhex("e800000000c3"))

            def offset(self, va):
                return va - 0x1000

        with self.assertRaises(tool.Halt):
            tool.Machine(Tiny()).run(0x1000, {})


class Determinism(unittest.TestCase):
    def test_cases_repeat(self):
        first = [tool.make_case(random.Random(3), n, "dispatch") for n in range(5)]
        second = [tool.make_case(random.Random(3), n, "dispatch") for n in range(5)]
        self.assertEqual(first, second)
        self.assertNotEqual(first[0], tool.make_case(random.Random(4), 0, "dispatch"))

    def test_model_runs_repeat_and_differ_per_case(self):
        digests = set()
        rnd = random.Random(11)
        for number in range(40):
            case = tool.make_case(rnd, number, "dispatch")
            image = FakeImage()
            first, second = [], []
            for sink in (first, second):
                mem, env, out = model(case, image=image)
                sink.append((bytes(out), env.log))
            self.assertEqual(first, second)
            digests.add(str(first[0][1]))
        self.assertGreater(len(digests), 20)

    def test_every_arm_reachable(self):
        arms = set()
        rnd = random.Random(1)
        for number in range(200):
            arms.add(tool.make_case(rnd, number, "dispatch")["arm"])
        self.assertEqual(arms, set(range(7)))

    def test_env_failures_follow_the_case(self):
        mem = tool.Memory(None)
        ok = tool.Env(mem, dict(seed=3, fail=set())).result("emit")
        bad = tool.Env(mem, dict(seed=3, fail={"emit:0"})).result("emit")
        self.assertEqual(tool.tag_of(ok), tool.OK)
        self.assertNotEqual(tool.tag_of(bad), tool.OK)
        self.assertTrue(re.fullmatch("[0-9a-f]+", ok[:4].hex()))


if __name__ == "__main__":
    unittest.main()
