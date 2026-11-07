import hashlib
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("order_value_gate_115", ROOT / "tools" / "order_value_gate_115.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

SHARED = {}


def shared():
    if not SHARED:
        data = (ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        tool.check_target(data)
        SHARED["data"] = data
        SHARED["image"] = tool.Image(bytearray(data))
    return SHARED["image"]


def base_case(**changes):
    """An accepted order: value 2e10, every gate open, reject kind 2."""
    case = tool.Case(copy=0, enabled=1, market=1, ident=6000, t_resolve=tool.TAG_OK, t_check=tool.TAG_OK,
                     price=2 * 10 ** 10, size=1, head=tool.HEAD_MARK, t_margin=tool.TAG_OK, kind=1, b8=0, b9=0,
                     count=0, total0=0, elements=(0, 0, 0, 0, 0), limit=0, reject=2, text_len=0,
                     alloc=0x7700_0000)
    for name, value in changes.items():
        setattr(case, name, value)
    return case


def outcome(case, copy=0):
    return tool.run_case(shared(), case, tool.GATES[copy])[0]


class Targets(unittest.TestCase):
    def test_digest_is_checked(self):
        shared()
        flipped = bytes([SHARED["data"][0] ^ 1]) + SHARED["data"][1:]
        with self.assertRaises(tool.ToolError):
            tool.check_target(flipped)
        with self.assertRaises(tool.ToolError):
            tool.check_target(SHARED["data"][:4096])
        self.assertEqual(hashlib.sha256(SHARED["data"]).hexdigest(), tool.SHA256)

    def test_extents_and_call_sites(self):
        image = shared()
        for start in tool.GATES:
            extent = image.fde_of(start)
            self.assertEqual(extent[1] - extent[0], tool.GATE_SIZE)
            self.assertEqual(len(tool.call_sites(image, start)), len(tool.ROLES))

    def test_layouts_differ_only_in_the_third_copy(self):
        image = shared()
        first, second, third = (tool.read_layout(image, g) for g in tool.GATES)
        self.assertEqual(first, second)
        for name in ("enabled", "market", "lea_addr", "set_obj", "count", "base"):
            self.assertEqual(third[name] - first[name], 0xb70)

    def test_outside_text_is_refused(self):
        image = shared()
        with self.assertRaises(tool.ToolError):
            image.fetch(0x1000)

    def test_min_shift_form(self):
        self.assertEqual(0x9502f9 << 10, tool.MIN_VALUE)
        self.assertEqual(tool.MAX_VALUE, 5 * 10 ** 14)


class Boundaries(unittest.TestCase):
    def check(self, case, want):
        for copy in range(3):
            self.assertEqual(outcome(case, copy), want, f"copy {copy}")
            self.assertEqual(tool.spec(case), want)

    def test_value_edges(self):
        self.check(base_case(price=tool.MIN_VALUE - 1), ("tag", tool.TAG_TOO_SMALL, tool.MIN_PAYLOAD))
        self.check(base_case(price=tool.MIN_VALUE), ("tag", tool.TAG_OK))
        self.check(base_case(price=tool.MAX_VALUE), ("tag", tool.TAG_OK))
        self.check(base_case(price=tool.MAX_VALUE + 1), ("tag", tool.TAG_TOO_LARGE, tool.MAX_PAYLOAD))

    def test_value_is_a_product(self):
        self.check(base_case(price=10 ** 5, size=10 ** 5), ("tag", tool.TAG_OK))
        self.check(base_case(price=10 ** 5 - 1, size=10 ** 5), ("tag", tool.TAG_TOO_SMALL, tool.MIN_PAYLOAD))

    def test_product_cap_and_overflow(self):
        self.check(base_case(price=tool.PRODUCT_CAP, size=1), ("tag", tool.TAG_TOO_LARGE, tool.MAX_PAYLOAD))
        self.check(base_case(price=tool.PRODUCT_CAP + 1, size=1), ("tag", tool.TAG_PRODUCT))
        self.check(base_case(price=2 ** 32, size=2 ** 32), ("tag", tool.TAG_PRODUCT))

    def test_asset_id_window(self):
        self.check(base_case(ident=4), ("tag", tool.TAG_BAD_ID, 4))
        self.check(base_case(ident=5), ("tag", tool.TAG_OK))
        self.check(base_case(ident=10080), ("tag", tool.TAG_OK))
        self.check(base_case(ident=10081), ("tag", tool.TAG_BAD_ID, 10081))

    def test_disabled_gate_wins_over_everything(self):
        self.check(base_case(enabled=0, ident=0, t_resolve=0x77), ("tag", tool.TAG_NOT_ENABLED))

    def test_open_total_check(self):
        loaded = dict(kind=5, b9=0, count=2, total0=5, elements=(7, 11, 99, 99, 99))
        self.check(base_case(limit=24, **loaded), ("tag", tool.TAG_OK))
        self.check(base_case(limit=23, **loaded), ("tag", tool.TAG_SUM))
        self.check(base_case(limit=22, **loaded), ("tag", tool.TAG_SUM))
        # kinds below 3 skip the total check entirely
        self.check(base_case(kind=2, limit=0, count=1, total0=1), ("tag", tool.TAG_OK))
        self.check(base_case(kind=3, limit=0, count=1, total0=1), ("tag", tool.TAG_SUM))

    def test_saturating_total(self):
        case = base_case(kind=5, count=2, total0=tool.U64 - 1, elements=(5, 5, 0, 0, 0), limit=tool.U64)
        self.check(case, ("tag", tool.TAG_SUM))
        self.check(base_case(kind=5, count=2, total0=1, elements=(5, 5, 0, 0, 0), limit=12), ("tag", tool.TAG_OK))

    def test_head_mark_skips_market_gates(self):
        self.check(base_case(head=7, market=0), ("tag", tool.TAG_NO_MARKET))
        self.check(base_case(head=7, t_margin=0x55), ("tag", 0x55))
        self.check(base_case(head=tool.HEAD_MARK, market=0, t_margin=0x55), ("tag", tool.TAG_OK))

    def test_reject_kind(self):
        self.check(base_case(reject=3), ("tag", tool.TAG_REJECT, 3))
        self.check(base_case(reject=0), ("tag", tool.TAG_REJECT, 0))
        self.check(base_case(reject=255), ("tag", tool.TAG_REJECT, 255))

    def test_text_panics(self):
        small = dict(price=1)
        self.check(base_case(text_len=-1, **small), ("panic", "negative text length"))
        self.check(base_case(text_len=4, alloc=0, **small), ("panic", "allocation failed"))
        self.check(base_case(text_len=4, **small), ("tag", tool.TAG_TOO_SMALL, tool.MIN_PAYLOAD))

    def test_error_tags_pass_through(self):
        self.check(base_case(t_resolve=0x77), ("tag", 0x77))
        self.check(base_case(t_check=0x99), ("tag", 0x99))


class Sweep(unittest.TestCase):
    def test_generated_cases_match_the_rule(self):
        image = shared()
        for copy, start in enumerate(tool.GATES):
            for index, case in enumerate(tool.cases_for(copy, 300)):
                got = tool.run_case(image, case, start)[0]
                self.assertEqual(got, tool.spec(case), f"copy {copy} case {index}")

    def test_case_stream_is_deterministic(self):
        first = [tool.case_detail(c) for c in tool.cases_for(1, 25)]
        second = [tool.case_detail(c) for c in tool.cases_for(1, 25)]
        self.assertEqual(first, second)
        self.assertNotEqual(first, [tool.case_detail(c) for c in tool.cases_for(2, 25)])


class Controls(unittest.TestCase):
    def setUp(self):
        self.image = shared()
        self.cases = list(tool.cases_for(0, tool.CONTROL_CASES)) + [base_case(price=tool.MIN_VALUE - 1),
                                                     base_case(price=tool.MAX_VALUE + 1),
                                                     base_case(price=tool.MAX_VALUE),
                                                     base_case(price=tool.MIN_VALUE)]

    def test_every_wrong_rule_is_caught(self):
        for flaw in tool.FLAWS:
            self.assertIsNotNone(tool.first_mismatch(self.image, self.cases, tool.GATES[0], flaw), flaw)

    def test_unmutated_bytes_pass(self):
        self.assertIsNone(tool.first_mismatch(self.image, self.cases, tool.GATES[0]))

    def test_mutants_are_caught(self):
        sites = tool.mutation_sites(self.image, tool.GATES[0])
        kinds = {site[0] for site in sites}
        self.assertEqual(kinds, {"branch inverted", "tag constant", "wide constant", "compare constant",
                                 "field offset"})
        chosen = {}
        for site in sites:
            chosen.setdefault(site[0], []).append(site)
        for kind in ("branch inverted", "wide constant", "compare constant"):
            for va, byte in [(s[1], s[2]) for s in chosen[kind][:6]]:
                before = tool.patch(self.image, va, bytes([byte]))
                try:
                    self.assertIsNotNone(tool.first_mismatch(self.image, self.cases, tool.GATES[0]),
                                         f"{kind} at {va:#x}")
                finally:
                    tool.patch(self.image, va, before)

    def test_payload_constants(self):
        # the 0xd7 and 0xd8 payloads are 64-bit immediates (100.0 and 5000000.0)
        data = self.image.data
        found = {}
        for kind, va, byte in tool.mutation_sites(self.image, tool.GATES[0]):
            if kind == "wide constant":
                off = self.image.file_offset(va)
                found[int.from_bytes(data[off:off + 8], "little")] = (va, byte)
        for wanted in (tool.MIN_PAYLOAD, tool.MAX_PAYLOAD, tool.MAX_VALUE, tool.PRODUCT_CAP, tool.HEAD_MARK):
            self.assertIn(wanted, found)
            va, byte = found[wanted]
            before = tool.patch(self.image, va, bytes([byte]))
            try:
                self.assertIsNotNone(tool.first_mismatch(self.image, self.cases, tool.GATES[0]), hex(wanted))
            finally:
                tool.patch(self.image, va, before)

    def test_survivors_are_only_copy_offsets_and_the_dropped_tag(self):
        survivors = set()
        for kind, va, byte in tool.mutation_sites(self.image, tool.GATES[0]):
            before = tool.patch(self.image, va, bytes([byte]))
            try:
                hit = tool.first_mismatch(self.image, self.cases, tool.GATES[0])
            finally:
                tool.patch(self.image, va, before)
            if hit is None:
                survivors.add(kind)
        self.assertLessEqual(survivors, {"field offset", "tag constant"})

    def test_stub_sees_a_changed_argument(self):
        # change the key-copy size: the key store at rsp+0x30 no longer reaches the stubs intact
        image = self.image
        start = tool.GATES[0]
        patched = None
        for insn in tool.sweep(image, start, start + tool.GATE_SIZE):
            if (insn.key == 0x89 and image.data[insn.modrm] >> 6 == 1 and image.data[insn.modrm] & 7 == 4
                    and image.data[insn.modrm + 2] == 0x30):
                patched = insn.va + (insn.modrm + 2 - insn.off)
                break
        self.assertIsNotNone(patched)
        before = tool.patch(image, patched, bytes([0x38]))
        try:
            self.assertIsNotNone(tool.first_mismatch(image, self.cases, start))
        finally:
            tool.patch(image, patched, before)


class Behaviour(unittest.TestCase):
    """Properties of the whole run, on a smaller case stream."""

    def setUp(self):
        self.image = shared()
        self.result = tool.verify_copies(self.image, 150)

    def test_gates_never_write_state_order_or_key(self):
        for trace in self.result["traces"].values():
            self.assertEqual(sum(trace.writes.values()), 0)

    def test_stub_call_sequences_follow_the_rule(self):
        for copy, start in enumerate(tool.GATES):
            for case in tool.cases_for(copy, 120):
                outcome, seen = tool.run_case(self.image, case, start)
                self.assertEqual(list(seen), tool.predict_calls(case), tool.case_detail(case))

    def test_field_reads_match_the_layout(self):
        layouts = [tool.read_layout(self.image, g) for g in tool.GATES]
        for copy, start in enumerate(tool.GATES):
            offsets = {offset for (offset, size) in self.result["traces"][start].state_reads}
            wanted = {0x780, 0x7b8, 0x7b9, layouts[copy]["market"], layouts[copy]["enabled"],
                      layouts[copy]["base"], layouts[copy]["count"]}
            self.assertEqual(offsets, wanted, f"copy {copy}")

    def test_order_fields_read(self):
        for start in tool.GATES:
            offsets = {offset for (offset, size) in self.result["traces"][start].order_reads}
            self.assertEqual(offsets, {0x0, 0x38, 0x40, 0x48, 0x50, 0x51})

    def test_copies_agree_on_the_same_case(self):
        rows = tool.agree_copies(self.image)
        self.assertEqual(len(rows), tool.AGREE_CASES // 5)

    def test_branch_directions_are_visible_in_a_short_run(self):
        rows = tool.edge_rows(self.image, self.result["traces"])
        seen = sum(row[3] + row[4] for row in rows)
        self.assertGreater(seen, len(rows))
        self.assertEqual(len({row[0] for row in rows}), 3)

    def test_prediction_for_known_cases(self):
        self.assertEqual(tool.predict_calls(base_case(enabled=0)), [])
        self.assertEqual(tool.predict_calls(base_case(ident=4)), [])
        self.assertEqual(tool.predict_calls(base_case(t_resolve=0x77)), ["resolve"])
        self.assertEqual(tool.predict_calls(base_case()),
                         ["resolve", "market_check", "price_of", "kind_of", "drop_tag", "reject_kind"])
        self.assertEqual(tool.predict_calls(base_case(price=1, text_len=3)),
                         ["resolve", "market_check", "price_of", "kind_of", "drop_tag", "text_of_min",
                          "alloc_min", "copy_min"])
        self.assertEqual(tool.predict_calls(base_case(price=tool.MAX_VALUE + 1, text_len=3, alloc=0)),
                         ["resolve", "market_check", "price_of", "kind_of", "drop_tag", "text_of_max",
                          "alloc_max"])

    def test_sequence_for_the_total_check(self):
        case = base_case(kind=5, count=3, total0=1, elements=(1, 1, 1, 0, 0), limit=100)
        self.assertEqual(tool.predict_calls(case)[3:8],
                         ["kind_of", "set_total", "element_total", "element_total", "element_total"])
        self.assertEqual(outcome(case), ("tag", tool.TAG_OK))

    def test_copy_difference_rows_are_calls_or_layout(self):
        kinds = {row[2].split(" ")[0] + " " + row[2].split(" ")[1] for row in tool.diff_rows(self.image)}
        self.assertEqual(kinds, {"call target", "call slot", "layout offset"})

    def test_mutants_in_the_other_copies_are_caught_too(self):
        cases = list(tool.cases_for(0, 300))
        for copy in (1, 2):
            rows, survivors = tool.controls(self.image, tool.GATES[copy], cases, label=f"copy{copy + 1} ")
            self.assertGreaterEqual(len(rows), 50)
            self.assertTrue(all(row[4] == "yes" for row in rows))
            self.assertTrue(all(row[0].startswith(f"copy{copy + 1} ") for row in rows + survivors))


def big_total():
    return tool.U64


class HandWrittenEdges(unittest.TestCase):
    """Expected outcomes written by hand from the byte reading, not computed by the tool's rule."""

    OK = ("tag", 0x1a2)
    SMALL = ("tag", 0xd7, 0x4059000000000000)
    LARGE = ("tag", 0xd8, 0x415312d000000000)
    ROWS = (
        (dict(price=9999999999), SMALL),
        (dict(price=10000000000), OK),
        (dict(price=10000000001), OK),
        (dict(price=499999999999999), OK),
        (dict(price=500000000000000), OK),
        (dict(price=500000000000001), LARGE),
        (dict(price=0), SMALL),
        (dict(price=1, size=0), SMALL),
        (dict(price=0, size=0), SMALL),
        (dict(price=2, size=5 * 10 ** 9), OK),
        (dict(price=2, size=5 * 10 ** 9 - 1), SMALL),
        (dict(price=5, size=10 ** 14), OK),
        (dict(price=5, size=10 ** 14 + 1), LARGE),
        (dict(price=1844674407370955161, size=1), LARGE),
        (dict(price=1844674407370955162, size=1), ("tag", 0x6d)),
        (dict(price=2 ** 64 - 1, size=1), ("tag", 0x6d)),
        (dict(price=2 ** 64 - 1, size=2), ("tag", 0x6d)),
        (dict(price=2 ** 63, size=2), ("tag", 0x6d)),
        (dict(price=2 ** 63, size=1), ("tag", 0x6d)),
        (dict(price=922337203685477580, size=2), LARGE),
        (dict(price=922337203685477581, size=2), ("tag", 0x6d)),
        (dict(price=1, size=2 ** 64 - 1), ("tag", 0x6d)),
        (dict(ident=5), OK),
        (dict(ident=6), OK),
        (dict(ident=10079), OK),
        (dict(ident=10080), OK),
        (dict(ident=0), ("tag", 0xd1, 0)),
        (dict(ident=4), ("tag", 0xd1, 4)),
        (dict(ident=10081), ("tag", 0xd1, 10081)),
        (dict(ident=2 ** 64 - 1), ("tag", 0xd1, 2 ** 64 - 1)),
        (dict(ident=2 ** 32 + 6000), ("tag", 0xd1, 2 ** 32 + 6000)),
        (dict(enabled=0), ("tag", 0xdd)),
        (dict(enabled=0, price=0), ("tag", 0xdd)),
        (dict(enabled=0, ident=0), ("tag", 0xdd)),
        (dict(enabled=1, ident=0, t_resolve=0x77), ("tag", 0xd1, 0)),
        (dict(t_resolve=0x77), ("tag", 0x77)),
        (dict(t_resolve=0x77, t_check=0x99), ("tag", 0x77)),
        (dict(t_check=0x99), ("tag", 0x99)),
        (dict(t_check=0x99, price=2 ** 64 - 1), ("tag", 0x99)),
        (dict(t_resolve=0x77, price=2 ** 64 - 1), ("tag", 0x77)),
        (dict(head=0, market=0), ("tag", 0xdc)),
        (dict(head=0, market=0, t_margin=0x55), ("tag", 0xdc)),
        (dict(head=0, market=1, t_margin=0x55), ("tag", 0x55)),
        (dict(head=0, market=2), OK),
        (dict(head=0, market=3), OK),
        (dict(head=1, market=1), OK),
        (dict(head=tool.HEAD_MARK - 1, market=0), ("tag", 0xdc)),
        (dict(head=tool.HEAD_MARK + 1, market=0), ("tag", 0xdc)),
        (dict(head=tool.HEAD_MARK, market=0, t_margin=0x55), OK),
        (dict(price=2 ** 64 - 1, size=1, head=0, market=0), ("tag", 0x6d)),
        (dict(reject=0), ("tag", 0x78, 0)),
        (dict(reject=1), ("tag", 0x78, 1)),
        (dict(reject=2), OK),
        (dict(reject=3), ("tag", 0x78, 3)),
        (dict(reject=254), ("tag", 0x78, 254)),
        (dict(reject=255), ("tag", 0x78, 255)),
        (dict(reject=1, price=1), SMALL),
        (dict(reject=1, price=tool.MAX_VALUE + 1), LARGE),
        (dict(text_len=-1, price=1), ("panic", "negative text length")),
        (dict(text_len=-1, price=tool.MAX_VALUE + 1), ("panic", "negative text length")),
        (dict(text_len=-(2 ** 63), price=1), ("panic", "negative text length")),
        (dict(text_len=1, alloc=0, price=1), ("panic", "allocation failed")),
        (dict(text_len=1, alloc=0, price=tool.MAX_VALUE + 1), ("panic", "allocation failed")),
        (dict(text_len=2 ** 40, alloc=0, price=1), ("panic", "allocation failed")),
        (dict(text_len=1, price=1), SMALL),
        (dict(text_len=-1), OK),
        (dict(text_len=1, alloc=0), OK),
    )

    MORE = (
        (dict(price=10 ** 5, size=10 ** 5), OK),
        (dict(price=10 ** 5 - 1, size=10 ** 5), SMALL),
        (dict(price=5 * 10 ** 4, size=2 * 10 ** 5), OK),
        (dict(price=4999999999, size=2), SMALL),
        (dict(price=5000000000, size=2), OK),
        (dict(price=250000000000000, size=2), OK),
        (dict(price=250000000000001, size=2), LARGE),
        (dict(price=2 ** 33, size=2 ** 2), OK),
        (dict(price=2 ** 33, size=2 ** 20), LARGE),
        (dict(price=2 ** 32, size=2 ** 31), ("tag", 0x6d)),
        (dict(price=2 ** 32, size=2 ** 32), ("tag", 0x6d)),
        (dict(price=3, size=0x5555555555555555), ("tag", 0x6d)),
        (dict(price=3, size=0x5555555555555556), ("tag", 0x6d)),
        (dict(price=tool.PRODUCT_CAP // 7, size=7), LARGE),
        (dict(price=tool.PRODUCT_CAP // 7 + 1, size=7), ("tag", 0x6d)),
        (dict(price=10 ** 10, size=1, ident=5), OK),
        (dict(price=10 ** 10 - 1, size=1, ident=5), SMALL),
        (dict(price=10 ** 10, size=1, ident=10080), OK),
        (dict(price=10 ** 10 - 1, size=1, ident=10080), SMALL),
        (dict(price=10 ** 10, size=1, ident=10081), ("tag", 0xd1, 10081)),
        (dict(price=1, size=1, ident=4), ("tag", 0xd1, 4)),
        (dict(price=5, size=2 * 10 ** 9, head=0), OK),
        (dict(price=5, size=2 * 10 ** 9 - 1, head=0), SMALL),
        (dict(price=5, size=2 * 10 ** 14 + 1, head=0), LARGE),
        (dict(price=5, size=10 ** 14, head=0), ("tag", 0x1a2)),
        (dict(head=0, t_margin=0x1a2, market=1), OK),
        (dict(head=0, t_margin=0x1a1, market=1), ("tag", 0x1a1)),
        (dict(head=0, t_margin=0x1a3, market=1), ("tag", 0x1a3)),
        (dict(head=0, t_margin=0, market=1), ("tag", 0)),
        (dict(head=0, t_margin=0xffff, market=1), ("tag", 0xffff)),
        (dict(t_resolve=0x1a1), ("tag", 0x1a1)),
        (dict(t_resolve=0x1a3), ("tag", 0x1a3)),
        (dict(t_resolve=0), ("tag", 0)),
        (dict(t_check=0x1a1), ("tag", 0x1a1)),
        (dict(t_check=0xffff), ("tag", 0xffff)),
        (dict(t_check=0), ("tag", 0)),
        (dict(market=0), OK),
        (dict(market=0, head=0), ("tag", 0xdc)),
        (dict(market=1, head=0), OK),
        (dict(enabled=2), OK),
        (dict(enabled=255), OK),
        (dict(enabled=0, t_resolve=0x77, t_check=0x99), ("tag", 0xdd)),
        (dict(kind=3, b9=1, count=1, total0=1, limit=0), OK),
        (dict(kind=3, b9=0, count=1, total0=1, limit=0), ("tag", 0xd2)),
        (dict(kind=4, b8=1, count=1, total0=1, limit=0), OK),
        (dict(kind=4, b8=0, count=1, total0=1, limit=0), ("tag", 0xd2)),
        (dict(kind=4, b9=1, b8=0, count=1, total0=1, limit=0), ("tag", 0xd2)),
        (dict(kind=2, b8=0, b9=0, count=1, total0=1, limit=0), OK),
        (dict(kind=0, count=5, total0=big_total(), limit=0), OK),
        (dict(kind=255, count=0, total0=0, limit=0), ("tag", 0xd2)),
        (dict(kind=255, b9=1, count=0, total0=0, limit=0), OK),
    )

    def test_more_rows_in_every_copy(self):
        for number, (changes, want) in enumerate(self.MORE):
            case = base_case(**changes)
            for copy in range(3):
                self.assertEqual(outcome(case, copy), want, f"more row {number} copy {copy}: {changes}")

    def test_more_rows_agree_with_the_rule(self):
        for number, (changes, want) in enumerate(self.MORE):
            self.assertEqual(tool.spec(base_case(**changes)), want, f"more row {number}: {changes}")

    def test_rows_in_every_copy(self):
        for number, (changes, want) in enumerate(self.ROWS):
            case = base_case(**changes)
            for copy in range(3):
                self.assertEqual(outcome(case, copy), want, f"row {number} copy {copy}: {changes}")

    def test_rows_agree_with_the_rule(self):
        for number, (changes, want) in enumerate(self.ROWS):
            self.assertEqual(tool.spec(base_case(**changes)), want, f"row {number}: {changes}")

    def test_total_check_matrix(self):
        """Which (kind, flag) pairs run the total check: hand table, limit 0 makes a run reject at once."""
        runs = {}
        for kind in (0, 1, 2, 3, 4, 5, 9, 255):
            for b8 in (0, 1):
                for b9 in (0, 1):
                    runs[(kind, b8, b9)] = (kind >= 3 and not b9) if kind != 4 else not b8
        for (kind, b8, b9), runs_check in runs.items():
            case = base_case(kind=kind, b8=b8, b9=b9, count=1, total0=1, limit=0)
            want = ("tag", 0xd2) if runs_check else ("tag", 0x1a2)
            for copy in range(3):
                self.assertEqual(outcome(case, copy), want, f"kind {kind} b8 {b8} b9 {b9} copy {copy}")

    def test_total_check_sums(self):
        big = tool.U64
        rows = (
            (dict(count=0, total0=0, limit=0), ("tag", 0xd2)),
            (dict(count=0, total0=0, limit=1), ("tag", 0x1a2)),
            (dict(count=0, total0=big, limit=big), ("tag", 0xd2)),
            (dict(count=0, total0=big - 1, limit=big), ("tag", 0x1a2)),
            (dict(count=1, total0=0, elements=(1, 0, 0, 0, 0), limit=1), ("tag", 0xd2)),
            (dict(count=1, total0=0, elements=(1, 0, 0, 0, 0), limit=2), ("tag", 0x1a2)),
            (dict(count=2, total0=big, elements=(big, big, 0, 0, 0), limit=big), ("tag", 0xd2)),
            (dict(count=2, total0=2 ** 63, elements=(2 ** 63 - 1, 1, 0, 0, 0), limit=big), ("tag", 0xd2)),
            (dict(count=2, total0=2 ** 63, elements=(2 ** 63 - 2, 0, 0, 0, 0), limit=big), ("tag", 0x1a2)),
            (dict(count=1, total0=2 ** 63, elements=(2 ** 63, 0, 0, 0, 0), limit=big), ("tag", 0xd2)),
            (dict(count=3, total0=0, elements=(1, 1, 1, 9, 9), limit=4), ("tag", 0x1a2)),
            (dict(count=3, total0=0, elements=(1, 1, 1, 9, 9), limit=3), ("tag", 0xd2)),
            (dict(count=5, total0=0, elements=(1, 2, 3, 4, 5), limit=16), ("tag", 0x1a2)),
            (dict(count=5, total0=0, elements=(1, 2, 3, 4, 5), limit=15), ("tag", 0xd2)),
        )
        for number, (changes, want) in enumerate(rows):
            case = base_case(kind=5, b9=0, **changes)
            for copy in range(3):
                self.assertEqual(outcome(case, copy), want, f"row {number} copy {copy}: {changes}")

    def test_total_check_comes_before_the_value_check(self):
        case = base_case(kind=5, count=1, total0=1, limit=0, price=1)
        for copy in range(3):
            self.assertEqual(outcome(case, copy), ("tag", 0xd2))
        case = base_case(kind=0, count=1, total0=1, limit=0, price=1)
        for copy in range(3):
            self.assertEqual(outcome(case, copy), self.SMALL)

    def test_product_check_comes_before_the_market_checks(self):
        case = base_case(head=0, market=0, price=2 ** 64 - 1, size=2)
        for copy in range(3):
            self.assertEqual(outcome(case, copy), ("tag", 0x6d))


class Callers(unittest.TestCase):
    def test_each_copy_has_one_direct_caller(self):
        rows, slots = tool.caller_rows(shared())
        self.assertEqual(sorted(row[0] for row in rows), sorted(hex(g) for g in tool.GATES))
        self.assertEqual(slots, {})


if __name__ == "__main__":
    unittest.main()
