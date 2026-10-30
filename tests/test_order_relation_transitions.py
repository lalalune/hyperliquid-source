import copy
import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import order_relation_transitions as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-order-relation-transitions-94"
A, B = tool.USER_A, tool.USER_B
CASCADE, REMOVE, CHILDREN, PEER = tool.CLONES[3]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()

    def runner(self, patches=None):
        return tool.Runner(self.image, patches)


class IdentityTests(Base):
    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_non_elf_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an x86-64 ELF"):
            tool.Image(b"\0" * 128)

    def test_interior_address_is_not_a_function_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(CASCADE + 1)

    def test_padding_is_outside_every_fde(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            self.image.fde(0x42F7883)

    def test_address_outside_segments_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed segments"):
            self.image.offset(0x10000000000)

    def test_every_target_decodes_to_its_exact_fde_end(self):
        for _, va in tool.TARGETS:
            start, end = self.image.exact_fde(va)
            rows = tool.decode_range(self.image, start, end)
            self.assertEqual(rows[-1].next, end)

    def test_short_range_overruns(self):
        with self.assertRaisesRegex(tool.EvidenceError, "overran"):
            tool.decode_range(self.image, CASCADE, CASCADE + 2)

    def test_unknown_opcode_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "undecodable"):
            tool.decode(lambda va, count: b"\x06" + bytes(count - 1), 0x1000)

    def test_high_byte_register_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "high byte"):
            tool.decode(lambda va, count: b"\x88\xe0" + bytes(count - 2), 0x1000)

    def test_clone_shapes(self):
        shapes = {}
        for role, va in tool.TARGETS:
            start, end = self.image.exact_fde(va)
            rows = tool.decode_range(self.image, start, end)
            shapes.setdefault(role, set()).add(tool.normalized_hash(self.image, start, end, rows))
        for role, count in tool.CLONE_SHAPES.items():
            self.assertEqual(len(shapes[role]), count)

    def test_lookup_pins_hold(self):
        self.assertEqual(len(tool.check_lookup_contract(self.image)), len(tool.LOOKUP_PINS))

    def test_each_lookup_pin_detects_one_changed_byte(self):
        for va, _, _ in tool.LOOKUP_PINS:
            clone = copy.copy(self.image)
            mutated = bytearray(self.image.blob)
            mutated[self.image.offset(va)] ^= 0x01
            clone.blob = mutated
            with self.assertRaisesRegex(tool.EvidenceError, "lookup pin changed"):
                tool.check_lookup_contract(clone)

    def test_lookup_pin_outside_fde_is_rejected(self):
        saved = tool.LOOKUP_PINS
        tool.LOOKUP_PINS = ((tool.LOOKUP_REF, "55", "wrong function"),)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "outside its FDE"):
                tool.check_lookup_contract(self.image)
        finally:
            tool.LOOKUP_PINS = saved

    def test_reason_scan_reads_fixed_operands_only(self):
        self.assertEqual(tool.reason_operand(self.image, 0x4305445), "0xb")
        self.assertEqual(tool.reason_operand(self.image, 0x430317F), "0x2")
        self.assertEqual(tool.reason_operand(self.image, 0x42F77FA), "not-fixed")

    def test_tool_runs_no_external_program(self):
        source = (ROOT / "tools" / "order_relation_transitions.py").read_text(encoding="utf-8")
        self.assertNotIn("sub" + "process", source)


class TransitionTests(Base):
    def run_attach(self, orders, parent, children):
        runner = self.runner()
        self.assertIsNone(runner.attach(orders, A, parent, children, len(children)))
        return runner.harness.state()

    def test_attach_skips_children_already_listed(self):
        state = self.run_attach({1: tool.clean_order(kids=(2,)), 2: tool.clean_order(), 3: tool.clean_order()}, 1, [2, 3, 3])
        self.assertEqual(state[1][3], (2, 3))
        self.assertEqual(state[3][1], (1, 1))

    def test_attach_grows_a_full_children_vector(self):
        state = self.run_attach({1: tool.clean_order(kids=(2,)), 2: tool.clean_order(), 3: tool.clean_order()}, 1, [3])
        self.assertEqual(state[1][3], (2, 3))

    def test_attach_with_missing_parent_still_points_children_at_it(self):
        state = self.run_attach({2: tool.clean_order()}, 99, [2])
        self.assertEqual(state[2][1], (1, 99))

    def test_attach_does_not_touch_another_users_child(self):
        state = self.run_attach({1: tool.clean_order(), 2: tool.clean_order(user=B)}, 1, [2])
        self.assertEqual(state[1][3], (2,))
        self.assertEqual(state[2][1], (0, tool.STALE))

    def test_detach_clears_the_tag_and_keeps_the_key(self):
        runner = self.runner()
        orders = {1: tool.clean_order(kids=(2,)), 2: tool.clean_order(parent=(1, 77))}
        self.assertIsNone(runner.simple(tool.DETACH, orders, A, 1, tool.spec_detach))
        state = runner.harness.state()
        self.assertEqual(state[2][1], (0, 77))
        self.assertEqual(state[1][3], (2,))

    def test_clear_peer_compares_only_the_low_32_tag_bits(self):
        for tag, cleared in ((1, 0), (0x100000001, 0), (2, 1)):
            runner = self.runner()
            orders = {1: tool.clean_order(peer=(tag, 2)), 2: tool.clean_order(peer=(1, 1))}
            self.assertIsNone(runner.simple(tool.CLEAR_PEER, orders, A, 1, tool.spec_clear_peer))
            self.assertEqual(runner.harness.state()[2][2][0], cleared)

    def test_set_peers_writes_both_sides_independently(self):
        runner = self.runner()
        self.assertIsNone(runner.simple(tool.SET_PEERS, {1: tool.clean_order()}, A, 1, tool.spec_set_peers, right=2))
        self.assertEqual(runner.harness.state()[1][2], (1, 2))

    def test_link_drops_absent_and_foreign_children_and_keeps_order(self):
        runner = self.runner()
        orders = {1: tool.clean_order(), 21: tool.clean_order(), 22: tool.clean_order(), 25: tool.clean_order(user=B)}
        self.assertIsNone(runner.link(orders, A, 1, 0, 0, 0, 0, [24, 22, 25, 21]))
        self.assertEqual(runner.harness.state()[1][3], (22, 21))

    def test_link_skips_peer_write_when_peer_is_absent(self):
        runner = self.runner()
        self.assertIsNone(runner.link({1: tool.clean_order()}, A, 1, 0, 0, 1, 3, []))
        self.assertEqual(runner.harness.state()[1][2], (0, tool.STALE))

    def test_link_flag_uses_bit_zero(self):
        runner = self.runner()
        orders = {1: tool.clean_order(), 2: tool.clean_order()}
        self.assertIsNone(runner.link(orders, A, 1, 2, 2, 0, 0, []))
        self.assertEqual(runner.harness.state()[2][3], ())

    def test_cascade_removes_children_depth_first_and_the_root_last(self):
        self.assertEqual(tool.example_cascade(self.image), [4, 2, 3, 1])

    def test_cascade_snapshot_and_shared_child(self):
        runner = self.runner()
        orders = {1: tool.clean_order(kids=(2, 3)), 2: tool.clean_order(kids=(3,)), 3: tool.clean_order()}
        self.assertIsNone(runner.cascade(CASCADE, orders, A, 1, 9))
        self.assertEqual([row[1] for row in runner.harness.log], [3, 2, 1])

    def test_cascade_return_value(self):
        for present, expected in ((False, 1), (True, 0)):
            harness = tool.Harness(self.image)
            harness.begin({1: tool.clean_order()} if present else {})
            result = harness.machine.run(CASCADE, {tool.RDI: tool.BOOK, tool.RSI: harness.set_user(A), tool.RDX: 1,
                                                   tool.RCX: tool.CTX, tool.R8: tool.EVENTS, tool.R9: 5})
            self.assertEqual(result & 0xFF, expected)

    def test_reason_byte_passes_through_recursion(self):
        runner = self.runner()
        orders = {1: tool.clean_order(kids=(2,)), 2: tool.clean_order()}
        self.assertIsNone(runner.cascade(CASCADE, orders, A, 1, 0x2A))
        self.assertEqual([row[5] for row in runner.harness.log], [0x2A, 0x2A])

    def test_children_entry_uses_reason_two(self):
        runner = self.runner()
        orders = {1: tool.clean_order()}
        self.assertIsNone(runner.children(CHILDREN, orders, A, [1, 9], 2))
        self.assertEqual(runner.harness.log[0][5], tool.REASON_CHILD)

    def test_peer_entry_cancels_peer_with_reason_eleven(self):
        runner = self.runner()
        orders = {1: tool.clean_order(peer=(1, 2)), 2: tool.clean_order(peer=(1, 1))}
        self.assertIsNone(runner.peer(PEER, orders, A, 1, (), 0, 0))
        self.assertEqual(runner.harness.log[0][1:2] + runner.harness.log[0][5:], (2, 0xB))
        self.assertEqual(runner.harness.state()[1][2][0], 0)

    def test_excluded_peer_stays(self):
        runner = self.runner()
        orders = {1: tool.clean_order(peer=(1, 2)), 2: tool.clean_order(peer=(1, 1))}
        self.assertIsNone(runner.peer(PEER, orders, A, 1, (1, 2, 3), 1, 3))
        self.assertEqual(runner.harness.log, [("once",)])

    def test_alloc_failure_reports_before_any_removal(self):
        orders = {1: tool.clean_order(kids=(2,)), 2: tool.clean_order()}
        self.assertIsNone(self.runner().alloc_failure(CASCADE, orders, A, 1))

    def test_every_clone_matches_the_specification_on_small_suites(self):
        for family, entry in tool.FAMILIES:
            _, failures = tool.run_family(self.runner(), family, entry, limit=40)
            self.assertEqual(failures, [], family)


class MutationTests(Base):
    def failing(self, family, entry, patches):
        _, failures = tool.run_family(self.runner(patches), family, entry, stop_first=True)
        return failures

    def test_flipped_found_check_is_caught(self):
        rows = tool.decode_range(self.image, *self.image.exact_fde(CASCADE))
        point = next(row for row in rows if row.va == 0x42F772C)
        self.assertEqual(self.failing("cascade", CASCADE, tool.mutate(point, self.image))[0][1], "event log")

    def test_changed_peer_reason_is_caught(self):
        self.assertEqual(bytes(self.image.blob[self.image.offset(0x4305431):self.image.offset(0x4305431) + 3]), b"\x41\xb9\x0b")
        self.assertEqual(self.failing("peer", PEER, {0x4305433: 0x0C})[0][1], "event log")

    def test_changed_child_reason_is_caught(self):
        self.assertEqual(bytes(self.image.blob[self.image.offset(0x4303179):self.image.offset(0x4303179) + 3]), b"\x41\xb9\x02")
        self.assertEqual(self.failing("children", CHILDREN, {0x430317B: 0x03})[0][1], "event log")

    def test_changed_parent_offset_is_caught(self):
        self.assertEqual(self.failing("attach", tool.ATTACH, {0x43033E4: 0x18})[0][1], "final state")

    def test_changed_peer_tag_offset_is_caught(self):
        self.assertTrue(self.failing("peer", PEER, {0x430536E: 0x21}))

    def test_mutate_rejects_a_non_branch(self):
        rows = tool.decode_range(self.image, *self.image.exact_fde(CASCADE))
        with self.assertRaisesRegex(tool.EvidenceError, "not a jcc"):
            tool.mutate(rows[0], self.image)


class EvidenceTests(Base):
    def test_generated_files_match_the_packet(self):
        outputs = tool.render(tool.analyse(self.image))
        names = sorted(path.name for path in FOLDER.iterdir() if path.name not in ("README.md", "MANIFEST.sha256"))
        self.assertEqual(names, sorted(outputs))
        for name, content in outputs.items():
            self.assertEqual((FOLDER / name).read_text(encoding="utf-8"), content, name)

    def test_manifest_matches_the_folder(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
        listed = {}
        for row in rows:
            digest, name = row.split("  ", 1)
            listed[name] = digest
        self.assertEqual(sorted(listed), sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"))
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
