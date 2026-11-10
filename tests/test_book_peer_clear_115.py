"""Offline controls for the node 115 peer-clear reconstruction."""
import collections
import pathlib
import tempfile
import unittest
from types import SimpleNamespace

from tools import book_peer_clear_115 as subject


class MapMemory:
    def __init__(self, words):
        self.words = words

    def read(self, address, size):
        if size != 8:
            raise AssertionError("unexpected read width")
        return self.words[address]


class TableSpec(subject.Spec):
    """A small independent setup for peer-option state transitions."""

    def __init__(self, table, words):
        world = SimpleNamespace(builder=SimpleNamespace(memory=MapMemory(words)))
        super().__init__(world)
        self.table = table

    def locate(self, key, oid):
        self.log.append(("lookup", oid))
        found = self.table.get(oid)
        if found == "panic":
            raise subject.SpecPanic(oid)
        return None if found is None else SimpleNamespace(body=found)


class TinyImage:
    def __init__(self, address, blob):
        self.blob = blob
        self.mapped = [{"address": address, "offset": 0, "size": len(blob), "type": 1}]
        self.base = address

    def offset(self, va):
        if not self.base <= va < self.base + len(self.blob):
            raise subject.EvidenceError("outside")
        return va - self.base


class ClearSpecificationTests(unittest.TestCase):
    key = bytes(range(20))
    first = 0x1000
    second = 0x2000

    def spec(self, tag, other=2, table=None):
        if table is None:
            table = {1: self.first, 2: self.second}
        return TableSpec(table, {self.first + 0x20: tag, self.first + 0x28: other})

    def test_missing_order_does_not_write_or_look_for_peer(self):
        spec = self.spec(1, table={})
        subject.expected_clear(spec, self.key, 1)
        self.assertEqual(spec.log, [("lookup", 1)])
        self.assertEqual(spec.writes, [])
        self.assertIsNone(spec.panic)

    def test_clear_happens_before_tag_check(self):
        for tag in (0, 2, 3, 0x100000000):
            with self.subTest(tag=tag):
                spec = self.spec(tag)
                subject.expected_clear(spec, self.key, 1)
                self.assertEqual(spec.writes, [(self.first + 0x20, 8, 0)])
                self.assertEqual(spec.log, [("lookup", 1)])

    def test_low_dword_controls_search_even_if_high_bits_are_set(self):
        for tag in (1, 0x100000001, 0xffffffff00000001):
            with self.subTest(tag=tag):
                spec = self.spec(tag)
                subject.expected_clear(spec, self.key, 1)
                self.assertEqual(spec.log, [("lookup", 1), ("lookup", 2)])
                self.assertEqual(spec.writes, [(self.first + 0x20, 8, 0),
                                               (self.second + 0x20, 8, 0)])

    def test_missing_peer_leaves_first_clear_in_place(self):
        spec = self.spec(1, table={1: self.first})
        subject.expected_clear(spec, self.key, 1)
        self.assertEqual(spec.writes, [(self.first + 0x20, 8, 0)])
        self.assertEqual(spec.log, [("lookup", 1), ("lookup", 2)])

    def test_second_lookup_panic_preserves_prior_write(self):
        spec = self.spec(1, table={1: self.first, 2: "panic"})
        subject.expected_clear(spec, self.key, 1)
        self.assertEqual(spec.writes, [(self.first + 0x20, 8, 0)])
        self.assertEqual(spec.panic, (2, subject.PANIC_LOCATION))

    def test_first_lookup_panic_has_no_prior_write(self):
        spec = self.spec(1, table={1: "panic"})
        subject.expected_clear(spec, self.key, 1)
        self.assertEqual(spec.writes, [])
        self.assertEqual(spec.panic, (1, subject.PANIC_LOCATION))

    def test_self_reference_is_resolved_and_cleared_twice(self):
        spec = self.spec(1, other=1)
        subject.expected_clear(spec, self.key, 1)
        self.assertEqual(spec.log, [("lookup", 1), ("lookup", 1)])
        self.assertEqual(spec.writes, [(self.first + 0x20, 8, 0)] * 2)

    def test_second_tag_is_cleared_without_checking_its_value(self):
        spec = self.spec(1)
        subject.expected_clear(spec, self.key, 1)
        self.assertEqual(spec.writes[-1], (self.second + 0x20, 8, 0))

    def test_intentional_bad_models_change_observable_behavior(self):
        for name in ("leave-first", "test-all-64", "nonzero-tag",
                     "skip-peer", "search-self", "leave-peer"):
            with self.subTest(variant=name):
                tag = 2 if name == "nonzero-tag" else 0x100000001
                good = self.spec(tag)
                bad = self.spec(tag)
                subject.expected_clear(good, self.key, 1)
                subject.expected_clear(bad, self.key, 1, mutation=name)
                self.assertNotEqual((good.log, good.writes), (bad.log, bad.writes))

    def test_sample_rotation_covers_all_fault_schedule_residues(self):
        sample = [case for case in range(400) if subject.sample_number(case)]
        self.assertEqual(len(sample), 100)
        self.assertEqual({case % 20 for case in sample}, set(range(20)))

    def test_ring_result_checks_low_status_bit_and_advertised_length(self):
        table, key = 100, b"key"
        for status, index, expected in ((0, 3, 3), (0, 4, None),
                                        (0, 5, None), (1, 2, None),
                                        (2, 2, 2), (3, 2, None)):
            with self.subTest(status=status, index=index):
                world = SimpleNamespace(ring_overrides={(table, key, 0): (status, index)})
                spec = subject.Spec(world)
                self.assertEqual(spec.ring_position(table, key, None, 4), expected)

    def test_lookup_distinguishes_absent_slab_and_user_store(self):
        class LookupSpec:
            def __init__(self, order, hit):
                self.world = SimpleNamespace(oid_map={9: 0} if hit else {})
                self.order = order
                self.panic = None
                self.last_probe_status = 1 if hit else 0

            def locate(self, key, oid):
                return self.order

        order = SimpleNamespace(body=0x5430)
        self.assertEqual(subject.expected_lookup(LookupSpec(order, True), self.key, 9),
                         (0, order.body))
        self.assertEqual(subject.expected_lookup(LookupSpec(order, False), self.key, 9),
                         (1, order.body))
        self.assertEqual(subject.expected_lookup(LookupSpec(None, True), self.key, 9),
                         (2, None))


class InterpreterInstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()

    def machine(self):
        machine = subject.Machine(self.image)
        machine.regs = [0] * 16
        machine.regs[subject.RSP] = subject.STACK_TOP - 0x1000
        return machine

    def step_sequence(self, machine, addresses):
        for address in addresses:
            instruction = subject.decode(machine.read_code, address)
            machine.step(instruction)

    def test_unsigned_three_way_key_comparison_at_boundaries(self):
        machine = self.machine()
        base = subject.HEAP_BASE + 0x100
        machine.regs[subject.RAX] = base
        machine.regs[subject.RDX] = 0
        values = (0, 1, 2, (1 << 63) - 1, 1 << 63,
                  (1 << 63) + 1, (1 << 64) - 2, (1 << 64) - 1)
        for left in values:
            for right in values:
                with self.subTest(left=left, right=right):
                    machine.regs[subject.R15] = left
                    machine.regs[subject.R9] = 0x123400
                    machine.memory.write(base + 0x10, 8, right)
                    self.step_sequence(machine, (0x58e6b98, 0x58e6b9d, 0x58e6ba1))
                    expected = ((left > right) - (left < right)) & 0xff
                    self.assertEqual(machine.regs[subject.R9] & 0xff, expected)

    def test_twenty_byte_equality_checks_every_byte(self):
        machine = self.machine()
        base = subject.HEAP_BASE + 0x100
        machine.regs[subject.RAX] = base
        stack = machine.regs[subject.RSP]
        actual = bytes(range(20))
        machine.memory.put_bytes(base + 0xf8, actual)
        addresses = (0x58e69e7, 0x58e69ef, 0x58e69f7, 0x58e69fd,
                     0x58e6a03, 0x58e6a07, 0x58e6a0b, 0x58e6a0f)
        for changed_byte in range(-1, len(actual)):
            with self.subTest(changed_byte=changed_byte):
                query = bytearray(actual)
                if changed_byte >= 0:
                    query[changed_byte] ^= 0x80
                machine.memory.put_bytes(stack + 0x20, query[:16])
                machine.memory.put_bytes(stack + 0x30, query[16:])
                self.step_sequence(machine, addresses)
                self.assertEqual(machine.zf, changed_byte == -1)
                self.assertEqual(machine.regs[subject.RCX] & 0xffff == 0xffff,
                                 changed_byte == -1)

    def test_negation_overflow_selects_only_the_u64_midpoint(self):
        machine = self.machine()
        negate = subject.decode(machine.read_code, 0x58e6a2f)
        branch = subject.decode(machine.read_code, 0x58e6a32)
        for word in (0, 1, (1 << 63) - 1, 1 << 63,
                     (1 << 63) + 1, (1 << 64) - 1):
            with self.subTest(word=word):
                machine.regs[subject.RAX] = word
                machine.step(negate)
                self.assertEqual(machine.of, word == 1 << 63)
                destination = machine.step(branch)
                self.assertEqual(destination, branch.next if word == 1 << 63
                                 else branch.target)

    def test_comparator_hook_agrees_with_independent_bytes_order(self):
        values = (b"\x00" * 20, b"\x00" * 19 + b"\x01",
                  bytes(range(20)), b"\xff" + b"\x00" * 19, b"\xff" * 20)
        for left in values:
            for right in values:
                with self.subTest(left=left, right=right):
                    difference = subject.compare_value(left, right)
                    self.assertEqual((difference > 0) - (difference < 0),
                                     (left > right) - (left < right))


class BinaryEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()

    def test_binary_identity_is_checked_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = pathlib.Path(directory) / "node"
            bad.write_bytes(b"not an ELF")
            with self.assertRaisesRegex(subject.EvidenceError, "SHA-256 mismatch"):
                subject.load_image(bad)
        with self.assertRaises(subject.EvidenceError):
            subject.require_digest("f" * 64, subject.SHA256)

    def test_known_fde_extents_and_instruction_counts(self):
        rows = subject.verify_decoding(self.image)
        expected = (333, 333, 181, 181)
        for body, length in zip(subject.BODIES, expected):
            self.assertEqual(self.image.exact_fde(body["entry"]),
                             (body["entry"], body["end"]))
            self.assertEqual(len(rows[body["entry"]]), length)

    def test_entry_interior_and_nonfile_address_are_rejected(self):
        for body in subject.BODIES:
            with self.subTest(entry=body["entry"]):
                with self.assertRaises(subject.EvidenceError):
                    self.image.exact_fde(body["entry"] + 1)
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(0)
        with self.assertRaises(subject.EvidenceError):
            subject.bytes_at(self.image, subject.BODIES[0]["entry"], -1)

    def test_sections_reject_nobits_file_reads(self):
        nobits = [s for s in self.image.sections if s["type"] == 8 and s["size"]]
        self.assertTrue(nobits)
        self.assertTrue(all(section["type"] != 8 for section in self.image.mapped))
        # TLS NOBITS may share its VA with a different file-backed section;
        # test unmapped addresses only when no file-backed range overlaps it.
        unmapped = [s for s in nobits if not any(
            m["address"] <= s["address"] < m["address"] + m["size"]
            for m in self.image.mapped)]
        self.assertTrue(unmapped)
        for section in unmapped:
            with self.subTest(section=section["name"]):
                with self.assertRaises(subject.EvidenceError):
                    self.image.offset(section["address"])

    def test_file_backed_ranges_reject_crossing_and_ambiguity(self):
        text = self.image.named[".text"]
        final_byte = text["address"] + text["size"] - 1
        self.assertIsInstance(self.image.range_offset(final_byte, 1), int)
        with self.assertRaises(subject.EvidenceError):
            self.image.range_offset(final_byte, 2)
        with self.assertRaises(subject.Halt):
            subject.Memory(self.image).bytes_at(final_byte, 2)
        fake = subject.Image.__new__(subject.Image)
        fake.mapped = [
            {"address": 0x100, "size": 8, "offset": 0, "type": 1},
            {"address": 0x104, "size": 8, "offset": 8, "type": 1},
        ]
        with self.assertRaises(subject.EvidenceError):
            fake.range_offset(0x104, 1)

    def test_call_edges_are_verified_from_relative_bytes(self):
        rows = list(subject.checked_call_sites(self.image))
        self.assertEqual(len(rows), len(subject.CALL_SITES))
        for row in rows:
            if int(row[0], 16) in subject.ARGUMENT_PREFIXES:
                self.assertEqual(row[-1], 28)
                self.assertNotEqual(row[-2], "-")
        with self.assertRaises(subject.EvidenceError):
            subject.require_equal_bytes(b"bad", b"good")
        address = 0x3000
        displacement = (0x3400 - (address + 5)).to_bytes(4, "little", signed=True)
        valid = TinyImage(address, b"\xe8" + displacement)
        self.assertEqual(subject.direct_call(valid, address), 0x3400)
        corrupt_opcode = TinyImage(address, b"\xe9" + displacement)
        with self.assertRaises(subject.EvidenceError):
            subject.direct_call(corrupt_opcode, address)
        corrupt_disp = TinyImage(address, b"\xe8" + bytes([displacement[0] ^ 1]) + displacement[1:])
        self.assertNotEqual(subject.direct_call(corrupt_disp, address), 0x3400)

    def test_import_and_panic_relocations_are_checked_from_elf(self):
        rows = subject.checked_relocations(self.image)
        self.assertEqual(rows, [(subject.GOT_PANIC, 8, 0, 0x1680cbf, ""),
                                (subject.GOT_COMPARE, 6, 12, 0, "memcmp")])
        with self.assertRaises(subject.EvidenceError):
            subject.require_relocation(subject.GOT_COMPARE, 7, 12, 0, "memcmp")
        with self.assertRaises(subject.EvidenceError):
            subject.require_relocation(subject.GOT_COMPARE, 6, 12, 0, "other")

    def test_body_corruption_and_boundary_controls(self):
        checks = subject.integrity_controls(self.image)
        self.assertEqual(len(checks), 29)
        self.assertTrue(all(passed for _, passed in checks), checks)

    def test_branch_controls_bind_actual_instruction_boundaries(self):
        rows = subject.verify_decoding(self.image)
        controls = subject.make_controls(self.image, rows)
        branches = [x for x in controls if x["kind"] == "branch"]
        self.assertEqual(len(branches), 50)
        for item in branches:
            with self.subTest(va=item["va"]):
                address, replacement = next(iter(item["patches"].items()))
                self.assertEqual(self.image.blob[self.image.offset(address)] ^ 1, replacement)

    def test_comparison_replays_all_representation_classes(self):
        class Sink:
            def writerow(self, row):
                pass

        class Witnesses:
            def __init__(self):
                self.labels = set()

            def writerow(self, row):
                self.labels.add(row[0])

        witness = Witnesses()
        count, _, tally, controls, coverage, boundaries = subject.run_cases(
            self.image, 800, Sink(), witness)
        self.assertIn("self-reference-cleared", witness.labels)
        self.assertIn("present-tag-with-high-bits", witness.labels)
        self.assertIn("0x0", boundaries["order_id"])
        self.assertIn(hex((1 << 64) - 1), boundaries["order_id"])
        self.assertEqual(set(coverage), {b["entry"] for b in subject.BODIES})
        self.assertEqual(count, 3200)
        self.assertGreater(len(tally), 20)
        self.assertTrue(all(item["detected"] for item in controls),
                        [item for item in controls if not item["detected"]])
        clear = [fields for fields in tally if fields[0] == subject.CLEAR]
        lookup = [fields for fields in tally if fields[0] == subject.LOOKUP]
        self.assertEqual({fields[1] for fields in clear}, {"tree", "ring"})
        self.assertTrue({"tree", "ring"}.issubset({fields[2] for fields in clear}))
        self.assertTrue({0, 1, 2}.issubset({fields[4] for fields in clear}))
        self.assertTrue(any(fields[5] for fields in clear))
        self.assertTrue({0, 1, 2}.issubset({fields[6] for fields in lookup}))
        self.assertFalse(any(fields[7].startswith("second-") for fields in lookup))
        faults = {fields[7] for fields in clear}
        self.assertTrue({"first-user-oob", "first-order-oob", "second-user-oob",
                         "second-order-oob", "first-probe-status-0x2",
                         "first-probe-status-0x100000001"}.issubset(faults), faults)
        for fields in clear:
            if fields[7] in ("first-user-oob", "first-order-oob"):
                self.assertEqual(fields[4:6], (0, False))
            if fields[7] in ("second-user-oob", "second-order-oob"):
                self.assertEqual(fields[4:6], (1, False))
        decoded = subject.verify_decoding(self.image)
        for body in subject.BODIES:
            hits = coverage[body["entry"]]
            for row in decoded[body["entry"]]:
                self.assertIn(row.va, hits["instructions"])
                if row.op == "jcc":
                    self.assertEqual(hits["edges"].get(row.va, 0), 3, hex(row.va))

    def test_independent_replay_is_deterministic(self):
        first = subject.Harness(self.image)
        second = subject.Harness(self.image)
        for index in range(len(subject.BODIES)):
            for case in (0, 7, 99, 211):
                ok_a, a = subject.execute_case(first, index, case, capture=True)
                ok_b, b = subject.execute_case(second, index, case, capture=True)
                self.assertTrue(ok_a and ok_b)
                self.assertEqual(a, b)
                proof = a["comparison"]
                self.assertEqual(proof["expected_heap_sha256"], proof["actual_heap_sha256"])
                self.assertEqual(proof["expected_events"], proof["actual_events"])
                self.assertEqual(proof["expected_panic"], proof["actual_panic"])

    def test_sample_worlds_cover_signed_tag_niche_and_lookup_misses(self):
        harness = subject.Harness(self.image)
        tally = collections.Counter()
        for body_index in range(len(subject.BODIES)):
            for case in range(150):
                ok, row = subject.execute_case(harness, body_index, case)
                self.assertTrue(ok, row)
                tally[(row["op"], row["probe"], row["result"])] += 1
        self.assertTrue(tally[(subject.LOOKUP, "hit", 2)])
        self.assertTrue(tally[(subject.LOOKUP, "miss", 1)])


if __name__ == "__main__":
    unittest.main()
