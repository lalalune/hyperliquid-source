"""Tests for the FilterPolicy builtin registrations model (node #115).

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The model pins the nine factories the builtin registrar 0x6137fe0
registers (one inlined, eight through 0x6137810), what each creator
builds, and the ':'-split name parsing. The exact matching semantics of
PatternEntry Matches (0x61f8670) and the parse helpers (0x61d2380,
0x61d1e30, 0x61d1b90) are cited, not pinned, so the matcher and the
parsers are models of the recorded pattern, not binary claims.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from filter_policy_registrations_115 import (
    MANAGER_OP_CLONE,
    MANAGER_OP_DESTROY,
    MANAGER_OP_FUNCTOR_PTR,
    MANAGER_OP_TYPEINFO,
    MAP_KEY,
    PER_FACTORY_REGISTRAR,
    REGISTRAR,
    REGISTRATIONS,
    create,
    find_factory,
    manager_op,
    parse_double,
    parse_int,
    split_name,
)


class TestRegistrationTable(unittest.TestCase):
    def test_nine_factories(self):
        self.assertEqual(len(REGISTRATIONS), 9)

    def test_indices_in_order(self):
        self.assertEqual([e.index for e in REGISTRATIONS],
                         list(range(1, 10)))

    def test_single_map_key(self):
        self.assertEqual(MAP_KEY, "FilterPolicy")

    def test_managers_step_0x30(self):
        managers = [e.manager for e in REGISTRATIONS]
        self.assertEqual(managers[0], 0x612D2A0)
        for prev, cur in zip(managers, managers[1:]):
            self.assertEqual(cur - prev, 0x30)

    def test_invokers_distinct(self):
        invokers = [e.invoker for e in REGISTRATIONS]
        self.assertEqual(len(set(invokers)), 9)

    def test_entry_names(self):
        names = [e.entry_name for e in REGISTRATIONS]
        self.assertEqual(names, [
            "rocksdb.BuiltinBloomFilter",
            "bloomfilter",
            "bloomfilter",
            "ribbonfilter",
            "ribbonfilter",
            "ribbonfilter",
            "rocksdb.internal.LegacyBloomFilter",
            "rocksdb.internal.FastLocalBloomFilter",
            "rocksdb.internal.Standard128RibbonFilter",
        ])

    def test_registrar_addresses(self):
        self.assertEqual(REGISTRAR, 0x6137FE0)
        self.assertEqual(PER_FACTORY_REGISTRAR, 0x6137810)

    def test_option_elements(self):
        self.assertEqual(REGISTRATIONS[2].option_elements, [(":false", 2)])
        self.assertEqual(REGISTRATIONS[3].option_elements, [(":true", 2)])
        self.assertEqual(REGISTRATIONS[5].option_elements, [(":", 3)])
        for i in (0, 1, 4, 6, 7, 8):
            self.assertEqual(REGISTRATIONS[i].option_elements, [])


class TestCreatorOutcomes(unittest.TestCase):
    def test_builtin_ignores_name(self):
        policy = create("rocksdb.BuiltinBloomFilter")
        self.assertEqual(policy.policy_class,
                         "rocksdb::ReadOnlyBuiltinFilterPolicy")
        self.assertEqual(policy.size, 0x20)
        self.assertEqual(policy.vtable, 0x64D4AF0)
        self.assertIsNone(policy.bits)
        self.assertIsNone(policy.int_param)

    def test_builtin_ignores_suffix(self):
        # The builtin creator 0x612de10 does no parsing at all.
        policy = create("rocksdb.BuiltinBloomFilter:10")
        self.assertEqual(policy.policy_class,
                         "rocksdb::ReadOnlyBuiltinFilterPolicy")
        self.assertIsNone(policy.bits)

    def test_bloom(self):
        policy = create("bloomfilter:10")
        self.assertEqual(policy.policy_class, "rocksdb::BloomFilterPolicy")
        self.assertEqual(policy.size, 0x40)
        self.assertEqual(policy.vtable, 0x64D4F20)
        self.assertEqual(policy.bits, 10.0)

    def test_bloom_false(self):
        policy = create("bloomfilter:10:false")
        self.assertEqual(policy.policy_class, "rocksdb::BloomFilterPolicy")
        self.assertEqual(policy.size, 0x40)
        self.assertEqual(policy.bits, 10.0)

    def test_ribbon_true_builds_bloom(self):
        # The table's asymmetry: the ':true' ribbon factory builds a
        # BloomFilterPolicy, not a RibbonFilterPolicy.
        policy = create("ribbonfilter:10:true")
        self.assertEqual(policy.policy_class, "rocksdb::BloomFilterPolicy")
        self.assertEqual(policy.size, 0x40)
        self.assertEqual(policy.vtable, 0x64D4F20)
        self.assertEqual(policy.bits, 10.0)

    def test_ribbon_plain(self):
        policy = create("ribbonfilter:10")
        self.assertEqual(policy.policy_class, "rocksdb::RibbonFilterPolicy")
        self.assertEqual(policy.size, 0x48)
        self.assertEqual(policy.vtable, 0x64D52E0)
        self.assertEqual(policy.bits, 10.0)
        self.assertEqual(policy.int_param, 0)

    def test_ribbon_colon_int(self):
        policy = create("ribbonfilter:10:3")
        self.assertEqual(policy.policy_class, "rocksdb::RibbonFilterPolicy")
        self.assertEqual(policy.size, 0x48)
        self.assertEqual(policy.int_param, 3)

    def test_internal_names(self):
        cases = [
            ("rocksdb.internal.LegacyBloomFilter:10",
             "rocksdb::test::LegacyBloomFilterPolicy", 0x64D4FE0),
            ("rocksdb.internal.FastLocalBloomFilter:10",
             "rocksdb::test::FastLocalBloomFilterPolicy", 0x64D50A0),
            ("rocksdb.internal.Standard128RibbonFilter:10",
             "rocksdb::test::Standard128RibbonFilterPolicy", 0x64D5160),
        ]
        for name, cls, vtable in cases:
            policy = create(name)
            self.assertEqual(policy.policy_class, cls)
            self.assertEqual(policy.size, 0x40)
            self.assertEqual(policy.vtable, vtable)
            self.assertEqual(policy.bits, 10.0)

    def test_unknown_name(self):
        with self.assertRaises(LookupError):
            create("nosuchfilter:10")

    def test_slot_release(self):
        slot = {}
        first = create("bloomfilter:10", slot)
        self.assertIs(slot["policy"], first)
        second = create("ribbonfilter:10", slot)
        self.assertIs(slot["policy"], second)
        self.assertIsNot(first, second)


class TestFindFactory(unittest.TestCase):
    def test_most_specific_wins(self):
        self.assertEqual(find_factory("bloomfilter:10:false").index, 3)
        self.assertEqual(find_factory("bloomfilter:10").index, 2)
        self.assertEqual(find_factory("ribbonfilter:10:true").index, 4)
        self.assertEqual(find_factory("ribbonfilter:10").index, 5)
        self.assertEqual(find_factory("ribbonfilter:10:3").index, 6)

    def test_no_match(self):
        self.assertIsNone(find_factory("unknown:10"))


class TestParseHelpers(unittest.TestCase):
    def test_split(self):
        self.assertEqual(split_name("ribbonfilter:10:true"),
                         ["ribbonfilter", "10", "true"])
        self.assertEqual(split_name("bloomfilter"), ["bloomfilter"])

    def test_parse_double(self):
        self.assertEqual(parse_double("10"), 10.0)
        self.assertAlmostEqual(parse_double("9.5"), 9.5)

    def test_parse_int(self):
        self.assertEqual(parse_int("3"), 3)


class TestManagerTemplate(unittest.TestCase):
    def test_op_dispatch(self):
        self.assertEqual(
            manager_op(0x612D2A0, MANAGER_OP_TYPEINFO),
            "RegisterBuiltinFilterPolicies lambda")
        self.assertEqual(
            manager_op(0x612D2A0, MANAGER_OP_FUNCTOR_PTR, functor="f"), "f")
        self.assertIsNone(manager_op(0x612D2A0, MANAGER_OP_CLONE))
        self.assertIsNone(manager_op(0x612D2A0, MANAGER_OP_DESTROY))

    def test_unknown_op(self):
        with self.assertRaises(ValueError):
            manager_op(0x612D2A0, 9)


if __name__ == "__main__":
    unittest.main()
