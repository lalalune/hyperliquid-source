"""Tests for tools/registrar_map_115.py (RE-001-registrar-map-115).

Every expectation is target-grounded: field offsets, sizes, literals and
census counts come from the packet's verbatim excerpts and census; the
seeded chains exercise the ctor replay and the destructor end to end.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import registrar_map_115 as m


class StaticInitTests(unittest.TestCase):
    def test_empty_state_invariants(self):
        mem = m.Memory()
        reg, strings, atexit = m.static_init(mem)
        self.assertTrue(reg.is_empty_state())
        self.assertEqual(reg.buckets, reg.single_bucket)
        self.assertEqual(reg.buckets, m.MAP_ADDR + m.MAP_SINGLE_BUCKET)
        self.assertEqual(reg.bucket_count, 1)
        self.assertIsNone(reg.before_begin)
        self.assertEqual(reg.element_count, 0)
        self.assertEqual(reg.max_load_factor, 1.0)
        self.assertEqual(reg.next_resize, 0)
        self.assertIsNone(reg._get(m.MAP_SINGLE_BUCKET))

    def test_build_info_strings_are_heap_and_exact(self):
        mem = m.Memory()
        _, strings, _ = m.static_init(mem)
        self.assertEqual(strings[0x65095C0].value(), m.BUILD_SHA)
        self.assertEqual(strings[0x65095A0].value(), m.BUILD_TAG)
        self.assertEqual(strings[0x6509580].value(), m.BUILD_DATE)
        for s in strings.values():
            # All three literals exceed the 15-byte SSO limit: heap storage.
            self.assertFalse(s.is_local())
            self.assertEqual(s.length, len(s.value()))
            self.assertEqual(s.capacity, len(s.value()))
        self.assertEqual(len(m.BUILD_SHA), 40)
        self.assertEqual(len(m.BUILD_TAG), 28)
        self.assertEqual(len(m.BUILD_DATE), 38)

    def test_max_load_factor_bits(self):
        import struct
        self.assertEqual(
            struct.pack("<f", m.MAX_LOAD_FACTOR).hex(), "0000803f")
        self.assertEqual(m.MAX_LOAD_FACTOR_BITS, 0x3F800000)

    def test_atexit_registration_order(self):
        mem = m.Memory()
        _, _, atexit = m.static_init(mem)
        self.assertEqual(atexit, [
            ("std::string::~basic_string", 0x65095C0),
            ("std::string::~basic_string", 0x65095A0),
            ("std::string::~basic_string", 0x6509580),
            ("registrar_map_destructor", m.MAP_ADDR),
        ])

    def test_map_object_size_and_neighbours(self):
        self.assertEqual(m.MAP_SIZE, 0x38)
        self.assertEqual(m.MAP_ADDR + m.MAP_SIZE, 0x6509578)
        # The next global (date string) starts 8 bytes later.
        self.assertEqual(0x6509580 - (m.MAP_ADDR + m.MAP_SIZE), 8)


class StringAssignTests(unittest.TestCase):
    def setUp(self):
        self.mem = m.Memory()
        self.obj = self.mem.alloc(0x20)

    def test_sso_boundaries(self):
        for text in ("", "x", "123456789012345"):
            s = m.string_assign(self.mem, self.obj, text)
            self.assertTrue(s.is_local(), text)
            self.assertEqual(s.value(), text)
            self.assertEqual(s.length, len(text))
            self.assertEqual(s.ptr, s.sso_buffer)

    def test_heap_boundary(self):
        s = m.string_assign(self.mem, self.obj, "1234567890123456")
        self.assertFalse(s.is_local())
        self.assertEqual(s.value(), "1234567890123456")
        self.assertEqual(s.length, 16)
        self.assertEqual(s.capacity, 16)
        # Heap allocation is length + 1 (room for the NUL).
        allocs = [op for op in self.mem.ops if op[0] == "alloc"]
        self.assertEqual(allocs[-1], ("alloc", s.ptr, 17))

    def test_null_input_raises_logic_error(self):
        with self.assertRaises(m.LogicError) as ctx:
            m.string_assign(self.mem, self.obj, None)
        self.assertEqual(str(ctx.exception), m.NULL_CTOR_MESSAGE)

    def test_first_write_is_sso_pointer(self):
        # The helper writes the SSO-buffer address into the data pointer
        # before branching on the input (observed at 0x5f20502).
        s = m.string_assign(self.mem, self.obj, "ab")
        self.assertEqual(s.ptr, s.sso_buffer)
        self.assertEqual(s.value(), "ab")


class CtorReplayTests(unittest.TestCase):
    def _seeded_map(self, pairs):
        mem = m.Memory()
        reg, _, _ = m.static_init(mem)
        # Build a 3-node chain: head -> ... ; before_begin points at head.
        prev = None
        head = None
        addrs = []
        for name, manager in pairs:
            addr = mem.alloc(m.NODE_SIZE)
            node = m.RegistrarNode(mem, addr, name, manager)
            addrs.append(addr)
            if prev is not None:
                prev.nxt = addr
            else:
                head = addr
            prev = node
        reg._set(m.MAP_BEFORE_BEGIN, head)
        reg._set(m.MAP_ELEMENT_COUNT, len(pairs))
        return mem, reg, addrs

    def test_empty_map_replay_is_vacuous(self):
        mem = m.Memory()
        reg, _, _ = m.static_init(mem)
        seen = []
        visited = m.ctor_replay(reg, lambda name, creator: seen.append((name, creator)))
        self.assertEqual(visited, [])
        self.assertEqual(seen, [])

    def test_seeded_chain_replays_in_order(self):
        pairs = [("TTL", "ttl-creator"), ("encryption", "enc-creator"),
                 ("Statistics", None)]
        mem, reg, _ = self._seeded_map(pairs)
        seen = []
        visited = m.ctor_replay(reg, lambda n, c: seen.append((n, c)))
        self.assertEqual([n for n, _ in visited], ["TTL", "encryption", "Statistics"])
        self.assertEqual(seen, visited)
        # The creator recorded is the manager pointer (opaque identity).
        self.assertEqual(visited[0][1], "ttl-creator")
        self.assertEqual(visited[1][1], "enc-creator")
        self.assertIsNone(visited[2][1])

    def test_node_layout_offsets(self):
        mem = m.Memory()
        addr = mem.alloc(m.NODE_SIZE)
        node = m.RegistrarNode(mem, addr, "TTL", "mgr")
        # Name string lives at node+0x08; creator function at node+0x28;
        # its manager at node+0x38; hash slot at node+0x48.
        self.assertEqual(node.key.value(), "TTL")
        self.assertEqual(mem.get(addr + m.NODE_VALUE, m.FN_MANAGER), "mgr")
        self.assertEqual(mem.get(addr, m.NODE_HASH), None)
        self.assertEqual(m.NODE_SIZE, 0x50)


class MapDestroyTests(unittest.TestCase):
    def _seeded_map(self, pairs, heap_names=True):
        mem = m.Memory()
        reg, _, _ = m.static_init(mem)
        prev = None
        head = None
        for name, manager in pairs:
            addr = mem.alloc(m.NODE_SIZE)
            node = m.RegistrarNode(mem, addr, name, manager)
            if prev is not None:
                prev.nxt = addr
            else:
                head = addr
            prev = node
        reg._set(m.MAP_BEFORE_BEGIN, head)
        reg._set(m.MAP_ELEMENT_COUNT, len(pairs))
        return mem, reg

    def test_destroy_calls_manager_op3_in_chain_order(self):
        calls = []

        def manager(functor, same, op):
            calls.append((functor, same, op))

        mem, reg = self._seeded_map(
            [("TTL", manager), ("encryption", manager), ("short", None)])
        destroyed = m.map_destroy(mem, reg)
        self.assertEqual([n for n, _ in destroyed],
                         ["TTL", "encryption", "short"])
        self.assertEqual([c for _, c in destroyed], [True, True, False])
        # Manager op 3 (destroy), called with (functor, functor).
        self.assertEqual(len(calls), 2)
        for functor, same, op in calls:
            self.assertEqual(functor, same)
            self.assertEqual(op, 3)

    def test_destroy_frees_nodes_sized_0x50(self):
        mem, reg = self._seeded_map([("TTL", None), ("encryption", None)])
        frees_before = [op for op in mem.ops if op[0] == "free"]
        m.map_destroy(mem, reg)
        node_frees = [op for op in mem.ops if op[0] == "free"
                      and op not in frees_before]
        # Two node frees (0x50 each); the heap name buffers are freed too
        # only for names longer than the SSO limit -- "TTL" (3) and
        # "encryption" (10) are both SSO, so no string-buffer frees.
        self.assertEqual(len(node_frees), 2)
        self.assertTrue(all(op[2] == 0x50 for op in node_frees),
                        node_frees)

    def test_destroy_frees_heap_key_buffers(self):
        mem, reg = self._seeded_map(
            [("a-very-long-library-name", None)])
        # The long name allocated a heap buffer of len+1.
        heap_bufs = [op for op in mem.ops
                     if op[0] == "alloc" and op[2] == len("a-very-long-library-name") + 1]
        self.assertEqual(len(heap_bufs), 1)
        buf = heap_bufs[0][1]
        m.map_destroy(mem, reg)
        self.assertIn(("free", buf, len("a-very-long-library-name") + 1),
                      mem.ops)

    def test_destroy_tears_down_buckets(self):
        mem, reg = self._seeded_map([("TTL", None)])
        destroyed = m.map_destroy(mem, reg)
        self.assertEqual(len(destroyed), 1)
        # Empty map: buckets == single bucket, so no array free; the
        # memset still runs over count*8 == 8 bytes.
        self.assertIn(("memset", reg.single_bucket, 8), mem.ops)
        self.assertEqual(reg.element_count, 0)
        self.assertIsNone(reg.before_begin)
        self.assertNotIn(("free", reg.single_bucket, 8), mem.ops)

    def test_destroy_frees_heap_bucket_array(self):
        mem, reg = self._seeded_map([("TTL", None)])
        # Simulate a grown map: 8 buckets on the heap.
        buckets = mem.alloc(8 * 8)
        reg._set(m.MAP_BUCKETS, buckets)
        reg._set(m.MAP_BUCKET_COUNT, 8)
        m.map_destroy(mem, reg)
        self.assertIn(("memset", buckets, 64), mem.ops)
        self.assertIn(("free", buckets, 64), mem.ops)


class CensusTests(unittest.TestCase):
    def test_census_constants(self):
        self.assertEqual(m.MAP_LEA_SITES, (0x61F9234, 0x620B516))
        self.assertEqual(m.STRING_HELPER_CALLS, 12)
        self.assertEqual(m.GETTER_CALLERS, (0x5FF88FC, 0x61F9420, 0x6206A3D))
        self.assertEqual(m.CTOR_CALLER, 0x61F9380)

    def test_fde_ranges(self):
        self.assertEqual(m.STATIC_INIT_FDE, (0x620B470, 0x620B57D))
        self.assertEqual(m.STRING_ASSIGN_FDE, (0x5F204E0, 0x5F205C3))
        self.assertEqual(m.MAP_DTOR_FDE, (0x620A500, 0x620A5BD))
        self.assertEqual(m.CTOR_FDE, (0x61F91B0, 0x61F9277))

    def test_no_inserter_result(self):
        # The packet's central result: the map has no inserter, so a
        # freshly initialized map replays zero libraries.
        mem = m.Memory()
        reg, _, _ = m.static_init(mem)
        self.assertEqual(reg.chain(), [])
        self.assertEqual(m.ctor_replay(reg, lambda n, c: None), [])


if __name__ == "__main__":
    unittest.main()
