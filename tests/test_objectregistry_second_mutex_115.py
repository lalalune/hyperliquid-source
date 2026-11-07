"""Tests for tools/objectregistry_second_mutex_115.py
(RE-001-objectregistry-second-mutex-115).

Every expectation is target-grounded: field offsets, sizes, the
16+16+8 zeroing pattern, the lock sites and the census counts come
from the packet's verbatim excerpts and census; the lifecycle test
exercises the two-mutex discipline end to end.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import objectregistry_second_mutex_115 as m


class LayoutTests(unittest.TestCase):
    def test_object_size_and_mutex_offsets(self):
        self.assertEqual(m.REGISTRY_SIZE, 0xC0)
        self.assertEqual(m.OBJECTS_MUTEX, 0x70)
        self.assertEqual(m.LIBRARY_MUTEX, 0x98)
        self.assertEqual(m.MUTEX_SIZE, 0x28)
        # The two mutexes tile the tail exactly: 0x70+0x28 == 0x98,
        # 0x98+0x28 == 0xc0.
        self.assertEqual(m.OBJECTS_MUTEX + m.MUTEX_SIZE, m.LIBRARY_MUTEX)
        self.assertEqual(m.LIBRARY_MUTEX + m.MUTEX_SIZE, m.REGISTRY_SIZE)

    def test_field_offsets(self):
        self.assertEqual(m.LIBRARIES, 0x00)
        self.assertEqual(m.NAMES, 0x18)
        self.assertEqual(m.MANAGED_MAP, 0x30)
        self.assertEqual(m.PARENT, 0x60)

    def test_zero_chunks_are_16_16_8(self):
        self.assertEqual(m.ZERO_CHUNKS, (16, 16, 8))
        self.assertEqual(sum(m.ZERO_CHUNKS), m.MUTEX_SIZE)


class ZeroingTests(unittest.TestCase):
    def _registry(self):
        mem = m.Memory()
        return mem, m.Registry(mem, 0x1000000)

    def test_ctor_zeroes_both_mutexes_with_same_pattern(self):
        mem, reg = self._registry()
        reg.ctor()
        zeros = [op for op in mem.ops if op[0] == "zero"]
        obj_zeros = [(off, size) for _k, _a, off, size in zeros
                     if _a == reg.addr]
        self.assertEqual(obj_zeros, [
            (0x70, 16), (0x80, 16), (0x90, 8),
            (0x98, 16), (0xA8, 16), (0xB8, 8),
        ])
        self.assertEqual(reg.objects_mutex.state, "zeroed")
        self.assertEqual(reg.library_mutex.state, "zeroed")

    def test_ctor_zeroes_fields_and_map_header(self):
        mem, reg = self._registry()
        reg.ctor()
        kinds = [op[0] for op in mem.ops]
        self.assertIn("zero-vector", kinds)
        self.assertIn("zero-map-header", kinds)
        self.assertIn("zero-shared-ptr", kinds)
        # Map header: left == right == &header, count 0.
        self.assertEqual(mem.get(reg.addr, m.MANAGED_MAP + 24),
                         reg.addr + m.MANAGED_MAP + 8)
        self.assertEqual(mem.get(reg.addr, m.MANAGED_MAP + 32),
                         reg.addr + m.MANAGED_MAP + 8)
        self.assertEqual(mem.get(reg.addr, m.MANAGED_MAP + 40), 0)
        self.assertIsNone(reg.parent)

    def test_clone_zeroes_both_mutexes_and_installs_parent(self):
        mem, reg = self._registry()
        reg.ctor()
        clone = m.Registry(mem, 0x10000C0)
        clone.clone(reg)
        zeros = [(op[2], op[3]) for op in mem.ops
                 if len(op) == 4 and op[0] == "zero"
                 and op[1] == clone.addr]
        self.assertEqual(zeros, [
            (0x70, 16), (0x80, 16), (0x90, 8),
            (0x98, 16), (0xA8, 16), (0xB8, 8),
        ])
        self.assertIs(clone.parent, reg)
        self.assertEqual(mem.get(clone.addr, m.PARENT), reg)

    def test_mutexes_start_zeroed_not_locked(self):
        mem, reg = self._registry()
        reg.ctor()
        self.assertEqual(reg.objects_mutex.state, "zeroed")
        self.assertEqual(reg.library_mutex.state, "zeroed")
        self.assertEqual(reg.objects_mutex.lock_count, 0)
        self.assertEqual(reg.library_mutex.lock_count, 0)
        self.assertIsNone(reg.objects_mutex.holder)
        self.assertIsNone(reg.library_mutex.holder)

    def test_ctor_seed_needs_no_lock(self):
        # The ctor seeds libraries[0] via vec-insert 0x5ff7960 without
        # taking either mutex: the seed happens before any locking.
        mem, reg = self._registry()
        reg.ctor()
        reg.libraries.append("default-library")
        self.assertEqual(reg.libraries, ["default-library"])
        self.assertEqual(reg.library_mutex.lock_count, 0)
        self.assertEqual(reg.library_mutex.state, "zeroed")


class LockDisciplineTests(unittest.TestCase):
    def _registry(self):
        mem = m.Memory()
        reg = m.Registry(mem, 0x1000000)
        reg.ctor()
        return mem, reg

    def test_add_library_requires_library_lock(self):
        mem, reg = self._registry()
        with self.assertRaises(m.MutexError):
            reg._locked_libraries_append("AddLibrary", "x", "lib")
        reg.add_library("AddLibrary", "encryption", "enc-library")
        self.assertEqual(reg.libraries, ["enc-library"])
        self.assertEqual(reg.names, ["encryption"])
        self.assertEqual(reg.library_mutex.state, "unlocked")
        self.assertEqual(reg.library_mutex.lock_count, 1)

    def test_ttl_register_appends_only_to_libraries(self):
        mem, reg = self._registry()
        reg.ttl_register("TTL", "ttl-library")
        self.assertEqual(reg.libraries, ["ttl-library"])
        self.assertEqual(reg.names, [])
        self.assertEqual(reg.library_mutex.lock_count, 1)

    def test_big_method_register_requires_lock(self):
        mem, reg = self._registry()
        with self.assertRaises(m.MutexError):
            reg._locked_libraries_append("big-method", "x", "lib")
        reg.big_method_register("big-method", "Statistics", "stats-lib")
        self.assertEqual(reg.libraries, ["stats-lib"])
        self.assertEqual(reg.names, ["Statistics"])

    def test_objects_mutex_never_acquired_in_lifecycle(self):
        mem = m.Memory()
        m.lifecycle(mem)
        self.assertEqual(
            [op for op in mem.ops if op[0] in ("lock", "unlock")
             and op[2] == m.OBJECTS_MUTEX], [])
        # The library mutex is acquired once per registering routine.
        lib_locks = [op for op in mem.ops if op[0] == "lock"
                     and op[2] == m.LIBRARY_MUTEX]
        self.assertEqual(len(lib_locks), 3)
        lib_unlocks = [op for op in mem.ops if op[0] == "unlock"
                       and op[2] == m.LIBRARY_MUTEX]
        self.assertEqual(len(lib_unlocks), 3)

    def test_double_lock_raises(self):
        mem, reg = self._registry()
        reg.library_mutex.lock("AddLibrary")
        with self.assertRaises(m.MutexError):
            reg.library_mutex.lock("TTL")
        reg.library_mutex.unlock("AddLibrary")

    def test_unlock_by_non_holder_raises(self):
        mem, reg = self._registry()
        reg.library_mutex.lock("AddLibrary")
        with self.assertRaises(m.MutexError):
            reg.library_mutex.unlock("TTL")
        reg.library_mutex.unlock("AddLibrary")

    def test_mutex_destroy_is_unreachable(self):
        mem, reg = self._registry()
        with self.assertRaises(m.MutexError):
            reg.objects_mutex.destroy()
        with self.assertRaises(m.MutexError):
            reg.library_mutex.destroy()

    def test_each_locker_unlocks_in_its_own_fde(self):
        # Every library lock site has its matching unlock inside the
        # same routine's FDE: lock/unlock are balanced per routine.
        fdes = (m.ADD_LIBRARY_FDE, m.BIG_METHOD_FDE, m.TTL_REGISTER_FDE)
        for locker, (start, end) in zip(m.LIBRARY_LOCKERS, fdes):
            self.assertEqual(locker["fde"], start)
            self.assertTrue(start <= locker["lock"] < end)
            self.assertTrue(start <= locker["unlock"] < end)


class DisposeTests(unittest.TestCase):
    def test_dispose_order_and_no_mutex_touch(self):
        mem = m.Memory()
        singleton, clone = m.lifecycle(mem)
        kinds = [op[0] for op in mem.ops]
        # Dispose order per registry: parent, map, names, libraries.
        self.assertEqual(
            [k for k in kinds if k.startswith("dispose-")],
            ["dispose-parent", "dispose-map", "dispose-names",
             "dispose-libraries"] * 2)
        # No mutex op (lock/unlock/zero/destroy) happens after the
        # first dispose begins.
        first = kinds.index("dispose-parent")
        tail = mem.ops[first:]
        self.assertEqual(
            [op for op in tail
             if op[0] in ("lock", "unlock")
             or (op[0] == "zero" and op[2] in (m.OBJECTS_MUTEX,
                                                m.LIBRARY_MUTEX))],
            [])
        self.assertTrue(singleton.disposed)
        self.assertTrue(clone.disposed)
        self.assertEqual(singleton.libraries, [])
        self.assertEqual(clone.libraries, [])


class AbsentMethodsTests(unittest.TestCase):
    def test_managed_object_methods_are_absent(self):
        mem = m.Memory()
        reg = m.Registry(mem, 0x1000000)
        reg.ctor()
        for call in (reg.set_managed_object, reg.get_managed_object,
                     reg.list_managed_objects):
            with self.assertRaises(m.MethodAbsent):
                call("type", "id")
        # Calling them never acquires objects_mutex_.
        self.assertEqual(reg.objects_mutex.lock_count, 0)
        self.assertEqual(reg.objects_mutex.state, "zeroed")

    def test_absent_strings(self):
        self.assertIn("Object already exists: ", m.ABSENT_STRINGS)
        self.assertIn("Registered Plugins:", m.ABSENT_STRINGS)

    def test_sole_managed_string_is_the_iterator_error(self):
        # The binary's only "managed" string is the RocksDB iterator
        # error message, not a registry managed-object string.
        self.assertEqual(m.SOLE_MANAGED_STRING_FILE_OFFSET, 0x95F620)
        self.assertEqual(m.SOLE_MANAGED_STRING,
                         "Managed iterator is not supported anymore.")
        self.assertTrue(m.SOLE_MANAGED_STRING.startswith(
            "Managed iterator"))
        self.assertNotIn("ObjectRegistry", m.SOLE_MANAGED_STRING)
        self.assertNotIn("managed_object", m.SOLE_MANAGED_STRING.lower())

    def test_managed_map_stays_empty(self):
        # No managed-object method ever populates the +0x30 map: the
        # lifecycle leaves it empty, and dispose clears it.
        mem = m.Memory()
        singleton, clone = m.lifecycle(mem)
        self.assertEqual(singleton.managed, {})
        self.assertEqual(clone.managed, {})


class CensusTests(unittest.TestCase):
    def test_lock_totals(self):
        self.assertEqual(m.LOCK_SITES_TOTAL, 1632)
        self.assertEqual(m.LOCK_CALLS, 224)
        self.assertEqual(m.UNLOCK_CALLS, 916)
        self.assertEqual(m.TRYLOCK_CALLS, 487)
        self.assertEqual(m.INIT_CALLS, 4)
        self.assertEqual(m.DESTROY_PLT_CALLS, 1)
        self.assertEqual(m.LOCK_CALLS + m.UNLOCK_CALLS + m.TRYLOCK_CALLS
                         + m.INIT_CALLS + m.DESTROY_PLT_CALLS,
                         m.LOCK_SITES_TOTAL)

    def test_disp_site_counts(self):
        self.assertEqual(m.DISP70_SITES, 8)
        self.assertEqual(m.DISP98_SITES, 28)
        self.assertEqual(m.DESTROY_HELPER_CALLERS, 74)
        self.assertEqual(m.MARKED_FDES, 32)
        self.assertEqual(m.DISP_HITS, 216)

    def test_library_lockers(self):
        self.assertEqual(len(m.LIBRARY_LOCKERS), 3)
        self.assertEqual(
            [(l["lock"], l["unlock"]) for l in m.LIBRARY_LOCKERS],
            [(0x61F8F09, 0x61F8F4F), (0x5FF8A28, 0x5FF8A7B),
             (0x6206B73, 0x6206BB4)])
        self.assertEqual(
            [l["routine"] for l in m.LIBRARY_LOCKERS],
            ["AddLibrary", "big registry method", "TTL registration"])

    def test_foreign_lock70_fdes(self):
        self.assertEqual(len(m.LOCK70_FDES), 5)
        self.assertEqual(m.LOCK70_FDES[0], (0x5F44C80, 0x5F44D56))
        self.assertEqual(m.LOCK70_FDES[4], (0x606A900, 0x606AA82))

    def test_fde_ranges(self):
        self.assertEqual(m.CTOR_FDE, (0x61F91B0, 0x61F9277))
        self.assertEqual(m.CLONE_FDE, (0x61F9400, 0x61F963E))
        self.assertEqual(m.DISPOSE_FDE, (0x61F8760, 0x61F89DB))
        self.assertEqual(m.ADD_LIBRARY_FDE, (0x61F8DC0, 0x61F913D))
        self.assertEqual(m.TTL_REGISTER_FDE, (0x62069F0, 0x6206D29))
        self.assertEqual(m.BIG_METHOD_FDE, (0x5FF88C0, 0x5FF9C50))
        self.assertEqual(m.DESTROY_HELPER_FDE, (0x60D5170, 0x60D5200))
        self.assertEqual(m.GETTER_FDE, (0x61F92B0, 0x61F93C5))

    def test_getter_callers_and_init_sites(self):
        self.assertEqual(m.GETTER_CALLERS,
                         (0x5FF88FC, 0x61F9420, 0x6206A3D))
        self.assertEqual(len(m.INIT_SITES), 4)
        self.assertEqual(m.INIT_SITES[0], (0x5FE2A3E, 0x5FE2860))
        self.assertEqual(m.INIT_SITES[1], (0x60D50DC, 0x60D50C0))

    def test_destroy_helper_identity(self):
        self.assertEqual(m.DESTROY_HELPER, 0x60D5170)
        self.assertEqual(m.DESTROY_HELPER_FDE, (0x60D5170, 0x60D5200))
        self.assertEqual(m.DESTROY_PLT_SITE, 0x60D5189)
        self.assertEqual(m.DESTROY_HELPER_CALLERS, 74)

    def test_full_lifecycle_counts(self):
        mem = m.Memory()
        singleton, clone = m.lifecycle(mem)
        # Two registries, each ctor/clone-zeroes both mutexes: 12 zero
        # chunks per mutex pair per registry... 2 registries x 2
        # mutexes x 3 chunks = 12 zero ops on mutex offsets.
        mutex_zeros = [op for op in mem.ops if op[0] == "zero"
                       and op[2] in (m.OBJECTS_MUTEX, m.LIBRARY_MUTEX,
                                     m.OBJECTS_MUTEX + 16,
                                     m.LIBRARY_MUTEX + 16,
                                     m.OBJECTS_MUTEX + 32,
                                     m.LIBRARY_MUTEX + 32)]
        self.assertEqual(len(mutex_zeros), 12)
        self.assertEqual(singleton.libraries, [])
        # Dispose destroyed the clone's parent shared_ptr, so after
        # the lifecycle the clone no longer holds the singleton.
        self.assertIsNone(clone.parent)
        self.assertTrue(clone.disposed)


if __name__ == "__main__":
    unittest.main()
