"""Tests for tools/register_builtin_comparators115.py (RE-002, node #115).

2,400 deterministic cases (600 registration sequence, 600 name builds,
600 manager dispatch, 600 name-cache) plus targeted boundary controls.
The model is checked against INDEPENDENT expectations derived from the
binary, not against itself:

  * Registration: the three blocks run in the fixed order Bytewise,
    Reverse, U64Ts; each registers (name, manager, stub) under the
    ObjectLibrary registry; a duplicate name keeps the existing entry
    (AddFactory's 0x61c0fa0 find branch); a second run adds no new
    entries.
  * Names: block 1 "leveldb.BytewiseComparator" (26) is rebuilt from
    the .rodata movdqa fragments 0x455300 + 0x453a20; block 2
    "rocksdb.ReverseBytewiseComparator" (33) from 0x452fb0 + 0x454210
    + 'r'; block 3 "leveldb.BytewiseComparator.u64ts" (32) from the
    cached Name() (26-char literal at 0x44e0fe + ".u64ts" at 0x43c8ab).
  * String copy: len 0 -> empty SSO; len 1 -> single-byte store;
    len <= 15 -> SSO inline; len > 15 -> _M_create + memcpy (heap).
    All three registered names (26/33/32) take the heap path.
  * Managers: op 0 returns the .data.rel.ro slot address (bytewise
    0x64d6ff8, reverse 0x64d7008, u64ts 0x64d7018); op 1 copies the
    functor value; any other op (2 in AddFactory, 3 for the local
    destroy, and anything else) returns 0 without writing.
  * Name cache: cold build via __cxa_guard_acquire + ostringstream
    (insert order 26-char literal, then ".u64ts") + __cxa_atexit +
    __cxa_guard_release; warm path returns the cached string with no
    acquire; acquire-returns-0 returns the other thread's value with
    no new build.
  * Return: the function returns void -- the upstream ``return 3``
    is discarded when RegisterBuiltinComparators is inlined into the
    call_once lambda (no ``mov $0x3,%eax`` anywhere in the body).
  * Ledger: the committed cases.tsv matches a fresh regeneration,
    and functions.tsv hashes match the binary + the vendor census.
"""

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import register_builtin_comparators115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-register-builtin-comparators-115")


class RegistrationTests(unittest.TestCase):
    def test_full_run_cold_and_warm(self):
        for case in m.generate_cases():
            if case["kind"] not in ("full-cold", "full-warm"):
                continue
            reg = m.Registry()
            cache = m.NameCache(pre_built=(case["kind"] == "full-warm"))
            out = m.register_builtin_comparators(reg, cache)
            self.assertEqual(
                [n for n, _mm, _s in out],
                ["leveldb.BytewiseComparator",
                 "rocksdb.ReverseBytewiseComparator",
                 "leveldb.BytewiseComparator.u64ts"], case["id"])
            self.assertEqual(reg.add_calls, 3, case["id"])
            self.assertEqual(reg.duplicates, 0, case["id"])
            self.assertEqual(cache.guard, 1, case["id"])
            self.assertTrue(cache.atexit, case["id"])

    def test_duplicate_name_kept(self):
        for case in m.generate_cases():
            if case["kind"] != "full-duplicate":
                continue
            reg = m.Registry()
            cache = m.NameCache(pre_built=True)
            m.register_builtin_comparators(reg, cache)
            before = dict(reg.entries)
            m.register_builtin_comparators(reg, cache)
            self.assertEqual(reg.entries, before, case["id"])
            self.assertEqual(reg.duplicates, 3, case["id"])

    def test_second_run_no_new_entries(self):
        for case in m.generate_cases():
            if case["kind"] != "full-second-run":
                continue
            reg = m.Registry()
            cache = m.NameCache()
            m.register_builtin_comparators(reg, cache)
            m.register_builtin_comparators(reg, cache)
            self.assertEqual(len(reg.entries), 3, case["id"])

    def test_block_order_and_sites(self):
        # AddFactory call sites and manager-destroy sites ascend in
        # the same order as the blocks.
        sites = [(m.BLOCKS[f]["add_factory_site"],
                  m.BLOCKS[f]["destroy_site"]) for f in m.BLOCK_ORDER]
        self.assertEqual(sites, [(0x61C131A, 0x61C1355),
                                 (0x61C13F8, 0x61C1433),
                                 (0x61C14D3, 0x61C150E)])
        for f in m.BLOCK_ORDER:
            spec = m.BLOCKS[f]
            self.assertLess(spec["add_factory_site"],
                            spec["destroy_site"])
        # All three AddFactory calls target 0x61c0d50.
        self.assertEqual(m.ADD_FACTORY, 0x61C0D50)

    def test_function_objects(self):
        for family in m.BLOCK_ORDER:
            func = m.FunctionObject(family)
            spec = m.BLOCKS[family]
            self.assertEqual(func.read_qword(0x00), 0, family)
            self.assertEqual(func.read_qword(0x08), 0, family)
            self.assertEqual(func.manager(), spec["manager"], family)
            self.assertEqual(func.stub(), spec["stub"], family)


class NameTests(unittest.TestCase):
    def test_literal_fragments(self):
        # Block 1: 16 + 10 = 26; block 2: 16 + 16 + 1 = 33.
        bw = m.build_literal_name("bytewise")
        self.assertEqual(bw, b"leveldb.BytewiseComparator")
        rv = m.build_literal_name("reverse")
        self.assertEqual(rv, b"rocksdb.ReverseBytewiseComparator")
        self.assertEqual(m.BLOCKS["reverse"]["tail_byte"], 0x72)

    def test_fragments_match_rodata(self):
        # The fragment bytes are the verbatim .rodata contents at
        # the movdqa source addresses.
        data = (m.ROOT / "work" / "hl-node-115.bin").read_bytes()
        for family in ("bytewise", "reverse"):
            for addr, frag, _off in m.BLOCKS[family]["fragments"]:
                self.assertEqual(data[_va_to_off(addr):
                                     _va_to_off(addr) + len(frag)],
                                 frag, family)
        for addr, frag, _off in m.BLOCKS["u64ts"]["fragments"]:
            self.assertEqual(data[_va_to_off(addr):
                                 _va_to_off(addr) + len(frag)],
                             frag)

    def test_copy_rules(self):
        for n, want in ((0, "sso"), (1, "sso"), (2, "sso"), (15, "sso"),
                        (16, "heap"), (26, "heap"), (32, "heap"),
                        (33, "heap")):
            storage, _b, heap = m.copy_string(b"x" * n)
            self.assertEqual(storage, want, n)
            self.assertEqual(heap, want == "heap", n)
        # All three registered names take the heap path.
        for family in m.BLOCK_ORDER:
            _s, _b, heap = m.copy_string(
                m.BLOCKS[family]["name"].encode())
            self.assertTrue(heap, family)


class ManagerTests(unittest.TestCase):
    def test_manager_dispatch(self):
        for family in m.BLOCK_ORDER:
            spec = m.BLOCKS[family]
            written, ret = m.manager_dispatch(family, 0, 0xBEEF, 0)
            self.assertEqual(written, spec["manager_slot"], family)
            self.assertEqual(ret, 0, family)
            written, ret = m.manager_dispatch(family, 0, 0xBEEF, 1)
            self.assertEqual(written, 0xBEEF, family)
            for op in (2, 3, 4, 7):
                written, ret = m.manager_dispatch(family, 0, 0xBEEF, op)
                self.assertIsNone(written, (family, op))
                self.assertEqual(ret, 0, (family, op))

    def test_manager_slots_distinct(self):
        slots = [m.BLOCKS[f]["manager_slot"] for f in m.BLOCK_ORDER]
        self.assertEqual(slots, [0x64D6FF8, 0x64D7008, 0x64D7018])
        managers = [m.BLOCKS[f]["manager"] for f in m.BLOCK_ORDER]
        self.assertEqual(managers, [0x61BD810, 0x61BD840, 0x61BD870])

    def test_manager_body_hashes(self):
        self.assertEqual(
            m.BLOCKS["bytewise"]["manager_body_sha256"],
            "164736ddd65a2c526c108f2e0344c812ff98589bb661a365a59ebf05fd2"
            "8165b")
        self.assertEqual(
            m.BLOCKS["reverse"]["manager_body_sha256"],
            "425a388c9d87a3732aac918124ccc6263a3e3b4e6fd7112df99dfa44926"
            "71e28")
        self.assertEqual(
            m.BLOCKS["u64ts"]["manager_body_sha256"],
            "434ddcf8ec3744d6fc8b1919b774c864067debeee5e4188ba7384775ae0"
            "f8381")

    def test_call_site_ops(self):
        # AddFactory invokes the manager with op 2; the local
        # destroy after each AddFactory uses op 3.
        self.assertEqual(m.MANAGER_ADDFACTORY_OP, 2)
        self.assertEqual(m.MANAGER_DESTROY_OP, 3)


class NameCacheTests(unittest.TestCase):
    def test_cold_build(self):
        for case in m.generate_cases():
            if case["kind"] != "cache-cold":
                continue
            cache = m.NameCache()
            name = cache.u64ts_name()
            self.assertEqual(name, b"leveldb.BytewiseComparator.u64ts",
                             case["id"])
            self.assertEqual(cache.guard, 1, case["id"])
            self.assertTrue(cache.atexit, case["id"])
            self.assertEqual(cache.builds, 1, case["id"])

    def test_warm_path(self):
        for case in m.generate_cases():
            if case["kind"] != "cache-warm":
                continue
            cache = m.NameCache(pre_built=True)
            name = cache.u64ts_name()
            self.assertEqual(name, b"leveldb.BytewiseComparator.u64ts",
                             case["id"])
            self.assertEqual(cache.acquires, 0, case["id"])
            self.assertEqual(cache.builds, 1, case["id"])

    def test_acquire_zero(self):
        for case in m.generate_cases():
            if case["kind"] != "cache-acquire-zero":
                continue
            cache = m.NameCache()
            cache.value = b"leveldb.BytewiseComparator.u64ts"
            cache.guard = 1
            name = cache.u64ts_name()
            self.assertEqual(name, b"leveldb.BytewiseComparator.u64ts",
                             case["id"])
            self.assertEqual(cache.builds, 0, case["id"])

    def test_guard_addresses(self):
        # The U64Ts name cache sits next to the U64Ts factory guard
        # in .bss (#5852): name guard 0x6508898 / string 0x65088a0.
        self.assertEqual((m.NAME_GUARD, m.NAME_STRING),
                         (0x6508898, 0x65088A0))


class HashTests(unittest.TestCase):
    def test_body_and_source_hashes(self):
        self.assertEqual(m.BODY_SHA256,
                         "260a5d53134aa84f31c151e9fcae09083038d854329ed7"
                         "ef73f411a752d24b38")
        self.assertEqual(m.SOURCE_SHA256,
                         "3d78ed4569b06ab290febf5037cb5012f61d47a1eb389"
                         "9fe6461593f293f6856")
        self.assertEqual((m.START, m.END), (0x61C1210, 0x61C1A1A))
        self.assertEqual(m.END - m.START, 2058)

    def test_functions_tsv_matches_binary_and_census(self):
        data = (m.ROOT / "work" / "hl-node-115.bin").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         m.ARTIFACT_SHA256)
        with open(m.ROOT / "research" / "work-items"
                   / "RE-002-node115-vendor-census" / "census.json") as fh:
            census = json.load(fh)["records"]
        by_start = {r["start"]: r for r in census}
        text = (PACKET / "functions.tsv").read_text().splitlines()
        self.assertEqual(len(text), 5)  # header + 4 functions
        for line in text[1:]:
            cols = line.split("\t")
            name, start, end = cols[0], int(cols[1], 16), int(cols[2], 16)
            body = hashlib.sha256(data[
                _va_to_off(start):_va_to_off(end)]).hexdigest()
            self.assertEqual(body, cols[4], name)
            if cols[8] != "none":
                rec = by_start[start]
                self.assertEqual(body, rec["target_body_sha256"], name)
                self.assertEqual(cols[5], rec["source_body_sha256"], name)
                self.assertEqual(len(rec["relocations"]), 79, name)
            else:
                # No-census manager: no source hash claimed.
                self.assertEqual(cols[5], "", name)
                family = {"manager-bytewise115": "bytewise",
                          "manager-reverse115": "reverse",
                          "manager-u64ts115": "u64ts"}[cols[11][:-4]]
                self.assertEqual(
                    body, m.BLOCKS[family]["manager_body_sha256"], name)


class ReplayTests(unittest.TestCase):
    def test_all_cases_replay_to_expected_outcome(self):
        for case in m.generate_cases():
            _events, outcome = m.replay_case(case)
            self.assertEqual(outcome, m.expected_outcome(case), case["id"])

    def test_case_count_and_split(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), 2400)
        groups = {}
        for c in cases:
            groups[c["group"]] = groups.get(c["group"], 0) + 1
        self.assertEqual(groups, {"register": 600, "names": 600,
                                  "managers": 600, "name-cache": 600})
        kinds = {}
        for c in cases:
            kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
        self.assertEqual(kinds["full-cold"], 200)
        self.assertEqual(kinds["full-warm"], 200)
        self.assertEqual(kinds["full-duplicate"], 100)
        self.assertEqual(kinds["full-second-run"], 100)
        self.assertEqual(kinds["mgr-op0"], 150)
        self.assertEqual(kinds["mgr-op1"], 150)


class LedgerTests(unittest.TestCase):
    def test_cases_tsv_matches_regeneration(self):
        rows = m.cases_tsv_rows()
        text = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(text[0], "id\tkind\tdetail\texpected_outcome"
                         "\tgroup")
        self.assertEqual(len(text) - 1, 2400)
        regen = ["\t".join(str(x) for x in r) for r in rows]
        self.assertEqual(text[1:], regen)

    def test_artifact_digest(self):
        data = (m.ROOT / "work" / "hl-node-115.bin").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         m.ARTIFACT_SHA256)


def _va_to_off(va):
    out = subprocess.check_output(
        ["readelf", "-lW", str(m.ROOT / "work" / "hl-node-115.bin")]
    ).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


if __name__ == "__main__":
    unittest.main()
