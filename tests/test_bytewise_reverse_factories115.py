"""Tests for tools/bytewise_reverse_factories115.py (RE-002, node #115).

2,400 deterministic cases (800 bytewise-factory + 800 reverse-factory
state machine, 800 vtable/name/layout) plus targeted boundary controls.
The model is checked against INDEPENDENT expectations derived from the
binary, not against itself:

  * First call: guard 0 -> acquire -> operator new(0x30) -> the object
    is built in the binary's store order (+0x08/+0x10/+0x18/+0x28
    zeroed, primary vptr at +0x00, secondary vptr at +0x20) -> the
    instance slot is stored -> guard released -> the same pointer is
    returned.
  * Repeat call: the guard fast path returns the same pointer with no
    second allocation.
  * Stub call: the 9-byte forwarder tail-jumps to the factory body, so
    a stub call constructs (first time) or returns the same pointer.
  * Acquire-returns-0: another thread initialized meanwhile; the
    existing instance is returned with no new allocation.
  * Alloc failure: the landing pad runs __cxa_guard_abort and
    _Unwind_Resume; the guard stays 0, the instance stays None, and a
    later call retries construction successfully.
  * Never destroyed: STATIC_AVOID_DESTRUCTION registers no __cxa_atexit
    anywhere in either body, so the singleton is intentionally leaked.
  * Vtable slots: Name at +0x70 returns the class name
    ("leveldb.BytewiseComparator" / "rocksdb.ReverseBytewiseComparator");
    Compare/CompareWithoutTimestamp/EqualWithoutTimestamp and the
    separator slots match the readelf RELATIVE addends and the #5844
    packet; secondary vtables hold thunk D1/D0 + the Compare copy 2
    with offset-to-top -32.
  * Shared source: both 184-byte bodies reproduce the SAME census
    source hash (55ccba1f...); the body hashes differ (different guard
    / instance / vtable relocation targets). Both stubs are
    byte-identical (same body hash bcc59137...): each sits exactly
    0xc9 bytes past its factory's start, so both jmp displacements
    are -0xc9.
  * Ledger: the committed cases.tsv matches a fresh regeneration, and
    functions.tsv hashes match the binary + the vendor census.
"""

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import bytewise_reverse_factories115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-bytewise-reverse-factories-115")


class FirstCallTests(unittest.TestCase):
    def test_first_call_constructs(self):
        for case in m.generate_cases():
            if case["kind"] != "first-call":
                continue
            f = m.make_factory(case["family"])
            obj = f.call()
            spec = m.FACTORIES[case["family"]]
            self.assertEqual(f.guard, 1, case["id"])
            self.assertEqual(f.allocations, 1, case["id"])
            self.assertIs(obj, f.instance, case["id"])
            self.assertEqual(obj.primary_vptr(), spec["primary_vptr"],
                             case["id"])
            self.assertEqual(obj.secondary_vptr(),
                             spec["secondary_vptr"], case["id"])
            self.assertEqual(obj.secondary_vptr(),
                             obj.primary_vptr() + 0xF8, case["id"])
            for off in m.ZERO_OFFSETS:
                self.assertEqual(obj.read_qword(off), 0, case["id"])
            # STATIC_AVOID_DESTRUCTION: never destroyed.
            self.assertFalse(obj.destroyed, case["id"])

    def test_object_size_and_store_order(self):
        # The 0x30-byte object: vptrs at +0x00/+0x20, zeros at
        # +0x08/+0x10/+0x18/+0x28 -- the binary's exact store order is
        # zeros first, then the vptrs (see the tool docstring).
        for family in ("bytewise", "reverse"):
            obj = m.ComparatorObject(family)
            self.assertEqual(len(obj.mem), 0x30, family)
            self.assertEqual(obj.read_qword(0x00),
                             m.FACTORIES[family]["primary_vptr"], family)
            self.assertEqual(obj.read_qword(0x20),
                             m.FACTORIES[family]["secondary_vptr"], family)


class RepeatCallTests(unittest.TestCase):
    def test_repeat_call_same_pointer(self):
        for case in m.generate_cases():
            if case["kind"] != "repeat-call":
                continue
            f = m.make_factory(case["family"])
            first = f.call()
            for _ in range(3):
                self.assertIs(f.call(), first, case["id"])
            self.assertEqual(f.allocations, 1, case["id"])
            self.assertEqual(f.acquires, 1, case["id"])

    def test_stub_call_identical(self):
        for case in m.generate_cases():
            if case["kind"] != "stub-call":
                continue
            f = m.make_factory(case["family"])
            via_stub = f.call_via_stub()
            direct = f.call()
            self.assertIs(via_stub, direct, case["id"])
            self.assertEqual(f.allocations, 1, case["id"])


class AcquireZeroTests(unittest.TestCase):
    def test_acquire_returns_zero(self):
        for case in m.generate_cases():
            if case["kind"] != "acquire-zero":
                continue
            f = m.make_factory(case["family"], pre_initialized=True)
            obj = f.call()
            self.assertIs(obj, f.instance, case["id"])
            # No new allocation: the other thread already built it.
            self.assertEqual(f.allocations, 1, case["id"])


class AllocFailTests(unittest.TestCase):
    def test_alloc_failure_aborts_then_retries(self):
        for case in m.generate_cases():
            if case["kind"] != "alloc-fail":
                continue
            f = m.make_factory(case["family"], fail_alloc=True)
            with self.assertRaises(m.GuardAbort, msg=case["id"]):
                f.call()
            self.assertEqual(f.guard, 0, case["id"])
            self.assertIsNone(f.instance, case["id"])
            self.assertEqual(f.allocations, 0, case["id"])
            f.fail_alloc = False
            obj = f.call()
            self.assertEqual(f.guard, 1, case["id"])
            self.assertIs(obj, f.instance, case["id"])


class VtableTests(unittest.TestCase):
    def test_name_slots(self):
        for case in m.generate_cases():
            if case["kind"] != "name-slot":
                continue
            f = m.make_factory(case["family"])
            obj = f.call()
            self.assertEqual(obj.name(), case["detail"], case["id"])
        self.assertEqual(
            m.ComparatorObject("bytewise").name(),
            "leveldb.BytewiseComparator")
        self.assertEqual(
            m.ComparatorObject("reverse").name(),
            "rocksdb.ReverseBytewiseComparator")

    def test_primary_vtable_slots(self):
        # Verified readelf -r RELATIVE addends; Compare slots agree
        # with the #5844 packet.
        bw = m.PRIMARY_SLOTS["bytewise"]
        self.assertEqual(bw[0x70], 0x61BD720)
        self.assertEqual(bw[0xE0], 0x61BDBF0)
        self.assertEqual(bw[0xD0], 0x61BDC40)
        self.assertEqual(bw[0x98], 0x61BD950)
        self.assertEqual(bw[0xA0], 0x61BD9E0)
        self.assertEqual(bw[0xA8], 0x61BD990)
        self.assertEqual(bw[0xB0], 0x61BD730)
        self.assertEqual(bw[0xB8], 0x61BD7D0)
        rv = m.PRIMARY_SLOTS["reverse"]
        self.assertEqual(rv[0x70], 0x61BD7E0)
        self.assertEqual(rv[0xE0], 0x61BDCF0)
        self.assertEqual(rv[0xD0], 0x61BDC90)
        self.assertEqual(rv[0x98], 0x61BD950)  # shared
        self.assertEqual(rv[0xA0], 0x61BDAB0)
        self.assertEqual(rv[0xA8], 0x61BD7F0)  # no-op successor
        self.assertEqual(rv[0xB0], 0x61BD800)  # always false
        self.assertEqual(rv[0xB8], 0x61BD7D0)  # shared
        # The two primaries share the base-class slots.
        for off in (0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48,
                    0x50, 0x58, 0x60, 0x68, 0x78, 0x80, 0x88, 0x90,
                    0x98, 0xB8, 0xC0, 0xC8, 0xD8):
            self.assertEqual(bw[off], rv[off], hex(off))
        self.assertEqual(len(bw), 29)
        self.assertEqual(len(rv), 29)

    def test_secondary_vtable_slots(self):
        for family in ("bytewise", "reverse"):
            slots = m.SECONDARY_SLOTS[family]
            self.assertEqual(len(slots), 3, family)
            self.assertEqual(m.SECONDARY_OFFSET_TO_TOP, -32, family)
            spec = m.FACTORIES[family]
            self.assertEqual(spec["secondary_vptr"],
                             spec["primary_vptr"] + 0xF8, family)
        self.assertEqual(m.SECONDARY_SLOTS["bytewise"][0x10], 0x61BDD50)
        self.assertEqual(m.SECONDARY_SLOTS["reverse"][0x10], 0x61BDDA0)

    def test_guard_instance_addresses_distinct(self):
        # The three comparator singletons sit adjacent in .bss: U64Ts
        # guard 0x65088c8 / instance 0x65088d0 (#5852), then reverse
        # guard 0x65088d8 / instance 0x65088e0, then bytewise guard
        # 0x65088e8 / instance 0x65088f0.
        bw = m.FACTORIES["bytewise"]
        rv = m.FACTORIES["reverse"]
        self.assertEqual((rv["guard"], rv["instance"]),
                         (0x65088D8, 0x65088E0))
        self.assertEqual((bw["guard"], bw["instance"]),
                         (0x65088E8, 0x65088F0))
        self.assertEqual(bw["guard"], rv["instance"] + 8)


class HashTests(unittest.TestCase):
    def test_shared_source_hash(self):
        self.assertEqual(m.SHARED_SOURCE_SHA256,
                         "55ccba1f251d91c8f0e4d144ba8ca8384beb212d0ab04e4e828c34761337069c")
        bw = m.FACTORIES["bytewise"]["body_sha256"]
        rv = m.FACTORIES["reverse"]["body_sha256"]
        self.assertNotEqual(bw, rv)
        self.assertEqual(bw, "4d3d060f00bf927dd0d7e9f0fb21a0e1798c54fb"
                         "4a514f504d529c430a136264")
        self.assertEqual(rv, "322fd2cf015ca9435663e3a73d93009727c2b0714"
                         "ef556bd06dfb73c6d34dd05")

    def test_functions_tsv_matches_binary_and_census(self):
        data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
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
            else:
                # No-census stub: no source hash claimed.
                self.assertEqual(cols[5], "", name)
                self.assertEqual(body, m.STUB_BODY_SHA256, name)

    def test_stub_bodies_identical(self):
        # Both stubs are `endbr64; jmp rel32` with displacement -0xc9:
        # each stub ends exactly 0xc9 bytes past its factory's start.
        for family in ("bytewise", "reverse"):
            spec = m.FACTORIES[family]
            self.assertEqual(spec["stub_start"] + 9 - spec["start"], 0xC9,
                             family)


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
        self.assertEqual(groups, {"factory": 1600, "vtable": 800})
        kinds = {}
        for c in cases:
            kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
        self.assertEqual(kinds["first-call"], 600)
        self.assertEqual(kinds["repeat-call"], 600)
        self.assertEqual(kinds["acquire-zero"], 200)
        self.assertEqual(kinds["alloc-fail"], 100)
        self.assertEqual(kinds["stub-call"], 100)


class LedgerTests(unittest.TestCase):
    def test_cases_tsv_matches_regeneration(self):
        rows = m.cases_tsv_rows()
        text = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(text[0], "id\tfamily\tkind\tdetail\t"
                         "expected_outcome\tgroup")
        self.assertEqual(len(text) - 1, 2400)
        regen = ["\t".join(str(x) for x in r) for r in rows]
        self.assertEqual(text[1:], regen)

    def test_artifact_digest(self):
        data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         m.ARTIFACT_SHA256)


def _va_to_off(va):
    out = subprocess.check_output(
        ["readelf", "-lW", str(m.ROOT / "artifacts" / "node" / "115" / "hl-node")]
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
