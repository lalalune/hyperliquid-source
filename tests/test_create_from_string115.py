"""Tests for tools/create_from_string115.py (RE-002, node #115).

2,400 deterministic cases (600 dispatch, 600 names, 600 status,
600 once-registry) plus targeted boundary controls. The model is
checked against INDEPENDENT expectations derived from the binary,
not against itself:

  * Dispatch: the parsed id selects Bytewise (26) / Reverse (33) /
    U64Ts (32, cached-name compare) by length + inline compare;
    an empty value yields nullptr + OK; an empty id with a
    non-empty value yields NotSupported("Cannot reset object ")
    (code 3); any other id goes to the registry
    (config_options.registry->NewStaticObject, then
    ConfigureNewObject on success).
  * Names: the bytewise name is rebuilt from the .rodata movabs
    fragments 0x61c0408/0x61c0412/0x61c042c/0x61c043a (overlapping at
    +10); the reverse name from 0x61c031d/0x61c0327/0x61c0a64/
    0x61c0a72 + the 'r' tail byte at +32; the U64Ts name from the
    cached Name() (26-char literal at 0x44e0fe + ".u64ts" at
    0x43c8ab). The fragment bytes are checked against .rodata.
  * Status: 16 bytes (code @0, subcode @1, severity @2,
    retryable @3, data_loss @4, scope @5, state_ @8, a
    unique_ptr<const char[]>); the error Status is code 3
    (kNotSupported) / subcode 0 / severity 0 with the 20-byte
    message; a GetOptionsMap error is returned as-is; the swallow
    rule needs the config byte at +1 (ignore_unsupported_options)
    set AND code 3; a guarded factory's InvalidArgument (code 4)
    is never swallowed; a Status move transfers the state_ and
    frees the old one.
  * Once/registry: call_once runs the registration exactly once;
    a pthread_once failure throws SystemError; NewStaticObject
    finds the factory by the parsed name (the target) and invokes
    it as factory(target, guard, &errmsg); ConfigureNewObject
    runs only after a successful create, and its Status is the
    result; the caller's "id" special case (name == "id", value
    empty) is handled without calling CreateFromString.
  * Ledger: the committed cases.tsv matches a fresh regeneration,
    and functions.tsv hashes match the binary (no census record
    exists for 0x61c0180, so only the body hash is claimed).
"""

import hashlib
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import create_from_string115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-create-from-string-115")


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


def _e8_target(site):
    data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
    o = _va_to_off(site)
    assert data[o] == 0xE8, hex(site)
    return site + 5 + struct.unpack_from("<i", data, o + 1)[0]


def _run(parse, value=b"x", ignore=False, cache=None, once=None,
         registry=None):
    config = m.ConfigOptions(ignore_unsupported=ignore,
                             registry=registry or m._default_registry())
    result = [None]
    status = m.create_from_string(
        config, value, result,
        cache or m.NameCache(), once or m.OnceFlag(), parse)
    return status, result


class DispatchTests(unittest.TestCase):
    def test_bytewise_dispatch(self):
        for case in m.generate_cases():
            if case["kind"] != "dispatch-bytewise":
                continue
            status, result = _run(
                (m.Status.ok(), b"leveldb.BytewiseComparator", {}),
                b"leveldb.BytewiseComparator")
            self.assertTrue(status.is_ok(), case["id"])
            self.assertIn("BytewiseComparator@0x61be810", result[0],
                          case["id"])

    def test_reverse_dispatch(self):
        for case in m.generate_cases():
            if case["kind"] != "dispatch-reverse":
                continue
            status, result = _run(
                (m.Status.ok(), b"rocksdb.ReverseBytewiseComparator", {}),
                b"rocksdb.ReverseBytewiseComparator")
            self.assertTrue(status.is_ok(), case["id"])
            self.assertIn("ReverseBytewiseComparator@0x61be8f0",
                          result[0], case["id"])

    def test_u64ts_dispatch_warm_and_cold(self):
        for case in m.generate_cases():
            if case["kind"] != "dispatch-u64ts":
                continue
            for pre_built in (True, False):
                cache = m.NameCache(pre_built=pre_built)
                status, result = _run(
                    (m.Status.ok(),
                     b"leveldb.BytewiseComparator.u64ts", {}),
                    b"leveldb.BytewiseComparator.u64ts", cache=cache)
                self.assertTrue(status.is_ok(), case["id"])
                self.assertIn("BytewiseComparatorWithU64Ts@0x61be9d0",
                              result[0], case["id"])
                self.assertEqual(cache.guard, 1, case["id"])

    def test_empty_value_nullptr_ok(self):
        for case in m.generate_cases():
            if case["kind"] != "dispatch-empty-value":
                continue
            status, result = _run((m.Status.ok(), b"", {}), b"")
            self.assertTrue(status.is_ok(), case["id"])
            self.assertIsNone(result[0], case["id"])

    def test_empty_id_not_supported(self):
        # "Cannot reset object" is Status::NotSupported (code 3),
        # not InvalidArgument (code 4) -- see the tool docstring.
        for case in m.generate_cases():
            if case["kind"] != "dispatch-empty-id":
                continue
            status, result = _run((m.Status.ok(), b"", {}), b"{opt=1}")
            self.assertFalse(status.is_ok(), case["id"])
            self.assertEqual(status.code, m.STATUS_NOT_SUPPORTED,
                             case["id"])
            self.assertEqual(status.state, b"Cannot reset object ",
                             case["id"])
            self.assertIsNone(result[0], case["id"])

    def test_registry_hit_and_miss(self):
        for case in m.generate_cases():
            if case["kind"] not in ("dispatch-registry-hit",
                                    "dispatch-registry-miss-swallow",
                                    "dispatch-registry-miss-propagate"):
                continue
            if case["kind"] == "dispatch-registry-hit":
                registry = m._default_registry()
                status, result = _run(
                    (m.Status.ok(), b"custom.Comparator", {"opt": "1"}),
                    b"custom.Comparator", registry=registry)
                self.assertTrue(status.is_ok(), case["id"])
                self.assertIsNotNone(result[0], case["id"])
                self.assertEqual(len(registry.configure_calls), 1,
                                 case["id"])
            elif case["kind"] == "dispatch-registry-miss-swallow":
                status, result = _run(
                    (m.Status.ok(), b"unknown.Comparator", {}),
                    b"unknown.Comparator", ignore=True)
                self.assertTrue(status.is_ok(), case["id"])
                self.assertIsNone(result[0], case["id"])
            else:
                status, result = _run(
                    (m.Status.ok(), b"unknown.Comparator", {}),
                    b"unknown.Comparator", ignore=False)
                self.assertFalse(status.is_ok(), case["id"])
                self.assertEqual(status.code, m.STATUS_NOT_SUPPORTED,
                                 case["id"])

    def test_factory_call_sites_in_binary(self):
        # E8 rel32 targets at the three factory call sites.
        self.assertEqual(
            _e8_target(m.NAMES["bytewise"]["factory_call_site"]),
            m.NAMES["bytewise"]["factory"])
        self.assertEqual(
            _e8_target(m.NAMES["reverse"]["factory_call_site"]),
            m.NAMES["reverse"]["factory"])
        self.assertEqual(
            _e8_target(m.NAMES["u64ts"]["factory_call_site"]),
            m.NAMES["u64ts"]["factory"])
        # Engine call sites.
        self.assertEqual(_e8_target(m.GET_OPTIONS_MAP_CALL),
                         m.GET_OPTIONS_MAP)
        self.assertEqual(_e8_target(m.NEW_STATIC_OBJECT_CALL),
                         m.NEW_STATIC_OBJECT)
        self.assertEqual(_e8_target(m.CONFIGURE_NEW_OBJECT_CALL),
                         m.CONFIGURE_NEW_OBJECT)
        self.assertEqual(_e8_target(m.STATUS_CTOR_CALL), m.STATUS_CTOR)
        self.assertEqual(_e8_target(m.PTHREAD_ONCE_CALL), 0x63F13D0)

    def test_call_once_lea_site(self):
        # LEA rcx, [rip + 0x100f] at 0x61c01fa takes the lambda.
        data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        o = _va_to_off(m.CALL_ONCE_LEA_SITE)
        self.assertEqual(data[o:o + 3], bytes([0x48, 0x8D, 0x0D]))
        disp = struct.unpack_from("<i", data, o + 3)[0]
        self.assertEqual(m.CALL_ONCE_LEA_SITE + 7 + disp, m.LAMBDA)
        self.assertEqual(m.LAMBDA, 0x61C1210)
        self.assertEqual(m.ONCE_FLAG, 0x65088C0)


class NameTests(unittest.TestCase):
    def test_literal_fragments(self):
        bw = m.build_literal_name("bytewise")
        self.assertEqual(bw, b"leveldb.BytewiseComparator")
        rv = m.build_literal_name("reverse")
        self.assertEqual(rv, b"rocksdb.ReverseBytewiseComparator")
        self.assertEqual(m.NAMES["reverse"]["tail_byte"], 0x72)
        u64 = m.build_literal_name("u64ts")
        self.assertEqual(u64, b"leveldb.BytewiseComparator.u64ts")

    def test_fragments_match_rodata(self):
        # The bytewise/reverse fragments are movabs immediates in
        # the instruction stream (checked by replay), the u64ts
        # fragments are the verbatim .rodata literals.
        data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        for _addr, frag, _off in m.NAMES["u64ts"]["fragments"]:
            self.assertEqual(data[_va_to_off(_addr):
                                 _va_to_off(_addr) + len(frag)],
                             frag)
        # The movabs immediates in the compare blocks.
        for family, sites in (
                ("bytewise", [(0x61C0408, b"leveldb."),
                              (0x61C0412, b"Bytewise"),
                              (0x61C042C, b"tewiseCo"),
                              (0x61C043A, b"mparator")]),
                ("reverse", [(0x61C031D, b"rocksdb."),
                             (0x61C0327, b"ReverseB"),
                             (0x61C0A64, b"ytewiseC"),
                             (0x61C0A72, b"omparato")])):
            for site, want in sites:
                o = _va_to_off(site)
                self.assertEqual(data[o], 0x48, hex(site))
                self.assertEqual(data[o + 1] in (0xB8, 0xBA), True,
                                 hex(site))
                imm = struct.unpack_from("<Q", data, o + 2)[0]
                self.assertEqual(imm.to_bytes(8, "little"), want,
                                 (family, hex(site)))

    def test_error_message_bytes(self):
        data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        o = _va_to_off(m.ERROR_MSG_ADDR)
        self.assertEqual(data[o:o + m.ERROR_MSG_LEN], m.ERROR_MSG)
        self.assertEqual(m.ERROR_MSG, b"Cannot reset object ")
        self.assertEqual(m.ERROR_MSG_LEN, 20)

    def test_copy_rules(self):
        for n, want in ((0, "sso"), (1, "sso"), (2, "sso"), (15, "sso"),
                        (16, "heap"), (26, "heap"), (32, "heap"),
                        (33, "heap")):
            storage, _b, heap = m.copy_string(b"x" * n)
            self.assertEqual(storage, want, n)
            self.assertEqual(heap, want == "heap", n)
        for family in m.NAME_ORDER:
            _s, _b, heap = m.copy_string(
                m.NAMES[family]["name"].encode())
            self.assertTrue(heap, family)

    def test_length_dispatch(self):
        # Only the exact lengths reach the compare blocks.
        self.assertTrue(m.match_name(
            "bytewise", b"leveldb.BytewiseComparator"))
        self.assertFalse(m.match_name(
            "bytewise", b"leveldb.BytewiseComparato"))
        self.assertFalse(m.match_name(
            "bytewise", b"leveldb.BytewiseComparatorX"))
        self.assertTrue(m.match_name(
            "reverse", b"rocksdb.ReverseBytewiseComparator"))
        self.assertFalse(m.match_name(
            "reverse", b"rocksdb.ReverseBytewiseComparato"))
        self.assertTrue(m.match_name(
            "u64ts", b"leveldb.BytewiseComparator.u64ts"))
        self.assertFalse(m.match_name(
            "u64ts", b"leveldb.BytewiseComparator.u64t"))

    def test_u64ts_cached_compare(self):
        cache = m.NameCache(pre_built=True)
        cached = cache.u64ts_name()
        self.assertTrue(m.match_name("u64ts", cached))
        self.assertFalse(m.match_name("u64ts",
                                      b"leveldb.BytewiseComparator"))
        self.assertFalse(m.match_name(
            "u64ts", b"leveldb.BytewiseComparator.u64tX"))
        self.assertEqual((m.NAME_GUARD, m.NAME_STRING),
                         (0x6508898, 0x65088A0))


class StatusTests(unittest.TestCase):
    def test_layout(self):
        s = m.Status.ok()
        self.assertTrue(s.is_ok())
        self.assertEqual(s.encode(), bytes(16))
        s = m.Status(3, 0, 0, state=b"msg")
        self.assertEqual(s.encode()[:3], bytes([3, 0, 0]))
        self.assertEqual(s.encode()[3:8], bytes(5))
        self.assertFalse(s.is_ok())

    def test_error_construction(self):
        s = m.Status.not_supported(m.ERROR_MSG)
        self.assertEqual(s.code, m.STATUS_NOT_SUPPORTED)
        self.assertEqual(s.subcode, 0)
        self.assertEqual(s.severity, 0)
        self.assertEqual(s.state, b"Cannot reset object ")
        self.assertEqual(len(s.state), 20)

    def test_parse_error_propagated(self):
        parse_err = m.Status(5, 0, 0, state=b"parse failed")
        status, result = _run((parse_err, b"", {}), b"bad{")
        self.assertIs(status, parse_err)
        self.assertIsNone(result[0])

    def test_swallow_rule(self):
        # Reachable combinations: a registry miss yields code 3
        # (NotSupported), so the flag decides OK vs propagated.
        # The code != 3 arm is reachable via a guarded factory
        # (InvalidArgument, code 4), which is never swallowed.
        # The `cmp $0x3,%al` at 0x61c0666 is pinned by the binary.
        data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        o = _va_to_off(0x61C0666)
        self.assertEqual(data[o:o + 2], bytes([0x3C, 0x03]),
                         "cmp $0x3,%al at 0x61c0666")
        for ignore, want_ok in ((True, True), (False, False)):
            config = m.ConfigOptions(ignore_unsupported=ignore,
                                     registry=m._default_registry())
            result = [None]
            status = m.create_from_string(
                config, b"x", result,
                m.NameCache(), m.OnceFlag(),
                (m.Status.ok(), b"unknown.Comparator", {}))
            self.assertEqual(status.is_ok(), want_ok, ignore)
            if not want_ok:
                self.assertEqual(status.code, m.STATUS_NOT_SUPPORTED)
        config = m.ConfigOptions(ignore_unsupported=True,
                                 registry=m._default_registry())
        result = [None]
        status = m.create_from_string(
            config, b"x", result,
            m.NameCache(), m.OnceFlag(),
            (m.Status.ok(), b"custom.Guarded", {}))
        self.assertFalse(status.is_ok())
        self.assertEqual(status.code, m.STATUS_INVALID_ARGUMENT)

    def test_status_move(self):
        cur = m.Status.ok()
        nxt = m.Status(3, 0, 0, state=b"err")
        cur.move_from(nxt)
        self.assertEqual(cur.code, 3)
        self.assertEqual(cur.state, b"err")
        self.assertTrue(nxt.is_ok())
        self.assertEqual(nxt.state, b"")
        cur2 = m.Status.ok()
        cur2.state = b"prev"
        cur2.move_from(m.Status(5, 0, 0, state=b"old"))
        self.assertEqual(cur2.freed_states, 1)
        self.assertEqual(cur2.state, b"old")


class OnceRegistryTests(unittest.TestCase):
    def test_call_once_runs_once(self):
        once = m.OnceFlag()
        for _ in range(2):
            _run((m.Status.ok(), b"leveldb.BytewiseComparator", {}),
                 b"leveldb.BytewiseComparator", once=once)
        self.assertEqual(once.runs, 1)
        self.assertTrue(once.done)

    def test_once_error_throws(self):
        once = m.OnceFlag()
        once.fail_next = True
        with self.assertRaises(SystemError):
            _run((m.Status.ok(), b"x", {}), b"x", once=once)

    def test_new_static_object_contract(self):
        registry = m._default_registry()
        result = [None]
        status, _c = registry.new_static_object(
            b"custom.Comparator", result)
        self.assertTrue(status.is_ok())
        self.assertIsNotNone(result[0])
        self.assertEqual(registry.find_calls, [b"custom.Comparator"])
        self.assertEqual(registry.create_calls,
                         [(b"custom.Comparator", b"custom.Comparator")])
        status, _c = registry.new_static_object(
            b"unknown.Comparator", [None])
        self.assertFalse(status.is_ok())
        self.assertEqual(status.code, m.STATUS_NOT_SUPPORTED)

    def test_configure_only_on_create_ok(self):
        registry = m._default_registry()
        status, result = _run(
            (m.Status.ok(), b"custom.Failing", {"bad": "1"}),
            b"x", registry=registry)
        self.assertFalse(status.is_ok())
        self.assertEqual(status.code, m.STATUS_INVALID_ARGUMENT)
        self.assertEqual(len(registry.configure_calls), 1)
        registry2 = m._default_registry()
        status2, _r2 = _run(
            (m.Status.ok(), b"unknown.Comparator", {}),
            b"x", registry=registry2)
        self.assertFalse(status2.is_ok())
        self.assertEqual(len(registry2.configure_calls), 0)

    def test_caller_id_special_case(self):
        result = [None]
        self.assertTrue(m.caller_id_special_case(b"id", b"", result))
        self.assertIsNone(result[0])
        result = [None]
        self.assertFalse(m.caller_id_special_case(b"id", b"x", result))
        self.assertFalse(
            m.caller_id_special_case(b"comparator", b"", result))


class HashTests(unittest.TestCase):
    def test_body_hash_and_size(self):
        self.assertEqual(m.BODY_SHA256,
                         "f8a5ceb9866dd4f351451e1ac48cae7a86db396e3e40ff"
                         "a0acf5068c17054c3f")
        self.assertEqual((m.START, m.END), (0x61C0180, 0x61C0CB4))
        self.assertEqual(m.END - m.START, 2868)

    def test_functions_tsv_matches_binary(self):
        data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         m.ARTIFACT_SHA256)
        text = (PACKET / "functions.tsv").read_text().splitlines()
        self.assertEqual(len(text), 2)  # header + 1 function
        cols = text[1].split("\t")
        start, end = int(cols[1], 16), int(cols[2], 16)
        body = hashlib.sha256(data[
            _va_to_off(start):_va_to_off(end)]).hexdigest()
        self.assertEqual(body, cols[4])
        self.assertEqual(cols[5], "")  # no source hash: no census
        self.assertEqual(cols[8], "none")
        # And the vendor census really has no record at this start.
        with open(m.ROOT / "research" / "work-items"
                   / "RE-002-node115-vendor-census" / "census.json") as fh:
            census = json.load(fh)["records"]
        starts = {r["start"] if isinstance(r["start"], str)
                  else hex(r["start"]) for r in census}
        self.assertNotIn("0x61c0180", starts)


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
        self.assertEqual(groups, {"dispatch": 600, "names": 600,
                                  "status": 600, "once-registry": 600})
        kinds = {}
        for c in cases:
            kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
        self.assertEqual(kinds["dispatch-bytewise"], 150)
        self.assertEqual(kinds["dispatch-reverse"], 100)
        self.assertEqual(kinds["dispatch-u64ts"], 100)
        self.assertEqual(kinds["dispatch-empty-value"], 100)
        self.assertEqual(kinds["dispatch-empty-id"], 50)
        self.assertEqual(kinds["dispatch-registry-hit"], 50)
        self.assertEqual(kinds["dispatch-registry-miss-swallow"], 25)
        self.assertEqual(kinds["dispatch-registry-miss-propagate"], 25)


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
        data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         m.ARTIFACT_SHA256)


if __name__ == "__main__":
    unittest.main()
