"""Tests for RE-001 member construction with probe install (0x5169250).

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_member_construct_probe.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from member_construct_probe import (
    KNOWN_98,
    FactoryObject,
    cleanup_member,
    construct_member,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def host(**over):
    h = {
        "f10": 0x1111,
        "b31": 0x01,
        "f60": 0x2222,
        "f6c": 0x12345678,
        "c58": None,
        "c60": 0x3333,
        "inner": object(),
    }
    h.update(over)
    return h


def test_default_path_no_probe_table():
    member, probe = construct_member(
        host(), {"b30": 0, "b31": 0}, lambda inner: None,
        FactoryObject("v90", KNOWN_98))
    check(probe is False, "null c58 must take the default path")
    check(member[0x28] == 0, "default path leaves +0x28 zero")
    check(member[0x50] == "v90", "default path uses +0x90 virtual")


def test_default_path_options_gate():
    for options in ({"b30": 1, "b31": 0}, {"b30": 0, "b31": 1}):
        member, probe = construct_member(
            host(c58=0x4444), options, lambda inner: None,
            FactoryObject("v90", KNOWN_98))
        check(probe is False, "options gate must force default: %r" % options)
        check(member[0x28] == 0, "default path leaves +0x28 zero")
        check(member[0x50] == "v90", "default path uses +0x90 virtual")


def test_probe_path_known_98():
    member, probe = construct_member(
        host(c58=0x4444), {"b30": 0, "b31": 0}, lambda inner: None,
        FactoryObject("v90", KNOWN_98))
    check(probe is True, "probe gate must fire")
    check(member[0x28] == 0x3333, "probe path installs host +0xc60")
    check(member[0x50] == "v90", "known +0x98 takes +0x90 virtual")


def test_probe_path_direct_98():
    member, probe = construct_member(
        host(c58=0x4444), {"b30": 0, "b31": 0}, lambda inner: None,
        FactoryObject("v90", 0x5164999))
    check(probe is True, "probe gate must fire")
    check(member[0x50] == ("direct98", 0x5164999),
          "unknown +0x98 is called directly")


def test_field_installs():
    member, _ = construct_member(
        host(), {"b30": 0, "b31": 0}, lambda inner: None,
        FactoryObject("v90", KNOWN_98))
    check(member[0x00] == 0x575B230, "main vtable address point")
    check(member[0x38] == 0x575B1F8, "+0x38 vtable address point")
    check(member[0x40] == 0x5757BE0, "+0x40 vtable address point")
    check(member[0x08] == 0 and member[0x20] == 0, "zero_init fields")
    check(member[0x30] is None, "+0x30 is host +0xc58")
    check(member[0x48] == 0x1111, "+0x48 is host +0x10")
    check(member[0x58] == 0x100, "+0x58 seed is 0x100, not 0 as in #2003")
    check(member[0x5A] == 0x00, "+0x5a is host +0x31 XOR 1")
    check(member[0x60] == 0x12345678, "+0x60 is host +0x6c")
    check(member[0x68] == 0 and member[0x6C] == 0, "zero fields")
    check(member[0x70] == 0, "+0x70 zero")
    check(member[0x78] == 0x2222, "+0x78 is host +0x60")


def test_field_installs_xor_and_zero_extension():
    member, _ = construct_member(
        host(b31=0x00, f6c=0x1FFFFFFFF), {"b30": 0, "b31": 0},
        lambda inner: None, FactoryObject("v90", KNOWN_98))
    check(member[0x5A] == 0x01, "host +0x31 0 XOR 1 is 1")
    check(member[0x60] == 0xFFFFFFFF,
          "host +0x6c is a u32 load, zero-extended")


def test_cleanup():
    freed, vtable, drained = cleanup_member({0x70: 0x9999})
    check(freed is True, "non-null +0x70 is freed")
    check(vtable == 0x57593F8, "vtable reset")
    check(drained is True, "member +0x8 drained through 0x541cab0")
    freed, _, _ = cleanup_member({0x70: None})
    check(freed is False, "null +0x70 frees nothing")


def test_packet_records():
    path = os.path.join(
        ROOT, "research/work-items/RE-001-member-construct-probe-94",
        "records.json")
    records = json.load(open(path))
    check(records["window"]["start"] == "0x5169250", "window start")
    check(records["window"]["artifact_sha256"].startswith("3b7179cd"),
          "digest bound")
    check(len(records["census"]["direct_calls"]) == 10, "ten callers")
    check(records["census"]["tail_jumps"] == [], "no tail jumps")
    check(records["census"]["relative_slots"] == [], "no RELATIVE slots")


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]


def main():
    for test in TESTS:
        test()
    print("all %d tests passed" % len(TESTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
