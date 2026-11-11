"""Tests for tools/stats_version_fetch_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_stats_version_fetch_115.py

Every expectation is grounded in the packet
research/work-items/RE-001-stats-version-fetch-115/: the mode
table and the invalid-mode message, the produce dispatch rule,
the chain chase, the forward rule, the aux replace, the result
protocol, the Status builder composition, the decimal parse,
the state-init stores, the cleanup-chain layout and the
caller's both-OK gate and error-log line all come from the
excerpts and records in that packet.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stats_version_fetch_115 import (
    FORMAT_VERSION_KEY, COMPATIBLE_VERSION_KEY,
    NOT_FOUND_PREFIX, NOT_FOUND_SUFFIX, INVALID_MODE_MESSAGE,
    CALLER_LOG_FORMAT, CALLER_LOG_FILE,
    FETCH_ADDR, CALLER_ADDR, DEFAULT_PRODUCE_ADDR,
    FORWARD_PRODUCE_ADDR, CHAIN_INIT_ADDR, CHAIN_DTOR_ADDR,
    GOT_PRODUCE_E8, GOT_PRODUCE_F0,
    CANONICAL_PRODUCE_E8, CANONICAL_PRODUCE_F0,
    SLOT_E8_VTABLES, SLOT_F0_VTABLES, MAX_U64,
    OK, NOT_FOUND, INVALID_ARGUMENT,
    Status, build_status_message, not_found_message, select_key,
    produce_path, parse_u64, state_init_bytes, ProduceResult,
    apply_produce_result, apply_produce_result_with_message,
    ChainNode, chain_init, chain_destroy, call_slot_f0,
    default_produce, fetch, caller_gate, status_to_string,
    caller_log_message, caller_fetch_both,
)

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % label)


class FakeSource:
    """A test double for the produce protocol: slot_e8 is a
    callable returning a ProduceResult or the canonical
    0x5d33a90; slot_f0 is a callable or the canonical
    0x5d2d0e0; next_source is the +0x8 chain hop."""

    def __init__(self, slot_e8=CANONICAL_PRODUCE_E8,
                 slot_f0=CANONICAL_PRODUCE_F0, next_source=None,
                 bound=0):
        self.slot_e8 = slot_e8
        self.slot_f0 = slot_f0
        self.next_source = next_source
        self.bound = bound


def result(value=b"", flag=0, aux_flag=0, replacement=b""):
    return ProduceResult(flag=flag, value=value,
                         aux_flag=aux_flag, replacement=replacement)


def test_addresses_and_constants():
    check(FETCH_ADDR == 0x606E3A0, "fetch address")
    check(CALLER_ADDR == 0x5E61AD0, "caller address")
    check(DEFAULT_PRODUCE_ADDR == 0x5D33A90, "default produce")
    check(FORWARD_PRODUCE_ADDR == 0x5D2D0E0, "forward produce")
    check(CHAIN_INIT_ADDR == 0x61BD0C0, "chain init address")
    check(CHAIN_DTOR_ADDR == 0x61BD0E0, "chain dtor address")
    check(GOT_PRODUCE_E8 == 0x64ED288, "GOT slot-0xe8 entry")
    check(GOT_PRODUCE_F0 == 0x64ED070, "GOT slot-0xf0 entry")
    check(CANONICAL_PRODUCE_E8 == 0x5D33A90, "canonical e8")
    check(CANONICAL_PRODUCE_F0 == 0x5D2D0E0, "canonical f0")
    check(len(SLOT_E8_VTABLES) == 6, "six slot-0xe8 vtables")
    check(SLOT_E8_VTABLES[0] == 0x64C82C0, "first e8 vtable")
    check(SLOT_F0_VTABLES == [0x64C82C0], "one slot-0xf0 vtable")
    check(FORMAT_VERSION_KEY
          == b"__persistent_stats_format_version__", "format key")
    check(len(FORMAT_VERSION_KEY) == 35, "format key length")
    check(COMPATIBLE_VERSION_KEY
          == b"__persistent_stats_compatible_version__",
          "compatible key")
    check(len(COMPATIBLE_VERSION_KEY) == 39, "compatible length")
    check(NOT_FOUND_PREFIX == b"Persistent stats version key ",
          "not-found prefix")
    check(len(NOT_FOUND_PREFIX) == 29, "prefix length")
    check(NOT_FOUND_SUFFIX == b" not found.", "not-found suffix")
    check(len(NOT_FOUND_SUFFIX) == 11, "suffix length")
    check(INVALID_MODE_MESSAGE
          == b"Invalid stats version key type provided",
          "invalid-mode message")
    check(len(INVALID_MODE_MESSAGE) == 39, "invalid-mode length")
    check(CALLER_LOG_FILE == b"db/db_impl/db_impl_open.cc",
          "caller log file")
    check(len(CALLER_LOG_FORMAT) == 136, "caller log format length")


def test_mode_table():
    key, err = select_key(0)
    check(key == b"" and err is None, "mode 0 empty key")
    key, err = select_key(1)
    check(key == FORMAT_VERSION_KEY and err is None, "mode 1")
    key, err = select_key(2)
    check(key == COMPATIBLE_VERSION_KEY and err is None, "mode 2")
    for bad in (3, 4, 255, 0x100):
        key, err = select_key(bad)
        check(key is None, "mode %d no key" % bad)
        check(err is not None and err.code == INVALID_ARGUMENT,
              "mode %d invalid argument" % bad)
        check(err.message == INVALID_MODE_MESSAGE,
              "mode %d message" % bad)


def test_produce_path():
    check(produce_path(CANONICAL_PRODUCE_E8) == "default",
          "canonical e8 is default path")
    for other in (0x5D33A91, 0x606E3A0, 0x0):
        check(produce_path(other) == "custom",
              "slot %#x is custom path" % other)


def test_builder_composition():
    check(build_status_message(b"msg", b"") == b"msg",
          "empty second view contributes nothing")
    check(build_status_message(b"msg", b"key") == b"msg: key",
          "second view appended after ': '")
    msg = not_found_message(FORMAT_VERSION_KEY)
    check(msg == b"Persistent stats version key "
                 b"__persistent_stats_format_version__ not found.: "
                 b"__persistent_stats_format_version__",
          "mode-1 message stores the key twice")
    check(not_found_message(b"") ==
          b"Persistent stats version key  not found.",
          "mode-0 message has no append")
    check(not_found_message(COMPATIBLE_VERSION_KEY).endswith(
        b": __persistent_stats_compatible_version__"),
        "mode-2 message append")


def test_parse_u64():
    check(parse_u64(b"0") == 0, "zero")
    check(parse_u64(b"42") == 42, "plain")
    check(parse_u64(b"  123") == 123, "leading whitespace")
    check(parse_u64(b"+7") == 7, "plus sign")
    check(parse_u64(b"-1") == MAX_U64, "minus wraps like strtoull")
    check(parse_u64(b"12K") == 12 << 10, "K suffix")
    check(parse_u64(b"3M") == 3 << 20, "M suffix")
    check(parse_u64(b"2G") == 2 << 30, "G suffix")
    check(parse_u64(b"1T") == 1 << 40, "T suffix")
    check(parse_u64(b"18446744073709551615") == MAX_U64, "max u64")
    for bad in (b"", b" ", b"abc", b"K", b"+", b"-"):
        try:
            parse_u64(bad)
            check(False, "parse %r must throw" % bad)
        except ValueError:
            check(True, "parse %r throws invalid_argument" % bad)
    for bad in (b"18446744073709551616", b"18446744073709551615K",
                b"12X", b"12 ", b"1.5"):
        try:
            parse_u64(bad)
            check(False, "parse %r must throw" % bad)
        except (ValueError, OverflowError):
            check(True, "parse %r throws" % bad)


def test_state_init():
    state = state_init_bytes()
    check(len(state) == 0x90, "state is 0x90 bytes")
    check(int.from_bytes(state[0x2C:0x34], "little") == 0x101,
          "state +0x2c is 0x101")
    check(int.from_bytes(state[0x78:0x80], "little") == MAX_U64,
          "state +0x78 is -1")
    check(int.from_bytes(state[0x84:0x88], "little") == 4,
          "state +0x84 is 4")
    check(int.from_bytes(state[0x88:0x8A], "little") == 0x100,
          "state +0x88 is 0x100")
    check(state[0x00:0x2C] == bytes(0x2C), "state head is zero")
    check(state[0x34:0x78] == bytes(0x44), "state middle is zero")
    check(state[0x8A:0x90] == bytes(6), "state tail is zero")


def test_result_protocol():
    status, out = apply_produce_result(result(b"123"))
    check(status.is_ok() and out == 123, "value parses to OK")
    status, out = apply_produce_result(result(b"", flag=0))
    check(status.code == NOT_FOUND and out is None,
          "empty value is NotFound")
    status, out = apply_produce_result(result(b"123", flag=1))
    check(status.code == NOT_FOUND and out is None,
          "flag set is NotFound even with a value")
    status, out = apply_produce_result(
        result(b"stale", aux_flag=1, replacement=b"99"))
    check(status.is_ok() and out == 99,
          "aux flag replaces the value")
    status, out = apply_produce_result(
        result(b"77", aux_flag=1, replacement=b""))
    check(status.code == NOT_FOUND and out is None,
          "aux replace with an empty replacement is NotFound")
    status, out = apply_produce_result(result(b"5K"))
    check(status.is_ok() and out == 5 << 10, "suffix value parses")
    try:
        apply_produce_result(result(b"nope"))
        check(False, "unparsable value must throw")
    except ValueError:
        check(True, "unparsable value throws")
    status, out = apply_produce_result_with_message(
        result(b"", flag=1), FORMAT_VERSION_KEY)
    check(status.message == not_found_message(FORMAT_VERSION_KEY),
          "NotFound message composed for the key")


def test_chain():
    calls = []
    head = chain_init()
    check(head.callback is None and head.next is None,
          "chain starts empty")
    chain_destroy(head)
    check(calls == [], "empty chain destroys silently")

    def first(a, b):
        calls.append(("first", a, b))

    def second(a, b):
        calls.append(("second", a, b))

    head = ChainNode(first, "x", 1,
                     ChainNode(second, "y", 2))
    chain_destroy(head)
    check(calls == [("first", "x", 1), ("second", "y", 2)],
          "chain calls in order with (arg1, arg2)")


def test_forward_and_chase():
    seen = []

    def leaf():
        seen.append("leaf")
        return result(b"7")

    # The forwarder: slot 0xf0 is canonical, so the next hop's
    # slot is called with the same arguments.
    inner = FakeSource(slot_f0=leaf)
    outer = FakeSource(slot_f0=CANONICAL_PRODUCE_F0,
                       next_source=inner)
    check(call_slot_f0(outer).value == b"7", "forwarder hops once")
    check(seen == ["leaf"], "forwarder called the leaf once")

    # The chase: first non-canonical slot wins.
    seen.clear()
    hop3 = FakeSource(slot_f0=leaf)
    hop2 = FakeSource(slot_f0=CANONICAL_PRODUCE_F0,
                      next_source=hop3)
    hop1 = FakeSource(slot_f0=CANONICAL_PRODUCE_F0,
                      next_source=hop2)
    hop0 = FakeSource(slot_f0=CANONICAL_PRODUCE_F0,
                      next_source=hop1)
    check(default_produce(hop0).value == b"7",
          "chase reaches the leaf through canonical hops")
    check(seen == ["leaf"], "chase called the leaf once")

    # A custom slot at hop1 stops the chase.
    def custom():
        seen.append("custom")
        return result(b"8")

    hop1b = FakeSource(slot_f0=custom, next_source=hop3)
    hop0b = FakeSource(slot_f0=CANONICAL_PRODUCE_F0,
                       next_source=hop1b)
    check(default_produce(hop0b).value == b"8",
          "chase stops at the first custom slot")
    check(seen == ["leaf", "custom"], "only the custom slot ran")


def test_fetch_end_to_end():
    # Custom slot 0xe8: called directly with the value.
    source = FakeSource(slot_e8=lambda: result(b"1234"))
    status, out = fetch(1, source)
    check(status.is_ok() and out == 1234, "custom path fetches")
    check(status.message is None, "OK has no message")

    # Default path: the chase finds the leaf's slot 0xf0.
    leaf = FakeSource(slot_f0=lambda: result(b"55"))
    chain = FakeSource(slot_f0=CANONICAL_PRODUCE_F0,
                       next_source=leaf)
    source = FakeSource(slot_e8=CANONICAL_PRODUCE_E8,
                        next_source=chain)
    status, out = fetch(2, source)
    check(status.is_ok() and out == 55, "default path fetches")

    # Aux replace through the default path.
    leaf2 = FakeSource(
        slot_f0=lambda: result(b"old", aux_flag=1,
                               replacement=b"42"))
    chain2 = FakeSource(slot_f0=CANONICAL_PRODUCE_F0,
                        next_source=leaf2)
    source2 = FakeSource(slot_e8=CANONICAL_PRODUCE_E8,
                         next_source=chain2)
    status, out = fetch(1, source2)
    check(status.is_ok() and out == 42, "aux replace applies")

    # No value: NotFound with the composed message.
    source3 = FakeSource(slot_e8=lambda: result(b"", flag=1))
    status, out = fetch(1, source3)
    check(status.code == NOT_FOUND and out is None,
          "missing value is NotFound")
    check(status.message == not_found_message(FORMAT_VERSION_KEY),
          "missing value message")

    # Mode > 2: InvalidArgument, no produce call.
    called = []
    source4 = FakeSource(
        slot_e8=lambda: called.append(1) or result(b"1"))
    status, out = fetch(9, source4)
    check(status.code == INVALID_ARGUMENT and out is None,
          "mode 9 is InvalidArgument")
    check(called == [], "mode 9 never produces")
    check(status.message == INVALID_MODE_MESSAGE, "mode 9 message")


def test_caller():
    check(caller_gate(Status(OK), Status(OK)), "both OK proceeds")
    check(not caller_gate(Status(NOT_FOUND), Status(OK)),
          "one failure blocks")
    check(not caller_gate(Status(OK), Status(NOT_FOUND)),
          "the other failure blocks")
    check(status_to_string(Status(OK)) == b"OK", "OK string")
    check(status_to_string(Status(NOT_FOUND, 0, b"msg"))
          == b"NotFound: msg", "NotFound string")
    check(status_to_string(Status(INVALID_ARGUMENT, 0, b"m"))
          == b"InvalidArgument: m", "InvalidArgument string")
    log = caller_log_message(b"OK", b"NotFound: x")
    check(log == CALLER_LOG_FORMAT
          % (CALLER_LOG_FILE, b"OK", b"NotFound: x"),
          "log line formats")

    leaf_ok = FakeSource(slot_f0=lambda: result(b"100"))
    chain_ok = FakeSource(slot_f0=CANONICAL_PRODUCE_F0,
                          next_source=leaf_ok)
    source_ok = FakeSource(slot_e8=CANONICAL_PRODUCE_E8,
                           next_source=chain_ok)
    ok, v1, v2, log = caller_fetch_both(source_ok)
    check(ok and v1 == 100 and v2 == 100 and log is None,
          "caller fetches both versions")

    leaf_bad = FakeSource(slot_f0=lambda: result(b"", flag=1))
    chain_bad = FakeSource(slot_f0=CANONICAL_PRODUCE_F0,
                           next_source=leaf_bad)
    source_bad = FakeSource(slot_e8=CANONICAL_PRODUCE_E8,
                            next_source=chain_bad)
    ok, v1, v2, log = caller_fetch_both(source_bad)
    check(not ok and v1 is None and v2 is None,
          "caller fails when a fetch fails")
    check(log is not None and log.startswith(
        b"[db/db_impl/db_impl_open.cc:744] Recreating persistent "
        b"stats column family"), "caller logs the recreate line")
    check(b"Format key: NotFound: " in log
          and b"compatible key: NotFound: " in log,
          "caller logs both Status strings")


def main():
    test_addresses_and_constants()
    test_mode_table()
    test_produce_path()
    test_builder_composition()
    test_parse_u64()
    test_state_init()
    test_result_protocol()
    test_chain()
    test_forward_and_chase()
    test_fetch_end_to_end()
    test_caller()
    print("%d checks passed" % CHECKS[0])


if __name__ == "__main__":
    main()
