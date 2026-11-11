"""Tests for tools/record_write_115.py (pytest-style, runnable
with plain python3: python3 tests/test_record_write_115.py).

The 64-bit hash callee is injected as a deterministic stub;
the tests pin the fold structure, call order, seeds and the
dispatch arms end to end, not the hash body itself (the hash
is cited by contract, as in the merged packets).
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import record_write_115 as m

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % label)


def stub_hash(calls=None):
    def h(data, seed):
        if calls is not None:
            calls.append((bytes(data), seed))
        return (seed ^ len(data) ^ sum(data)) & m.MASK64
    return h


def make_found(key=b"hello", seq=7, value=b"abc", tag_type=1):
    """A well-formed found record: varint(len+8) + key +
    trailer((seq << 8) | type) + varint(len(value)) + value."""
    prefix = m.encode_varint32(len(key) + 8)
    trailer = ((seq << 8) | tag_type) & m.MASK64
    return (prefix + key + trailer.to_bytes(8, "little")
            + m.encode_varint32(len(value)) + value)


def make_virt(found=None, check=True, dispatch_code=0,
               reported_len=None, out_string=b"", direct_fold=None,
               insert_status=None, stats_log=None, once_log=None):
    virt = {}
    seen = {"find": [], "insert_args": []}

    def find_a50(slice_full):
        seen["find"].append(bytes(slice_full))
        return found
    virt["find_a50"] = find_a50
    virt["check_a10"] = lambda f, o: check
    virt["bucket_for"] = lambda s: {"rc": 0, "locked": False}
    virt["dispatch"] = lambda v, rl, o, d: (
        dispatch_code,
        vlen_of(found) if reported_len is None else reported_len,
        out_string)
    if insert_status is None:
        insert_status = bytes(16)
    def insert(args):
        seen["insert_args"].append(args)
        return insert_status
    virt["insert"] = insert
    virt["once"] = lambda: (once_log.append(1) if once_log is not None
                            else None)
    if stats_log is not None:
        virt["stats"] = lambda code: stats_log.append(code)
    virt["release_a50"] = lambda: seen.setdefault("released", []).append(1)
    virt["seen"] = seen
    return virt


def vlen_of(found):
    parsed = m.parse_key_length(found, 0)
    klen, kconsumed = parsed
    trailer_at = kconsumed + (klen - 8)
    vparsed = m.parse_key_length(found, trailer_at + 8)
    return vparsed[0]


def test_varint():
    check(m.encode_varint32(0) == b"\x00", "varint 0")
    check(m.encode_varint32(0x7F) == b"\x7f", "varint 0x7f")
    check(m.encode_varint32(0x80) == b"\x80\x01", "varint 0x80")
    check(m.encode_varint32(300) == b"\xac\x02", "varint 300")
    for v in (0, 1, 0x7F, 0x80, 300, 0x3FFF, 0x1FFFFF, 0x0FFFFFFF):
        dec = m.decode_varint32(m.encode_varint32(v), 0)
        check(dec == (v, len(m.encode_varint32(v))),
              "varint roundtrip %#x" % v)
    check(m.decode_varint32(b"\x80\x01", 0) == (0x80, 2), "decode 0x80")
    check(m.decode_varint32(b"\xff\xff\xff\xff\x7f", 0) is None
          or m.decode_varint32(b"\xff\xff\xff\xff\x7f", 0)[0] == 0x7FFFFFFFF,
          "decode max 5 bytes")
    check(m.decode_varint32(b"\x80", 0, 1) is None, "decode hits limit")
    check(m.decode_varint32(b"\xff\xff\xff\xff\xff\x01", 0) is None,
          "decode shift overflow")
    check(m.parse_key_length(b"\x05abc", 0) == (5, 1), "key len 1 byte")
    check(m.parse_key_length(b"\x80\x01abc", 0) == (0x80, 2),
          "key len varint")
    check(m.parse_key_length(b"\x80", 0) is None, "key len truncated")
    check(m.varint_len(0x80) == 2, "varint_len 0x80")
    check(m.varint_len(0x3FFF) == 2, "varint_len 0x3fff")


def test_key_build():
    built = m.build_internal_key(b"hello", 0x1234)
    check(built["inline"] is True, "short key inline")
    check(built["bytes"][:1] == b"\x0d", "key prefix varint")
    check(built["bytes"][1:6] == b"hello", "key payload")
    trailer = int.from_bytes(built["bytes"][6:14], "little")
    check(trailer == ((0x1234 << 8) | 0x16), "key trailer")
    check(built["total"] == 14, "key total")
    long_key = bytes(200)
    built2 = m.build_internal_key(long_key, 1)
    check(built2["inline"] is False, "200-byte key heap")
    check(m.build_internal_key(bytes(187), 1)["inline"] is True,
          "187-byte key inline boundary")
    check(m.build_internal_key(bytes(188), 1)["inline"] is False,
          "188-byte key heap boundary")
    built3 = m.build_internal_key(b"ab", 3, second=b"cd")
    check(built3["bytes"][1:3] == b"ab", "second slice part1")
    check(built3["bytes"][3:5] == b"cd", "second slice part2")
    trailer3 = int.from_bytes(built3["bytes"][5:13], "little")
    check(trailer3 == ((3 << 8) | 0x16), "second slice trailer")


def test_status_and_move():
    st = bytearray(b"\xff" * 16)
    m.clear_status(st)
    check(bytes(st) == b"\x00" * 6 + b"\xff\xff" + b"\x00" * 8,
          "clear preserves bytes 6..7")
    st2 = bytearray(16)
    m.write_status(st2, 1)
    check(st2[0] == 1 and st2[4:6] == b"\x00\x00"
          and st2[8:16] == b"\x00" * 8, "write not_found")
    dst = bytearray(16)
    src = bytearray(b"\x01\x00\x00\x00\x00\x00\xff\xff"
                    + (0x1234).to_bytes(8, "little"))
    dst[8:16] = (0x9999).to_bytes(8, "little")
    freed = m.move_record(dst, src)
    check(freed == 0x9999, "move frees dst old pointer")
    check(dst[0] == 1 and dst[8:16] == (0x1234).to_bytes(8, "little"),
          "move copies code and pointer")
    check(src == bytearray(b"\x00" * 6 + b"\xff\xff" + b"\x00" * 8),
          "move zeroes source except bytes 6..7")
    check(m.move_record(dst, dst) is None, "self move no-op")


def test_rwlock():
    for rc in (0, 0x10, 0x6E):
        lock = {"rc": rc, "locked": False}
        m.rwlock_wrlock(lock)
        check(lock["locked"] is True, "wrlock rc %#x" % rc)
        m.rwlock_unlock(lock)
        check(lock["locked"] is False, "unlock rc %#x" % rc)
    for rc in (1, 0x6F, 0x16):
        try:
            m.rwlock_wrlock({"rc": rc, "locked": False})
            check(False, "wrlock rc %#x must raise" % rc)
        except RuntimeError:
            check(True, "wrlock rc %#x raises" % rc)
        try:
            m.rwlock_unlock({"rc": rc, "locked": True})
            check(False, "unlock rc %#x must raise" % rc)
        except RuntimeError:
            check(True, "unlock rc %#x raises" % rc)


def test_resolve():
    out = bytearray(16)
    h = stub_hash()
    got, stored = m.resolve_value(0x1122334455667788, b"k", b"k", 1, 7,
                                  8, out, h)
    check(got == 0x1122334455667788, "resolve direct value")
    check(stored == 8 and out[:8] == (0x1122334455667788).to_bytes(8, "little"),
          "resolve direct store width 8")
    out2 = bytearray(16)
    got, stored = m.resolve_value(0x1122334455667788, b"k", b"k", 1, 7,
                                  2, out2, h)
    check(stored == 2 and out2[:2] == b"\x88\x77", "resolve width 2")
    out3 = bytearray(16)
    got, stored = m.resolve_value(0x1122334455667788, b"k", b"k", 1, 7,
                                  0, out3, h)
    check(stored == 0 and out3 == bytearray(16), "resolve width 0")
    out4 = bytearray(16)
    got, stored = m.resolve_value(0x1122334455667788, b"k", b"k", 1, 7,
                                  3, out4, h)
    check(stored == 0, "resolve width 3 no store")
    calls = []
    hh = stub_hash(calls)
    plain = stub_hash()
    got, stored = m.resolve_value(None, b"AB", b"C", 5, 9, 8,
                                  bytearray(16), hh)
    expect = (plain(b"AB", 0) ^ plain(b"C", m.SEED_VALUE)
              ^ plain(bytes([5]), m.SEED_TAG_BYTE)
              ^ plain((9).to_bytes(8, "little"), m.SEED_SHIFTED_TRAILER))
    check(got == expect, "resolve fold value")
    check([c[1] for c in calls] == [0, m.SEED_VALUE, m.SEED_TAG_BYTE,
                                    m.SEED_SHIFTED_TRAILER],
          "resolve fold seed order")


def test_validate():
    h = stub_hash()
    key = b"hello"
    value = b"abc"
    trailer = (7 << 8) | 1
    buf = (m.encode_varint32(len(key) + 8) + key
           + trailer.to_bytes(8, "little")
           + m.encode_varint32(len(value)) + value)
    shifted = (trailer >> 8).to_bytes(8, "little")
    tag = bytes([trailer & 0xFF])
    protection = (h(shifted, m.SEED_SHIFTED_TRAILER)
                  ^ h(key, 0) ^ h(value, m.SEED_VALUE)
                  ^ h(tag, m.SEED_TAG_BYTE))
    ok, msg = m.validate_record(buf, 0, protection, h)
    check(ok is True and msg is None, "validate valid record")
    ok, msg = m.validate_record(buf, 0, protection ^ 1, h)
    check(ok is False and msg == b"ProtectionInfo mismatch",
          "validate protection mismatch")
    ok, msg = m.validate_record(b"\x80", 0, protection, h)
    check(ok is False and msg == b"Unable to parse internal key length",
          "validate key parse fail")
    short = (m.encode_varint32(len(key) + 8) + key
             + trailer.to_bytes(8, "little")
             + m.encode_varint32(len(value)) + value)
    ok, msg = m.validate_record(short, 100, protection, h)
    check(ok is False and msg == b"Internal key length too short",
          "validate key too short")
    ok, msg = m.validate_record(buf[:-5], 0, protection, h)
    check(ok is False and msg == b"Internal key length too long",
          "validate key too long")
    bad_value_len = (m.encode_varint32(len(key) + 8) + key
                     + trailer.to_bytes(8, "little")
                     + b"\x02" + value)
    ok, msg = m.validate_record(bad_value_len, 0, protection, h)
    check(ok is False and msg == b"Value length too short",
          "validate value too short")
    bad_value_len2 = (m.encode_varint32(len(key) + 8) + key
                      + trailer.to_bytes(8, "little")
                      + b"\x04" + value)
    ok, msg = m.validate_record(bad_value_len2, 0, protection, h)
    check(ok is False and msg == b"Value length too long",
          "validate value too long")


def base_owner():
    return {"width": 8, "a10_capacity": 0}


def test_arm0():
    found = make_found()
    stats_log, once_log = [], []
    virt = make_virt(found=found, dispatch_code=0,
                     stats_log=stats_log, once_log=once_log)
    out = bytearray(16)
    status, events = m.record_write(out, base_owner(), b"hello", 0x1234,
                                    b"optslice12345678", 0x42, virt,
                                    hash64=stub_hash())
    check(status == "ok", "arm0 ok")
    check(out[0] == 0, "arm0 out code 0")
    check(once_log == [1], "arm0 once once")
    check(stats_log == [], "arm0 no stats call")
    check("lock" in events and "unlock" in events, "arm0 lock cycle")
    check("release_a50" in events, "arm0 release")
    check("key_build:inline" in events, "arm0 inline key")
    check(virt["seen"]["find"][0] ==
          m.build_internal_key(b"hello", 0x1234)["bytes"],
          "arm0 find gets the full built key")


def test_not_found_paths():
    out = bytearray(16)
    virt = make_virt(found=None, dispatch_code=0)
    status, events = m.record_write(out, base_owner(), b"hello", 1,
                                    b"", None, virt, hash64=stub_hash())
    check(status == "not_found" and out[0] == 1, "find none not_found")
    check("lock" not in events, "find none no lock")
    found = make_found(tag_type=2)
    virt = make_virt(found=found, dispatch_code=0)
    out = bytearray(16)
    status, _ = m.record_write(out, base_owner(), b"hello", 1, b"",
                               None, virt, hash64=stub_hash())
    check(status == "not_found", "tag 2 not_found")
    found = make_found()
    virt = make_virt(found=found, dispatch_code=0)
    virt["check_a10"] = lambda f, o: False
    out = bytearray(16)
    status, _ = m.record_write(out, base_owner(), b"hello", 1, b"",
                               None, virt, hash64=stub_hash())
    check(status == "not_found", "check_a10 false not_found")
    virt = make_virt(found=found, dispatch_code=9)
    out = bytearray(16)
    status, _ = m.record_write(out, base_owner(), b"hello", 1, b"",
                               None, virt, hash64=stub_hash())
    check(status == "not_found", "dispatch code 9 not_found")


def test_arm1_direct():
    found = make_found()
    calls = []
    h = stub_hash(calls)
    plain = stub_hash()
    stats_log, once_log = [], []
    tag = 0x1234
    options = b"optslice12345678"
    # Pick direct so the arm-1 fold equals the protection the
    # validate window needs: protection = H(shifted)^H(key)^
    # H(value)^H(tag) with the stub hash.
    trailer = (7 << 8) | 1
    shifted = (trailer >> 8).to_bytes(8, "little")
    key = b"hello"
    value = b"abc"
    protection = (plain(shifted, m.SEED_SHIFTED_TRAILER) ^ plain(key, 0)
                  ^ plain(value, m.SEED_VALUE)
                  ^ plain(bytes([1]), m.SEED_TAG_BYTE))
    fold_parts = (plain(tag.to_bytes(8, "little"), m.SEED_SHIFTED_TRAILER)
                  ^ plain(shifted, m.SEED_SHIFTED_TRAILER)
                  ^ plain(options, m.SEED_VALUE)
                  ^ plain(b"\x0dhello", m.SEED_VALUE))
    direct = protection ^ fold_parts
    virt = make_virt(found=found, dispatch_code=1,
                     stats_log=stats_log, once_log=once_log)
    out = bytearray(16)
    status, events = m.record_write(out, base_owner(), key, tag,
                                    options, direct, virt, hash64=h)
    check(status == "ok", "arm1 direct ok")
    check(out[0] == 0, "arm1 out code 0")
    check(stats_log == [0x27], "arm1 stats 0x27")
    check(once_log == [1], "arm1 once once")
    check("fold" in events and "validate" in events, "arm1 fold+validate")
    check("resolve:direct" in events, "arm1 resolve direct")
    check("grow" not in events, "arm1 no grow when lengths equal")
    # Hash call order: fold A/B/C/D then validate shifted/key/
    # value/tag.
    seeds = [c[1] for c in calls]
    check(seeds == [m.SEED_SHIFTED_TRAILER, m.SEED_SHIFTED_TRAILER,
                    m.SEED_VALUE, m.SEED_VALUE,
                    m.SEED_SHIFTED_TRAILER, 0, m.SEED_VALUE,
                    m.SEED_TAG_BYTE],
          "arm1 hash call order")
    check(calls[0][0] == tag.to_bytes(8, "little"), "fold hashes tag")
    check(calls[1][0] == shifted, "fold hashes trailer>>8")
    check(calls[2][0] == options, "fold hashes options")
    check(calls[3][0] == b"\x0dhello",
          "fold hashes the -0x150 slice (prefix + key)")


def test_arm1_grow():
    found = make_found(value=bytes(200))
    calls = []
    h = stub_hash(calls)
    stats_log, once_log = [], []
    # reported_len 3 < vlen 200; varint(200) is 2 bytes,
    # varint(3) is 1 byte, so the value shifts.
    virt = make_virt(found=found, dispatch_code=1, reported_len=3,
                     stats_log=stats_log, once_log=once_log)
    out = bytearray(16)
    status, events = m.record_write(out, base_owner(), b"hello", 1,
                                    b"optslice12345678", None, virt,
                                    hash64=h)
    check(status == "ok", "arm1 grow ok (direct none)")
    check("grow" in events and "grow_memcpy" in events,
          "arm1 grow memcpy runs")
    check("resolve:fold" in events, "arm1 grow resolve fold path")
    # The resolve fold path hashes the orig-rcx slice first
    # (user key) and the -0x150 slice second (prefix + key).
    check(calls == [(b"hello", 0),
                    (b"\x0dhello", m.SEED_VALUE),
                    (b"\x01", m.SEED_TAG_BYTE),
                    ((7).to_bytes(8, "little"),
                     m.SEED_SHIFTED_TRAILER)],
          "arm1 grow resolve fold call order")


def test_arm1_grow_no_memcpy():
    found = make_found(value=bytes(200))
    h = stub_hash()
    virt = make_virt(found=found, dispatch_code=1, reported_len=150)
    out = bytearray(16)
    status, events = m.record_write(out, base_owner(), b"hello", 1,
                                    b"optslice12345678", None, virt,
                                    hash64=h)
    check(status == "ok", "arm1 grow no-memcpy ok")
    check("grow" in events, "arm1 grow runs")
    check("grow_memcpy" not in events,
          "arm1 no memcpy when varint lengths equal")


def test_arm1_validate_fail():
    found = make_found()
    h = stub_hash()
    virt = make_virt(found=found, dispatch_code=1)
    out = bytearray(16)
    status, message, events = m.record_write(
        out, base_owner(), b"hello", 0x1234, b"optslice12345678",
        0xDEADBEEF, virt, hash64=h)
    check(status == "corruption", "arm1 validate fail corruption")
    check(message == b"ProtectionInfo mismatch", "arm1 fail message")
    check(out[0] == 2, "arm1 fail out code 2")


def test_arm2():
    found = make_found()
    h = stub_hash()
    stats_log, once_log = [], []
    virt = make_virt(found=found, dispatch_code=2, out_string=b"outstr",
                     stats_log=stats_log, once_log=once_log)
    out = bytearray(16)
    status, events = m.record_write(out, base_owner(), b"hello", 0x1234,
                                    b"optslice12345678", 0x42, virt,
                                    hash64=h)
    check(status == "ok", "arm2 ok")
    check(stats_log == [0x25], "arm2 stats 0x25")
    check(once_log == [1], "arm2 once once")
    check("fold2" in events and "insert" in events, "arm2 fold2+insert")
    args = virt["seen"]["insert_args"][0]
    check(args["type"] == 1, "arm2 insert type 1")
    check(args["flag"] == 0, "arm2 insert flag 0")
    check(args["context"] is None, "arm2 insert context null")
    check(args["counters"] is None, "arm2 insert counters null")
    check(args["part1"] == b"hello", "arm2 insert part1 key")
    check(args["part2"] == b"outstr", "arm2 insert part2 out string")
    expect_fold2 = (0x42 ^ h(b"optslice12345678", m.SEED_VALUE)
                    ^ h(b"outstr", m.SEED_VALUE))
    check(args["arg7"] == expect_fold2, "arm2 insert arg7 fold2")


def test_arm2_try_again():
    found = make_found()
    h = stub_hash()
    status_bytes = bytearray(16)
    status_bytes[0] = 13
    virt = make_virt(found=found, dispatch_code=2, out_string=b"",
                     insert_status=bytes(status_bytes))
    out = bytearray(16)
    status, events = m.record_write(out, base_owner(), b"hello", 1,
                                    b"", 0x42, virt, hash64=h)
    check(status == "try_again", "arm2 insert try_again")
    check(out[0] == 13, "arm2 out code 13")


def test_arm2_direct_none():
    found = make_found()
    h = stub_hash()
    virt = make_virt(found=found, dispatch_code=2, out_string=b"")
    out = bytearray(16)
    status, events = m.record_write(out, base_owner(), b"hello", 1,
                                    b"", None, virt, hash64=h)
    check(status == "ok", "arm2 direct none ok")
    check("fold2" not in events, "arm2 direct none no fold2")
    check(virt["seen"]["insert_args"][0]["arg7"] is None,
          "arm2 direct none insert arg7 null")


def test_heap_key():
    found = make_found(key=bytes(200))
    virt = make_virt(found=found, dispatch_code=0)
    out = bytearray(16)
    status, events = m.record_write(out, base_owner(), bytes(200), 1,
                                    b"", None, virt, hash64=stub_hash())
    check(status == "ok", "heap key arm0 ok")
    check("key_build:heap" in events, "heap key event")
    check("key_buffer_freed" in events, "heap key freed")


def main():
    test_varint()
    test_key_build()
    test_status_and_move()
    test_rwlock()
    test_resolve()
    test_validate()
    test_arm0()
    test_not_found_paths()
    test_arm1_direct()
    test_arm1_grow()
    test_arm1_grow_no_memcpy()
    test_arm1_validate_fail()
    test_arm2()
    test_arm2_try_again()
    test_arm2_direct_none()
    test_heap_key()
    print("ALL %d CHECKS PASSED" % CHECKS[0])


if __name__ == "__main__":
    main()
