"""Tests for tools/shard_member_access.py (RE-001, node #94 0x516a390).

pytest-style, with a plain-python3 __main__ runner because pytest
is not installed on this VM.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from shard_member_access import (  # noqa: E402
    Host, Member, Opts58, Shard, access, bucket_index, cpuid_index,
    minstd_rand, seed_rng,
)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_cpuid_index():
    check(cpuid_index(0, 0xFF000000) == -1, "no-leaf must be -1")
    check(cpuid_index(1, 0x01000000) == 1, "EBX top byte 1")
    check(cpuid_index(1, 0xFF000000) == 255, "EBX top byte 255")
    check(cpuid_index(1, 0x00ABCDEF) == 0, "low bytes ignored")


def test_seed_rng():
    check(seed_rng(lambda b, n, s: 0, b"x") == 1, "zero hash -> 1")
    check(seed_rng(lambda b, n, s: 0xFFFFFFFF, b"x") == 0x7FFFFFFF,
          "hash masked to 31 bits")
    check(seed_rng(lambda b, n, s: 0x12345678, b"x") == 0x12345678,
          "hash kept when nonzero")


def test_minstd_rand():
    check(minstd_rand(1) == 16807, "minstd 1 -> 16807")
    check(minstd_rand(2) == 33614, "minstd 2 -> 33614")
    check(minstd_rand(7) == 117649, "minstd 7 -> 117649")
    for state in (1, 2, 7, 12345, 999999937, 2147483646):
        check(minstd_rand(state) == (state * 16807) % (2 ** 31 - 1),
              "minstd must equal big-int mod for %d" % state)
    check(minstd_rand(0x7FFFFFFF) == 0x7FFFFFFF,
          "literal reduction fixed point at the modulus")


def test_bucket_index():
    check(bucket_index(0x1FF, 4) == 15, "mask 4 bits")
    check(bucket_index(0x1FF, 0) == 0, "shift 0 -> bucket 0")
    check(bucket_index(7, 10) == 7, "small seed unchanged")


def _host(buckets, shift=4):
    return Host(buckets, shift, Member("gm8", "gm20"), "h8")


def test_global_path():
    host = _host([Shard()])
    wrapper, rng, log = access(host, Opts58(9), "a3", True,
                               (1, 0), 1, lambda: None)
    check(wrapper["kind"] == "global", "global kind")
    check(wrapper["member"].f8 == "gm8", "global member from +0xce0")
    check(wrapper["shared_ptr_held"] is False, "no shared_ptr held")
    check(wrapper["view80"].second == 9, "global view80 raw opts58")
    check(wrapper["view88"] == ("gm8", "gm20"), "global view88")
    check(wrapper["view98"] == ("gm8", "gm20"), "global view98 dup")
    check(wrapper["viewa0"] == "gm20", "global viewa0")
    check(log == ["path:global"], "global log")


def test_shard_fast_path():
    member = Member("m8", "m20")
    shard = Shard(member, installed=True)
    host = _host([shard] + [Shard() for _ in range(15)])
    calls = []
    wrapper, rng, log = access(host, Opts58(9), "a3", False,
                               (1, 0x00000000), 1,
                               lambda: calls.append(1))
    check(calls == [], "fast path must not build")
    check(log[0] == "index:cpuid" and log[1] == "bucket:0"
          and "path:fast" in log, "fast path log")
    check(wrapper["kind"] == "shard", "shard kind")
    check(wrapper["member"] is member, "wrapper member is shard member")
    check(wrapper["shared_ptr_held"] is True, "wrapper holds shared_ptr")
    check(wrapper["view80"][0].second == 9, "shard view80 opts58 kept")
    check(wrapper["view80"][1] == "m8", "shard view80 member +0x8")
    check(wrapper["view90"] == ("m20", "m8"), "shard view90")
    check(wrapper["viewa0"] == "m20", "shard viewa0")
    check(shard.refcount == 2, "load bump + wrapper bump - caller release")


def test_lazy_install_once():
    shard = Shard()
    host = _host([shard] + [Shard() for _ in range(15)])
    built = []

    def build():
        member = Member("n8", "n20")
        built.append(member)
        return member

    wrapper, _, log = access(host, None, "a3", False, (1, 0), 1, build)
    check(len(built) == 1, "builder called once")
    check(shard.installed is True, "flag set after install")
    check("install:built" in log and "install:flag-set" in log,
          "install log")
    wrapper2, _, _ = access(host, None, "a3", False, (1, 0), 1,
                            lambda: built.append(Member("x", "y")) or
                            built[-1])
    check(len(built) == 1, "second access takes the fast path")
    check(wrapper2["member"] is shard.member, "same member reused")


def test_random_fallback_index():
    shards = [Shard() for _ in range(16)]
    host = _host(shards)
    wrapper, rng, log = access(host, None, "a3", False, (0, 0), 1,
                               lambda: Member("r8", "r20"))
    check(log[0] == "index:random", "negative seed takes random path")
    check(rng == 16807, "rng advanced by minstd")
    check(log[1] == "bucket:7", "16807 & 15 == 7")
    check(wrapper["member"].f8 == "r8", "random bucket member built")


def test_recheck_hit_skips_build():
    member = Member("e8", "e20")
    shard = Shard(member, installed=False)
    host = _host([shard] + [Shard() for _ in range(15)])
    built = []
    wrapper, _, log = access(host, None, "a3", False, (1, 0), 1,
                             lambda: built.append(1))
    check(built == [], "recheck hit must not build")
    check(shard.installed is False, "flag not set on recheck hit")
    check("recheck:already-installed" in log, "recheck log")
    check(wrapper["member"] is member, "existing member wrapped")


def test_lock_failure():
    shard = Shard(lock_fail=True)
    host = _host([shard] + [Shard() for _ in range(15)])
    built = []
    try:
        access(host, None, "a3", False, (1, 0), 1,
               lambda: built.append(1))
    except SystemError:
        pass
    else:
        raise AssertionError("lock failure must raise")
    check(built == [], "no build on lock failure")
    check(shard.installed is False, "flag stays clear")


def test_opts58_nulling():
    host = _host([Shard(Member("m8", "m20"), installed=True)]
                 + [Shard() for _ in range(15)])
    wrapper, _, _ = access(host, Opts58(0), "a3", False, (1, 0), 1,
                           lambda: None)
    check(wrapper["view80"][0] is None, "zero-second opts58 nulled")
    wrapper, _, _ = access(host, Opts58(5), "a3", False, (1, 0), 1,
                           lambda: None)
    check(wrapper["view80"][0].second == 5, "nonzero-second kept")


def test_packet_checks():
    packet = os.path.join(ROOT, "research", "work-items",
                          "RE-001-shard-member-access-94")
    for name in ("README.md", "records.json", "window.txt",
                 "thunk.txt", "index_helpers.txt", "rng_state.txt",
                 "zero_init.txt", "wrapper_global.txt",
                 "wrapper_shard.txt", "frames.txt", "relocations.txt",
                 "census.py", "export_excerpts.py", "verify.py"):
        check(os.path.exists(os.path.join(packet, name)),
              "packet file missing: %s" % name)
    records = json.load(open(os.path.join(packet, "records.json")))
    check(records["window"]["artifact_sha256"] ==
          "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f",
          "records digest")
    check(records["census"]["direct_calls"] == ["0x516da31"],
          "records census calls")
    check(records["census"]["tail_jumps"] == ["0x516aa38"],
          "records census tails")


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]


def main():
    for test in TESTS:
        test()
        print("ok", test.__name__)
    print("ALL %d TESTS PASSED" % len(TESTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
