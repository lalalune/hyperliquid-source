"""Tests for tools/chain_histogram_snapshot_115.py.

Every expectation is target-grounded: the constants and rules come
from research/work-items/RE-001-chain-histogram-snapshot-115/
records.json and, for the HistogramImpl rules, from open PR #3371.
Run from the repository root: python3 tests/test_chain_histogram_snapshot_115.py
"""

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from chain_histogram_snapshot_115 import (
    Arena, BOUNDARIES, ChainNode, FakeLogger, HashLinkListRep, Histogram,
    Index38, LogGate, ThreadSeed, advance_seed, bucket_index,
    generate_boundaries, mersenne_step, normalize_block_size,
    rebuild_and_report,
)

PASSED = 0
FAILED = 0


def check(name, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
    else:
        FAILED += 1
        print("FAILED:", name)


# --- size normalizer (0x605cfa0) -------------------------------------------
check("normalizer 0 -> 0x1000", normalize_block_size(0) == 0x1000)
check("normalizer 0x1000 -> 0x1000", normalize_block_size(0x1000) == 0x1000)
check("normalizer 0x1001 -> 0x1010", normalize_block_size(0x1001) == 0x1010)
check("normalizer 0x100f -> 0x1010", normalize_block_size(0x100F) == 0x1010)
check("normalizer 0x1010 -> 0x1010", normalize_block_size(0x1010) == 0x1010)
check("normalizer 0x2000 -> 0x2000", normalize_block_size(0x2000) == 0x2000)
check("normalizer 0x7fffffff -> 0x80000000",
      normalize_block_size(0x7FFFFFFF) == 0x80000000)
check("normalizer 0x80000000 -> 0x1000",
      normalize_block_size(0x80000000) == 0x1000)
check("normalizer 0x80000001 -> 0x1000",
      normalize_block_size(0x80000001) == 0x1000)
check("normalizer 0xffffffffffffffff -> 0x1000",
      normalize_block_size(0xFFFFFFFFFFFFFFFF) == 0x1000)

# --- mersenne step (0x605f340 hash) ----------------------------------------
random.seed(20261106)
for _ in range(200):
    s = random.randrange(1, 0x7FFFFFFF)
    got = mersenne_step(s)
    want = (s * 0x41A7) % 0x7FFFFFFF
    check("mersenne_step(%d)" % s, got == want or (want == 0 and got == 0x7FFFFFFF))
check("mersenne_step(1)", mersenne_step(1) == 0x41A7)
check("mersenne_step(0x7ffffffe)",
      mersenne_step(0x7FFFFFFE) == (0x7FFFFFFE * 0x41A7) % 0x7FFFFFFF
      or mersenne_step(0x7FFFFFFE) == 0x7FFFFFFF)

# --- seed advance (0x605f340 rehash) ---------------------------------------
check("advance count<=1 skips loop",
      advance_seed(12345, 0x20000000, 1) == (12345, 1))
check("advance count 0 skips loop",
      advance_seed(12345, 0x20000000, 0) == (12345, 1))
s2, n2 = advance_seed(1, 0x20000000, 12)
check("advance size in range", 2 <= n2 <= 13)
check("advance seed reaches step or cap",
      s2 >= 0x20000000 or n2 == 13)
# Determinism: same inputs, same outputs.
check("advance deterministic",
      advance_seed(1, 0x20000000, 12) == (s2, n2))
# Hand-stepped: seed 1 -> 0x41a7 (16711) < step, -> 16711*0x41a7 mod ..
v = mersenne_step(1)
check("advance first step", v == 0x41A7)

# --- bucket boundaries (#3371) ---------------------------------------------
check("boundaries first 12",
      BOUNDARIES[:12] == [1, 2, 3, 4, 6, 10, 15, 22, 34, 51, 76, 110])
check("boundaries count 109", len(BOUNDARIES) == 109)
check("boundaries last", BOUNDARIES[-1] == 13000000000000000000)
check("boundaries strictly increasing",
      all(BOUNDARIES[i] < BOUNDARIES[i + 1] for i in range(len(BOUNDARIES) - 1)))
check("generate_boundaries matches BOUNDARIES",
      generate_boundaries() == BOUNDARIES)
check("bucket_index 0 -> 0", bucket_index(0) == 0)
check("bucket_index 1 -> 0", bucket_index(1) == 0)
check("bucket_index 2 -> 1", bucket_index(2) == 1)
check("bucket_index 5 -> 4", bucket_index(5) == 4)
check("bucket_index huge -> 108", bucket_index(2 ** 64 - 1) == 108)

# --- histogram record/render (#3371) ---------------------------------------
h = Histogram()
for v in (0, 0, 0, 5):
    h.record(v)
check("hist count 4", h.count == 4)
check("hist min 0", h.min == 0)
check("hist max 5", h.max == 5)
check("hist sum 5", h.sum == 5)
check("hist bucket0 == 3", h.buckets[0] == 3)
check("hist bucket4 == 1", h.buckets[4] == 1)
rendered = h.render()
check("render Count line", "Count: 4 Average:" in rendered)
check("render Min line", "Min: 0  Median:" in rendered)
check("render Percentiles line", "Percentiles: P50:" in rendered)
check("render separator", "-" * 54 in rendered)
check("render bucket row", "[       0,       1 ]        3" in rendered)
h0 = Histogram()
check("empty render Count 0", "Count: 0 Average: 0.0000" in h0.render())
check("empty render Min 0", "Min: 0  Median: 0.0000  Max: 0" in h0.render())

# --- log gate (0x5fcef60) ---------------------------------------------------
def make_gate(level):
    seen = []
    gate = LogGate(lambda: level, lambda lv, text: seen.append((lv, text)))
    return gate, seen

g, seen = make_gate(0)
check("gate level 0 logs", g.log("x %s", "y") is True and seen == [(1, "x y")])
g, seen = make_gate(1)
check("gate level 1 logs", g.log("x") is True and seen == [(1, "x")])
g, seen = make_gate(2)
check("gate level 2 drops", g.log("x") is False and seen == [])
g, seen = make_gate(255)
check("gate level 255 drops", g.log("x") is False and seen == [])

# --- arena (0x605dd90) ------------------------------------------------------
a = Arena(0x1000, 0, 0)
check("arena normalized 0x1000", a.normalized_size == 0x1000)
check("arena two slot blocks", a.slot_blocks == 2)
check("arena two data blocks", a.data_blocks == 2)
check("arena tail consts", a.tail["const_a"] == 0x800 and a.tail["const_b"] == 0x800)
check("arena host args no counter add", a.counter_add_calls == [])
a2 = Arena(0x5000, 3, 7)
check("arena normalized 0x5000", a2.normalized_size == 0x5000)
check("arena rounded arg4", a2.tail["rounded_arg4"] == ((0x5000 - 1) // 7 + 1) * 7)
check("arena counter add recorded", a2.counter_add_calls == [(3, 0x800)])
a3 = Arena(0x1000, 0, 0x1000)
check("arena arg4 == size stays", a3.tail["rounded_arg4"] == 0x1000)

# --- thread seed (0x61c4080) ------------------------------------------------
ts = ThreadSeed(b"\x01\x02\x03\x04\x05\x06\x07\x08")
v1 = ts.pointer()
check("seed in range", 1 <= v1 <= 0x7FFFFFFF)
check("seed cached", ts.pointer() == v1)
ts2 = ThreadSeed(b"\x01\x02\x03\x04\x05\x06\x07\x08")
check("seed deterministic", ts2.pointer() == v1)
ts3 = ThreadSeed(b"\x08\x07\x06\x05\x04\x03\x02\x01")
check("seed differs by tid", ts3.pointer() != v1)
ts.store(0x41A7)
check("seed store", ts.pointer() == 0x41A7)

# --- index (0x605f290 / 0x605f340) -------------------------------------------
ts4 = ThreadSeed(b"\x00" * 8)
idx = Index38(0xC, 0x4, object(), object(), ts4)
check("index step", idx.step == 0x20000000)
check("index array A size", len(idx.array_a) == 13)
check("index array B size", len(idx.array_b) == 12)
check("index B points at A", all(b is idx.array_a for b in idx.array_b))
check("index capacity 1", idx.capacity == 1)
comp = lambda a, b: (a > b) - (a < b)
idx.insert(10, comp)
idx.insert(5, comp)
idx.insert(20, comp)
check("index chains hold keys",
      sorted(k for chain in idx.chains.values() for k in chain) == [5, 10, 20])
check("index chain ordered",
      all(chain == sorted(chain) for chain in idx.chains.values()))

# --- host end to end (0x605feb0) --------------------------------------------
def chain(*keys):
    head = None
    for k in reversed(keys):
        head = ChainNode(k, head)
    return head

logger = FakeLogger(1)
rep = HashLinkListRep(
    buckets=[chain(30, 10, 20), None, chain(7)],
    key_obj=object(), logger=logger, report_flag=1,
    size_source=lambda: 0x2000)
it, hist, text = rebuild_and_report(rep, object(), ThreadSeed(b"\x00" * 8), comp)
check("host records one value per bucket", hist.count == 3)
check("host recorded lengths", sorted(
    (i, c) for i, c in enumerate(hist.buckets) if c) ==
    [(bucket_index(0), 2), (bucket_index(3), 1)])
check("host min length 0", hist.min == 0)
check("host max length 3", hist.max == 3)
check("host rendered text", text.startswith("Count: 3 Average:"))
check("host logged once", len(logger.emitted) == 1)
check("host log format",
      logger.emitted[0][1].startswith(
          "hashLinkedList Entry distribution among buckets: "))
check("host log level 1", logger.emitted[0][0] == 1)
check("host iterator vtable", it["vtable"] == 0x64D2090)
check("host iterator index 12/4",
      it["index"].count == 12 and it["index"].divisor == 4)
check("host iterator arena size", it["arena"].normalized_size == 0x2000)

logger2 = FakeLogger(1)
rep2 = HashLinkListRep(
    buckets=[chain(1, 2)], key_obj=object(), logger=logger2,
    report_flag=0, size_source=lambda: 0x1000)
it2, hist2, text2 = rebuild_and_report(rep2, object(), ThreadSeed(b"\x00" * 8), comp)
check("host flag 0 records nothing", hist2.count == 0)
check("host flag 0 logs nothing", logger2.emitted == [])
check("host flag 0 renders nothing", text2 == "")

logger3 = FakeLogger(2)
rep3 = HashLinkListRep(
    buckets=[chain(1)], key_obj=object(), logger=logger3,
    report_flag=1, size_source=lambda: 0x1000)
it3, hist3, text3 = rebuild_and_report(rep3, object(), ThreadSeed(b"\x00" * 8), comp)
check("host logger level 2 drops", logger3.emitted == [])
check("host logger level 2 still records", hist3.count == 1)

print("PASSED %d, FAILED %d" % (PASSED, FAILED))
sys.exit(1 if FAILED else 0)
