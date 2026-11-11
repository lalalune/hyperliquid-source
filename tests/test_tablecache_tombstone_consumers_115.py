"""Tests for tools/tablecache_tombstone_consumers_115.py.

Every check is target-grounded: the gate order, the mask polarity,
the raise-and-refresh rule and the fragment-index arithmetic are
read off the node #115 disassembly (0x5f3d4f0, 0x5f40070), and the
max-covering rule is #3900's MaxCoveringTombstoneSeqnum contract.
Randomised checks cross-check the model against independent
brute-force references on seeded inputs.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tablecache_tombstone_consumers_115 import (
    NULL_STUB,
    CachedTombstoneState,
    Fragment,
    FragmentedTombstoneIterator,
    build_iterator,
    covering_key_index,
    table_cache_get_tombstone_gate,
    update_range_tombstone_seqnums,
)

CHECKS = []


def check(name, cond):
    CHECKS.append((name, bool(cond)))


def brute_max_covering(fragments, user_key, read_seq):
    best = 0
    for frag in fragments:
        if frag.start_key <= user_key < frag.end_key:
            for seq in frag.seqnums:
                if seq <= read_seq and seq > best:
                    best = seq
    return best


def make_fragments(rng, n=4):
    frags = []
    key = 0
    for _ in range(n):
        start = key
        end = key + rng.randint(1, 20)
        key = end + rng.randint(0, 5)
        count = rng.randint(0, 5)
        seqs = sorted(rng.sample(range(1, 200), min(count, 199)), reverse=True)
        entries = [b"e%d" % s for s in seqs]
        frags.append(Fragment(start, end, seqs, entries))
    return frags


def real_builder(fragments, read_seq):
    calls = {"n": 0}

    def build(receiver, options):
        calls["n"] += 1
        return FragmentedTombstoneIterator(fragments, read_seq)

    build.calls = calls
    return build


# --- max_covering_seqnum vs brute force (seeded) ---
rng = random.Random(20261107)
for trial in range(200):
    frags = make_fragments(rng, rng.randint(0, 5))
    read_seq = rng.randint(0, 200)
    user_key = rng.randint(0, 80)
    it = FragmentedTombstoneIterator(frags, read_seq)
    got, _, _ = it.max_covering_seqnum(user_key)
    check("brute-max trial %d" % trial,
          got == brute_max_covering(frags, user_key, read_seq))

# --- boundary: empty list, key outside all fragments ---
it = FragmentedTombstoneIterator([], 100)
check("empty list -> 0", it.max_covering_seqnum(5)[0] == 0)
frags = [Fragment(10, 20, [50, 40], [b"a", b"b"])]
it = FragmentedTombstoneIterator(frags, 100)
check("key before first fragment -> 0", it.max_covering_seqnum(5)[0] == 0)
check("key at end bound -> 0", it.max_covering_seqnum(20)[0] == 0)
check("key at start bound covers", it.max_covering_seqnum(10)[0] == 50)
# read_seq below every seqnum -> 0 (seq_ptr at range end)
it = FragmentedTombstoneIterator(frags, 30)
check("read_seq below all seqnums -> 0", it.max_covering_seqnum(15)[0] == 0)
it = FragmentedTombstoneIterator(frags, 45)
check("read_seq between seqnums picks 40",
      it.max_covering_seqnum(15)[0] == 40)
check("positioned entry is the picked seqnum's Slice",
      it.covering_key_entry() == b"b")
it = FragmentedTombstoneIterator(frags, 100)
it.max_covering_seqnum(5)
check("unpositioned iterator has no entry",
      it.covering_key_entry() is None)

# --- raise_max semantics ---
s = CachedTombstoneState(max_seqnum=10, covering_key=b"old")
check("lower max does not raise", s.raise_max(5, b"x") is False)
check("lower max leaves state", s.max_seqnum == 10 and s.covering_key == b"old"
      and s.has_covering_key is False)
check("equal max does not raise", s.raise_max(10, b"x") is False)
check("higher max raises", s.raise_max(12, b"new") is True)
check("raise stores max", s.max_seqnum == 12)
check("raise refreshes string", s.covering_key == b"new")
check("raise sets flag", s.has_covering_key is True)
s2 = CachedTombstoneState(max_seqnum=0, covering_key=None)
check("raise with null string slot still raises",
      s2.raise_max(7, b"e") is True)
check("null string slot stays null", s2.covering_key is None)
check("flag still set on null-string raise", s2.has_covering_key is True)
s3 = CachedTombstoneState(max_seqnum=0, covering_key=b"k")
s3.raise_max(9, None)
check("raise with no positioned entry keeps string",
      s3.covering_key == b"k" and s3.max_seqnum == 9)

# --- fragment-index arithmetic ---
check("index 0", covering_key_index(0x1000, 0x1000) == 0)
check("index 1", covering_key_index(0x1008, 0x1000) == 1)
check("index 5", covering_key_index(0x1028, 0x1000) == 5)
check("index 17", covering_key_index(0x1088, 0x1000) == 17)

# --- build_iterator: canonical stub vs real builder ---
check("canonical stub builds nothing",
      build_iterator(NULL_STUB, object(), None) is None)
builder = real_builder([Fragment(0, 10, [5], [b"e"])], 10)
it = build_iterator(builder, object(), None)
check("real builder builds iterator", isinstance(it, FragmentedTombstoneIterator))
check("builder called once", builder.calls["n"] == 1)

# --- Get gate matrix ---
frags = [Fragment(0, 100, [90, 80, 70], [b"e90", b"e80", b"e70"])]


def fresh_state():
    return CachedTombstoneState(max_seqnum=50, covering_key=b"old")


# state None -> no consult
check("gate: null cached slot -> no consult",
      table_cache_get_tombstone_gate(None, 10, False, real_builder(frags, 100),
                                     object(), None) == (False, False))
# skip flag set -> no consult
st = fresh_state()
check("gate: skip flag -> no consult",
      table_cache_get_tombstone_gate(st, 10, True, real_builder(frags, 100),
                                     object(), None) == (False, False))
check("gate: skip flag leaves state", st.max_seqnum == 50)
# canonical stub -> no consult
st = fresh_state()
check("gate: canonical slot -> no consult",
      table_cache_get_tombstone_gate(st, 10, False, NULL_STUB,
                                     object(), None) == (False, False))
# builder returns None -> no consult
st = fresh_state()
check("gate: null iterator -> no consult",
      table_cache_get_tombstone_gate(st, 10, False, lambda r, o: None,
                                     object(), None) == (False, False))
# consult + raise
st = fresh_state()
consulted, raised = table_cache_get_tombstone_gate(
    st, 10, False, real_builder(frags, 100), object(), None)
check("gate: consult runs", consulted is True and raised is True)
check("gate: max raised to 90", st.max_seqnum == 90)
check("gate: string refreshed to e90", st.covering_key == b"e90")
check("gate: flag set", st.has_covering_key is True)
# consult, no raise (cached max already higher)
st = CachedTombstoneState(max_seqnum=95, covering_key=b"old")
consulted, raised = table_cache_get_tombstone_gate(
    st, 10, False, real_builder(frags, 100), object(), None)
check("gate: consult runs but no raise", consulted is True and raised is False)
check("gate: no-raise leaves string", st.covering_key == b"old")
# consult, key outside fragments -> max 0 -> no raise
st = fresh_state()
consulted, raised = table_cache_get_tombstone_gate(
    st, 500, False, real_builder(frags, 100), object(), None)
check("gate: uncovered key consults but does not raise",
      consulted is True and raised is False and st.max_seqnum == 50)

# --- UpdateRangeTombstoneSeqnums loop ---
frags = [Fragment(0, 100, [90, 80], [b"e90", b"e80"])]
levels = [
    (0, CachedTombstoneState(0, b"a"), 10),
    (1, CachedTombstoneState(0, b"b"), 20),
    (2, CachedTombstoneState(0, b"c"), 30),
    (3, CachedTombstoneState(0, b"d"), 40),
]
builder = real_builder(frags, 100)
updated, built = update_range_tombstone_seqnums(levels, 0, builder,
                                                object(), None)
check("loop: all levels updated", updated == 4 and built is True)
check("loop: iterator built once", builder.calls["n"] == 1)
check("loop: every level raised to 90",
      all(s.max_seqnum == 90 for _, s, _ in levels))
check("loop: every level refreshed",
      all(s.covering_key == b"e90" for _, s, _ in levels))

# mask: bit 1 set -> level 1 skipped
levels = [
    (0, CachedTombstoneState(0, b"a"), 10),
    (1, CachedTombstoneState(0, b"b"), 20),
    (2, CachedTombstoneState(0, b"c"), 30),
]
updated, built = update_range_tombstone_seqnums(
    levels, 0b010, real_builder(frags, 100), object(), None)
check("loop: masked level skipped", updated == 2)
check("loop: skipped level untouched",
      levels[1][1].max_seqnum == 0 and levels[1][1].covering_key == b"b")
# mask all set -> nothing updated, iterator still built
levels = [(0, CachedTombstoneState(0, b"a"), 10)]
updated, built = update_range_tombstone_seqnums(
    levels, 0b1, real_builder(frags, 100), object(), None)
check("loop: all-masked -> 0 updated, iterator built",
      updated == 0 and built is True)
# canonical stub -> no build, no update
levels = [(0, CachedTombstoneState(0, b"a"), 10)]
check("loop: canonical stub -> (0, False)",
      update_range_tombstone_seqnums(levels, 0, NULL_STUB,
                                     object(), None) == (0, False))
# builder None -> no update
check("loop: null iterator -> (0, False)",
      update_range_tombstone_seqnums(levels, 0, lambda r, o: None,
                                     object(), None) == (0, False))
# empty level range -> iterator still built and released
check("loop: empty range builds iterator",
      update_range_tombstone_seqnums([], 0, real_builder(frags, 100),
                                     object(), None) == (0, True))

# --- seeded random loop cross-check vs direct reference ---
rng = random.Random(770115)
for trial in range(100):
    frags = make_fragments(rng, rng.randint(1, 4))
    read_seq = rng.randint(0, 200)
    n_levels = rng.randint(0, 5)
    mask = rng.randint(0, 31)
    levels = []
    expected = 0
    builder = real_builder(frags, read_seq)
    for lv in range(n_levels):
        key = rng.randint(0, 80)
        state = CachedTombstoneState(rng.randint(0, 150), b"s%d" % lv)
        levels.append((lv, state, key))
        if not (mask >> lv) & 1:
            want = brute_max_covering(frags, key, read_seq)
            if want > state.max_seqnum:
                expected += 1
    updated, built = update_range_tombstone_seqnums(
        levels, mask, builder, object(), None)
    check("random loop trial %d" % trial,
          updated == expected and built is True)
    check("random loop builder once %d" % trial, builder.calls["n"] == 1)


def main():
    failed = [name for name, ok in CHECKS if not ok]
    print("%d checks, %d passed, %d failed"
          % (len(CHECKS), len(CHECKS) - len(failed), len(failed)))
    for name in failed:
        print("FAIL: %s" % name)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
