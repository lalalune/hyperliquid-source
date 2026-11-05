"""Tests for tools/lazy_resolver_115.py (run directly; no pytest
on this VM).

Usage (from the repository root):
    python3 tests/test_lazy_resolver_115.py
"""

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import lazy_resolver_115 as model

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % label)


def make_slot(value, skip=False, owned=None):
    def slot(_node, out):
        out["value"] = value
        out["skip_cache"] = skip
        out["owned"] = owned
    return slot


def chain_of(winners):
    """winners maps 1-based level -> slot (None = canonical).
    Builds a chain long enough for the level, all canonical
    elsewhere, terminated by a None next at the far end."""
    top = max(winners) if winners else 1
    chain = {}
    for level in range(1, top + 2):
        nxt = level + 1 if level <= top else None
        chain[level] = {"slot24": winners.get(level),
                        "next": nxt}
    return chain


def main():
    # Fresh owner state.
    owner = model.fresh_owner(chain_head=1)
    check(owner["cb8"] == model.SENTINEL, "fresh cb8 is the sentinel")
    check(owner["c70"] == 1, "fresh c70 is the chain head")
    check(owner["c18"] == 0 and owner["c60"] == 0 and owner["c30"] == 0,
          "fresh gate fields are zero")

    # Already-resolved owner: the resolver returns at once.
    owner = {"cb8": 0x1234, "c70": 1, "c18": 0, "c60": 0, "c30": 0}
    invoked = []
    installed, freed = model.resolve(
        owner, chain_of({1: make_slot(7)}), invoked)
    check(installed is False, "resolved owner installs nothing")
    check(freed == [], "resolved owner frees nothing")
    check(invoked == [], "resolved owner invokes no slot")
    check(owner["cb8"] == 0x1234, "resolved owner cb8 unchanged")

    # Winner at each inline level 1..5.
    for level in (1, 2, 3, 4, 5):
        owner = model.fresh_owner(chain_head=1)
        invoked = []
        installed, freed = model.resolve(
            owner, chain_of({level: make_slot(0x100 + level)}), invoked)
        check(installed is True, "level %d installs" % level)
        check(owner["cb8"] == 0x100 + level,
              "level %d installs its value" % level)
        check(invoked == [level], "level %d invokes only its slot" % level)
        check(freed == [], "level %d frees nothing" % level)

    # Winner deeper in the canonical continuation: levels 6,
    # 13, 14 (last compared level), 15 (first level of the
    # recursed continuation) and 23 (its unconditional call).
    for level in (6, 13, 14, 15, 23):
        owner = model.fresh_owner(chain_head=1)
        invoked = []
        installed, freed = model.resolve(
            owner, chain_of({level: make_slot(0x200 + level)}), invoked)
        check(installed is True, "deep level %d installs" % level)
        check(owner["cb8"] == 0x200 + level,
              "deep level %d installs its value" % level)
        check(invoked == [level],
              "deep level %d invokes only its slot" % level)

    # The skip-cache bool: true means no install, but the
    # owned pointer is still freed.
    owner = model.fresh_owner(chain_head=1)
    invoked = []
    installed, freed = model.resolve(
        owner, chain_of({2: make_slot(0x55, skip=True, owned="buf")}),
        invoked)
    check(installed is False, "skip-cache installs nothing")
    check(owner["cb8"] == model.SENTINEL, "skip-cache leaves the sentinel")
    check(freed == ["buf"], "skip-cache still frees the owned pointer")
    check(invoked == [2], "skip-cache still invokes the winner")

    # Normal install frees the owned pointer too.
    owner = model.fresh_owner(chain_head=1)
    installed, freed = model.resolve(
        owner, chain_of({1: make_slot(0x77, owned="buf2")}))
    check(installed is True, "normal install installs")
    check(freed == ["buf2"], "normal install frees the owned pointer")
    check(owner["cb8"] == 0x77, "normal install stores the value")

    # No owned pointer means nothing freed.
    owner = model.fresh_owner(chain_head=1)
    installed, freed = model.resolve(owner, chain_of({1: make_slot(9)}))
    check(freed == [], "no owned pointer frees nothing")

    # Two racing resolvers: both run their slot calls (the
    # barrier inside the callbacks guarantees both passed the
    # sentinel check before either installs), exactly one
    # installs, and both free their owned pointers.
    owner = model.fresh_owner(chain_head=1)
    lock = threading.Lock()
    barrier = threading.Barrier(2)
    results = []

    def race_slot(value):
        def slot(_node, out):
            barrier.wait(timeout=10)
            out["value"] = value
            out["skip_cache"] = False
            out["owned"] = "r%d" % value
        return slot

    def race(value):
        inv = []
        res = model.resolve(
            owner, chain_of({1: race_slot(value)}), inv, lock=lock)
        results.append(res)

    threads = [threading.Thread(target=race, args=(0xA1,)),
               threading.Thread(target=race, args=(0xB2,))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(sum(1 for ok, _f in results if ok) == 1,
          "race installs exactly once")
    check(owner["cb8"] in (0xA1, 0xB2), "race installs one of the values")
    check(sorted(f for _ok, f in results for f in f) == ["r161", "r178"],
          "race frees both owned pointers")

    # A null chain head or a null link where the walk must
    # dereference it is a model error, like the binary fault.
    owner = model.fresh_owner(chain_head=None)
    try:
        model.resolve(owner, {})
        check(False, "null chain head must raise")
    except ValueError:
        check(True, "null chain head raises")
    owner = model.fresh_owner(chain_head=1)
    try:
        model.resolve(owner, {1: {"slot24": None, "next": None}})
        check(False, "null chain link must raise")
    except ValueError:
        check(True, "null chain link raises")

    # The call-site gate in 0x5f0e890.
    check(model.callsite_gate({"c18": 1, "c60": 0, "c30": 0}) is True,
          "gate runs when c18 set and no small table")
    check(model.callsite_gate({"c18": 0, "c60": 0, "c30": 0}) is False,
          "gate skips when c18 clear")
    check(model.callsite_gate({"c18": 1, "c60": 1, "c30": 1}) is False,
          "gate skips when small table installed and c30 set")
    check(model.callsite_gate({"c18": 1, "c60": 1, "c30": 0}) is True,
          "gate runs when c30 clear despite the small table")
    check(model.callsite_gate({"c18": 1, "c60": 0, "c30": 1}) is True,
          "gate runs when c60 clear despite c30 set")

    # Chain helpers.
    chain = chain_of({3: make_slot(1)})
    check(model.chain_depth_to_winner(chain, 1) == 2,
          "depth to a level-3 winner is 2")
    check(model.chain_depth_to_winner(chain_of({}), 1) is None,
          "no winner means no depth")
    check(model.winner_at_level(chain, 1, 3) == 3, "winner at level 3")
    check(model.winner_at_level(chain, 1, 1) == 1, "winner at level 1")
    check(model.winner_at_level(chain, 1, 99) is None,
          "winner past the end is None")

    # Constants pinned to the binary.
    check(model.SENTINEL == 0xFFFFFFFFFFFFFFFF, "sentinel is -1")
    check(model.SENTINEL_CONSTANT_BYTES ==
          bytes.fromhex("ffffffffffffffff0000000000000000"),
          "sentinel constant bytes")
    check(model.CANONICAL == 0x5D4B100, "canonical address")
    check(model.GOT_CANONICAL_SLOT == 0x64ED3E8, "canonical GOT slot")
    check(model.INLINE_LEVELS == 4, "four inline levels")
    check(model.CANONICAL_LEVELS == 8, "eight canonical levels")
    check(model.RESOLVER == 0x5F074E0, "resolver address")
    check(model.ONCE_HELPER == 0x5F07490, "once helper address")
    check(model.ONCE_PREDICATE == 0x5F07300, "once predicate address")
    check(model.CHAIN_LINK == 0x20, "chain link offset")
    check(model.SLOT24 == 0xC0, "slot 0xc0 offset")

    # The canonical walk on its own: it advances past the
    # entry node first, then finds the winner.
    out = {"value": 0, "skip_cache": False, "owned": None}
    invoked = []
    model.canonical_walk(chain_of({2: make_slot(0x42)}), 1, out, invoked)
    check(invoked == [2], "canonical walk finds the level-2 winner")
    check(out["value"] == 0x42, "canonical walk returns the winner value")

    print("all %d checks passed" % CHECKS[0])


if __name__ == "__main__":
    main()
