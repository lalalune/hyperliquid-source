"""Tests for tools/canonical_lea_sites_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_canonical_lea_sites_115.py

Every expectation is pinned to the node #115 bytes: the
walk depths (A 11, B 9, C 11, D 11 compared levels), the
slot-24 contract, the emulated slot-24 flag/scaled-add
behavior, the site gates, and the vtable slot tables from
the RELATIVE records.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from canonical_lea_sites_115 import (
    CANONICAL, EMULATED_SLOT24, EMULATED_SLOTS, EMULATED_VTABLE,
    ENTRY_VTABLES, SITE_DEPTHS, WRAPPER_SLOTS, WRAPPER_VTABLE,
    WRAPPER_VTABLE_HEADER, call_slot24, canonical_walk,
    emulated_slot24, entry_install, fresh_out, fresh_value,
    install_wrapper_vtable, resolver_fast_path, scaled_add,
    site_a_first_use, site_a_sum, site_b_first_use,
    site_b_gate, site_c_first_use, site_c_prologue,
    site_d_config, site_d_first_use, walk_dispatch,
)

CHECKS = []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        raise AssertionError("%s: got %r, want %r" % (name, got, want))


def stub_slot24(marker):
    """A non-canonical slot 24 that records its call."""
    def run(chain, node_id, out, value, invoked):
        invoked.append(node_id)
        out["code"] = marker
        value["value"] = marker * 100
        return out
    return run


def chain_of(length, slot_at=None):
    """An all-canonical chain of `length` nodes; slot_at maps
    an index to a slot-24 callable (None = canonical)."""
    chain = {}
    for i in range(length):
        slot = None
        if slot_at and i in slot_at:
            slot = slot_at[i]
        chain[i] = {"slot24": slot,
                    "next": i + 1 if i + 1 < length else None,
                    "flag48": False, "v30": 0, "v40": 0}
    return chain


def main():
    # --- vtable identity ---
    check("wrapper slot count", len(WRAPPER_SLOTS), 26)
    check("wrapper slot 24 is canonical", WRAPPER_SLOTS[24], CANONICAL)
    check("wrapper slots 0/1/14 null",
          (WRAPPER_SLOTS[0], WRAPPER_SLOTS[1], WRAPPER_SLOTS[14]),
          (None, None, None))
    check("emulated slot count", len(EMULATED_SLOTS), 26)
    check("emulated slot 24", EMULATED_SLOTS[24], EMULATED_SLOT24)
    check("emulated slots 0/1 installers",
          (EMULATED_SLOTS[0], EMULATED_SLOTS[1]), (0x6029110, 0x6029620))
    check("shared slots 2..13",
          WRAPPER_SLOTS[2:14], EMULATED_SLOTS[2:14])
    check("shared slot 25", WRAPPER_SLOTS[25], EMULATED_SLOTS[25])
    check("wrapper vtable base", WRAPPER_VTABLE, 0x64CDD88)
    check("wrapper header is vtable-0x10",
          WRAPPER_VTABLE_HEADER, WRAPPER_VTABLE - 0x10)
    check("emulated vtable base", EMULATED_VTABLE, 0x64D1650)
    check("entry vtables", ENTRY_VTABLES,
          [0x64CD9D0, 0x64CD9E0, 0x64CD9F0])
    check("site depths", SITE_DEPTHS,
          {"A": (11, 12), "B": (9, 10), "C": (11, 12), "D": (11, 12)})

    # --- scaled add (emulated slot 24, 0x6025f92) ---
    check("scaled 0", scaled_add(0), 0)
    check("scaled 1", scaled_add(1), 0)
    check("scaled -1", scaled_add(-1), 0)
    check("scaled 2**40", scaled_add(2 ** 40), 1099511)
    check("scaled -2**40", scaled_add(-(2 ** 40)), -1099511)
    check("scaled 2**60", scaled_add(2 ** 60), 1152921504606)
    check("scaled -2**60", scaled_add(-(2 ** 60)), -1152921504606)
    check("scaled 123456789", scaled_add(123456789), 123)

    # --- walk dispatch: all-canonical chains hit the terminal ---
    for site, (compared, _terminal) in SITE_DEPTHS.items():
        chain = chain_of(compared + 1, slot_at={compared: stub_slot24(7)})
        how, node, invoked, out, value = walk_dispatch(chain, 0, site)
        check("site %s terminal how" % site, how, "terminal")
        check("site %s terminal node" % site, node, compared)
        check("site %s terminal invoked" % site, invoked, [compared])
        check("site %s terminal value" % site, value["value"], 700)
        check("site %s terminal code" % site, out["code"], 7)

    # --- walk dispatch: mismatch at each level wins ---
    for site, (compared, _terminal) in SITE_DEPTHS.items():
        for level in (0, 1, compared // 2, compared - 1):
            chain = chain_of(compared + 1,
                             slot_at={level: stub_slot24(3)})
            how, node, invoked, out, value = walk_dispatch(chain, 0, site)
            check("site %s mismatch L%d how" % (site, level),
                  how, "mismatch")
            check("site %s mismatch L%d node" % (site, level), node, level)
            check("site %s mismatch L%d invoked" % (site, level),
                  invoked, [level])
            check("site %s mismatch L%d value" % (site, level),
                  value["value"], 300)

    # --- walk dispatch: terminal emulated slot answers directly ---
    chain = chain_of(10)
    chain[9] = {"slot24": emulated_slot24, "next": None,
                "flag48": True, "v30": 50, "v40": 2 ** 40}
    how, node, invoked, out, value = walk_dispatch(chain, 0, "B")
    check("B terminal emulated how", how, "terminal")
    check("B terminal emulated node", node, 9)
    check("B terminal emulated value", value["value"],
          50 + 1099511)
    check("B terminal emulated out", out,
          {"code": 0, "code2": 0, "ptr": 0})

    # --- walk dispatch: terminal canonical recurses (site A) ---
    # Terminal node 11 is canonical, so canonical_walk runs
    # from 11 (compares 12..19, calls 20, which is canonical
    # too and recurses: compares 21..28, calls 29).
    chain = chain_of(30)
    chain[29] = {"slot24": stub_slot24(9), "next": None,
                 "flag48": False, "v30": 0, "v40": 0}
    how, node, invoked, out, value = walk_dispatch(chain, 0, "A")
    check("A terminal canonical how", how, "terminal")
    check("A terminal canonical node", node, 11)
    check("A terminal canonical invoked",
          invoked, [("canonical", 11), ("canonical", 20), 29])
    check("A terminal canonical value", value["value"], 900)

    # --- walk dispatch: short chain faults ---
    for site in ("A", "B", "C", "D"):
        try:
            walk_dispatch(chain_of(3), 0, site)
            raise AssertionError("site %s short chain did not fault" % site)
        except ValueError:
            CHECKS.append("site %s short chain faults" % site)

    # --- canonical walk directly (#3322 shape) ---
    chain = chain_of(12, slot_at={9: stub_slot24(4)})
    out, value, invoked = fresh_out(), fresh_value(), []
    canonical_walk(chain, 0, out, value, invoked)
    check("canonical 8+1 invoked", invoked, [("canonical", 0), 9])
    check("canonical 8+1 value", value["value"], 400)
    chain = chain_of(12, slot_at={3: stub_slot24(5)})
    out, value, invoked = fresh_out(), fresh_value(), []
    canonical_walk(chain, 0, out, value, invoked)
    check("canonical early mismatch invoked", invoked,
          [("canonical", 0), 3])

    # --- emulated slot 24 ---
    chain = {0: {"slot24": emulated_slot24, "next": None,
                 "flag48": True, "v30": 11, "v40": 0}}
    out, value, invoked = fresh_out(), fresh_value(), []
    emulated_slot24(chain, 0, out, value, invoked)
    check("emulated flag set value", value["value"], 11)
    check("emulated flag set out", out, {"code": 0, "code2": 0, "ptr": 0})
    chain = {
        0: {"slot24": emulated_slot24, "next": 1,
            "flag48": False, "v30": 0, "v40": 2 ** 40},
        1: {"slot24": stub_slot24(0), "next": None,
            "flag48": False, "v30": 0, "v40": 0},
    }
    out, value, invoked = fresh_out(), fresh_value(), []
    emulated_slot24(chain, 0, out, value, invoked)
    check("emulated recurse merges then adds",
          value["value"], 0 + 1099511)
    check("emulated recurse invoked", invoked, [0, 1])
    chain[1]["slot24"] = stub_slot24(5)
    out, value, invoked = fresh_out(), fresh_value(), []
    emulated_slot24(chain, 0, out, value, invoked)
    check("emulated recurse nonzero bool skips add",
          value["value"], 500)
    check("emulated recurse nonzero code", out["code"], 5)
    try:
        emulated_slot24({0: {"slot24": emulated_slot24, "next": None,
                             "flag48": False, "v30": 0, "v40": 0}},
                        0, fresh_out(), fresh_value(), [])
        raise AssertionError("emulated past-end did not fault")
    except ValueError:
        CHECKS.append("emulated past-end faults")

    # --- site A sum ---
    check("A sum empty", site_a_sum([]), 0)
    check("A sum one", site_a_sum([5]), 5)
    check("A sum odd tail", site_a_sum([1, 2, 3]), 6)
    check("A sum wraps mod 2**64",
          site_a_sum([0xFFFFFFFFFFFFFFFF, 1]), 0)

    # --- site B gate ---
    base = {"b270": 0, "b271": 3, "x438": 9,
            "x1068": 0x100, "x1060": 0xC0, "b10e0": 0}
    check("B gate passes", site_b_gate(base), True)
    for field, bad in (("b270", 1), ("b271", 2), ("x438", 0),
                       ("b10e0", 1)):
        obj = dict(base)
        obj[field] = bad
        check("B gate fails on %s" % field, site_b_gate(obj), False)
    obj = dict(base)
    obj["x1068"] = 0xF8  # span 0x38, not above
    check("B gate fails on span", site_b_gate(obj), False)

    # --- site C prologue ---
    owner = {"c88": 7, "d18": 4, "d20": 9}
    check("C prologue syncs", site_c_prologue(owner),
          {"c88": 0, "d18": 4, "d20": 4})
    owner = {"c88": 0, "d18": 4, "d20": 4}
    check("C prologue no-op", site_c_prologue(owner),
          {"c88": 0, "d18": 4, "d20": 4})

    # --- site D config ---
    check("D config", site_d_config(),
          {"neg68": 1, "neg60": 0, "neg58": 0, "neg50": 0x3F800000,
           "neg48": 0, "neg40": 0})

    # --- post-dispatch first uses ---
    check("A first use bool", site_a_first_use(1, 99, {"x38": 0}),
          "alt-0x5dca750")
    check("A first use x38", site_a_first_use(0, 99, {"x38": 5}),
          "alt-0x5dca6f8")
    check("A first use continue",
          site_a_first_use(0, 99, {"x38": 0}), ("continue", 99))
    check("B first use bool", site_b_first_use(1, 99, 10),
          "alt-0x5e19038")
    check("B first use low ptr", site_b_first_use(0, 9, 10),
          "alt-0x5e19038")
    check("B first use continue", site_b_first_use(0, 30, 10),
          ("continue", 25))
    check("C first use bool", site_c_first_use(1, 99, 10),
          "alt-0x5f7daec")
    check("C first use low ptr", site_c_first_use(0, 9, 10),
          "alt-0x5f7daec")
    check("C first use continue", site_c_first_use(0, 30, 10),
          ("continue", 20))
    check("D first use bool", site_d_first_use(1, 99), "alt-0x5f86fcc")
    check("D first use continue", site_d_first_use(0, 99),
          ("continue", 99))

    # --- installers ---
    obj = {}
    install_wrapper_vtable(obj)
    check("wrapper install", obj["vptr"], WRAPPER_VTABLE)
    for i, vtable in enumerate(ENTRY_VTABLES):
        obj = {}
        check("entry install %d mode 0 returns 0" % i,
              entry_install(0, obj, 0xDEAD, vtable), 0)
        check("entry install %d mode 0" % i, obj["slot0"], vtable)
        obj = {}
        check("entry install %d mode 1 returns 0" % i,
              entry_install(1, obj, 0xBEEF, vtable), 0)
        check("entry install %d mode 1" % i, obj["slot0"], 0xBEEF)
        obj = {"slot0": 0x1234}
        check("entry install %d mode 2 returns 0" % i,
              entry_install(2, obj, 0xBEEF, vtable), 0)
        check("entry install %d mode 2 untouched" % i,
              obj["slot0"], 0x1234)

    # --- resolver fast path (re-shipped ground, #3322) ---
    check("resolver fast path resolved",
          resolver_fast_path({"cb8": 5}), True)
    check("resolver fast path sentinel",
          resolver_fast_path({"cb8": 0xFFFFFFFFFFFFFFFF}), False)

    print("%d checks, 0 failed" % len(CHECKS))


if __name__ == "__main__":
    sys.exit(main())
