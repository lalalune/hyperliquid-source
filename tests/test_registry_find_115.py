#!/usr/bin/env python3
"""Tests for tools/registry_find_115.py (node #115).

Run from the repository root:

    python3 tests/test_registry_find_115.py

Every test drives the model end-to-end (inputs through the model
to observable outputs), not just pinned constants. The hash
vectors are the libstdc++ values verified in
tools/registry_create_115.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import registry_find_115 as m

PASSED = 0


def check(label, got, want):
    global PASSED
    if got != want:
        raise AssertionError("%s: got %r, want %r" % (label, got, want))
    PASSED += 1


def check_true(label, cond):
    global PASSED
    if not cond:
        raise AssertionError("%s: expected true" % label)
    PASSED += 1


# --- hash ---------------------------------------------------------------

def test_hash():
    check("hash empty", m.hash_bytes(b""), 0x553E93901E462A6E)
    check("hash Statistics", m.hash_bytes("Statistics"),
          0xD971F53C71278410)
    check("hash BasicStatistics", m.hash_bytes("BasicStatistics"),
          0x09C2C29A91E52549)
    check("hash TableFactory", m.hash_bytes("TableFactory"),
          0x5FC34B207B5C1B2E)
    check("hash id", m.hash_bytes("id"), m.hash_bytes(b"id"))


# --- trim / value_extract / parse_options --------------------------------

def test_trim():
    check("trim plain", m.trim("  abc  "), "abc")
    check("trim tabs", m.trim("\t\n a b \r\n"), "a b")
    check("trim empty", m.trim(""), "")
    check("trim all ws", m.trim("  \t\n "), "")


def test_value_extract():
    cur = [None]
    st, val = m.value_extract("a=1;b=2", 2, cur)
    check("extract ok", st, m.Status.ok())
    check("extract plain value", val, "1")
    check("extract plain cursor", cur[0], 3)
    cur = [None]
    st, val = m.value_extract("a=1", 2, cur)
    check("extract to end", (st.is_ok(), val, cur[0]),
          (True, "1", -1))
    cur = [None]
    st, val = m.value_extract("a={x;y};b=2", 2, cur)
    check("extract brace value", (st.is_ok(), val, cur[0]),
          (True, "x;y", 7))
    cur = [None]
    st, val = m.value_extract("a={x;y", 2, cur)
    check("extract unbalanced code", st.code, m.INVALID_ARGUMENT)
    check("extract unbalanced msg", st.msg,
          ": " + m.MSG_MISMATCHED_BRACES)
    cur = [None]
    st, val = m.value_extract("a={x}y;b=2", 2, cur)
    check("extract after-nested code", st.code, m.INVALID_ARGUMENT)
    check("extract after-nested msg", st.msg,
          ": " + m.MSG_UNEXPECTED_AFTER_NESTED)
    cur = [None]
    st, val = m.value_extract("a=", 2, cur)
    check("extract empty value", (st.is_ok(), val, cur[0]),
          (True, "", -1))
    cur = [None]
    st, val = m.value_extract("a=1", 99, cur)
    check("extract past end", (st.is_ok(), val, cur[0]),
          (True, "", -1))
    cur = [None]
    st, val = m.value_extract("a=  spaced  ;b=2", 2, cur)
    check("extract trims", (st.is_ok(), val, cur[0]),
          (True, "spaced", 12))


def test_parse_options():
    mp = m.OptionsMap()
    st = m.parse_options("a=1;b=2;c=3", mp)
    check("parse ok", st, m.Status.ok())
    check("parse a", mp.find("a"), "1")
    check("parse b", mp.find("b"), "2")
    check("parse c", mp.find("c"), "3")
    mp = m.OptionsMap()
    st = m.parse_options("{a=1;b=2}", mp)
    check("parse braces ok", st.is_ok(), True)
    check("parse braces a", mp.find("a"), "1")
    check("parse braces b", mp.find("b"), "2")
    mp = m.OptionsMap()
    st = m.parse_options("{{a=1}}", mp)
    check("parse double braces", (st.is_ok(), mp.find("a")),
          (True, "1"))
    mp = m.OptionsMap()
    st = m.parse_options("a={x;y};b=2", mp)
    check("parse nested value", (st.is_ok(), mp.find("a"),
                                 mp.find("b")),
          (True, "x;y", "2"))
    mp = m.OptionsMap()
    st = m.parse_options("a=1;a=2", mp)
    check("parse duplicate overwrites", (st.is_ok(), mp.find("a")),
          (True, "2"))
    mp = m.OptionsMap()
    st = m.parse_options("a", mp)
    check("parse no delimiter code", st.code, m.INVALID_ARGUMENT)
    check("parse no delimiter msg", st.msg,
          ": " + m.MSG_MISMATCHED_PAIR)
    mp = m.OptionsMap()
    st = m.parse_options("a;b=1", mp)
    check("parse unexpected char", st.msg,
          ": " + m.MSG_UNEXPECTED_CHAR)
    mp = m.OptionsMap()
    st = m.parse_options("=1", mp)
    check("parse empty key", st.msg, ": " + m.MSG_EMPTY_KEY)
    mp = m.OptionsMap()
    st = m.parse_options("a={x", mp)
    check("parse unbalanced braces", st.msg,
          ": " + m.MSG_MISMATCHED_BRACES)


# --- options map ---------------------------------------------------------

def test_options_map():
    mp = m.OptionsMap()
    check("map empty find", mp.find("a"), None)
    mp.index("a").set("1")
    mp.index("b").set("2")
    check("map find a", mp.find("a"), "1")
    check("map len", len(mp), 2)
    # insert-if-absent: index returns the existing node.
    mp.index("a").set("9")
    check("map overwrite via index", mp.find("a"), "9")
    check("map len after dup", len(mp), 2)
    mp.erase("a")
    check("map erased", mp.find("a"), None)
    check("map len after erase", len(mp), 1)
    mp.clear()
    check("map cleared", (len(mp), mp.find("b")), (0, None))
    # Over 20 entries: the hash-bucket walk must still find
    # every key, across rehashes.
    mp = m.OptionsMap()
    for i in range(40):
        mp.index("k%02d" % i).set("v%02d" % i)
    check("map 40 len", len(mp), 40)
    check("map bucket count grew", mp.bucket_count > 1, True)
    for i in range(40):
        check("map 40 find k%02d" % i, mp.find("k%02d" % i),
              "v%02d" % i)
    mp.erase("k07")
    mp.erase("k31")
    check("map 40 after erase", (mp.find("k07"), mp.find("k31"),
                                 mp.find("k08"), len(mp)),
          (None, None, "v08", 38))
    # Erasing a node that is another bucket's before-begin must
    # not break later finds (the erase fixes bucket pointers).
    mp2 = m.OptionsMap()
    for i in range(30):
        mp2.index("e%02d" % i).set("w%02d" % i)
    for i in range(30):
        mp2.erase("e%02d" % i)
        for j in range(i + 1, 30):
            check("map erase keeps e%02d" % j,
                  mp2.find("e%02d" % j), "w%02d" % j)
    check("map erase all", len(mp2), 0)


# --- find_norm -----------------------------------------------------------

def test_find_norm():
    mp = m.OptionsMap()
    st, out = m.find_norm("", "fb", mp)
    check("norm empty name", (st.is_ok(), out), (True, "fb"))
    mp = m.OptionsMap()
    st, out = m.find_norm("default", "fb", mp)
    check("norm default name", (st.is_ok(), out), (True, "fb"))
    mp = m.OptionsMap()
    st, out = m.find_norm("plain", "fb", mp)
    check("norm no equals", (st.is_ok(), out), (True, "plain"))
    mp = m.OptionsMap()
    st, out = m.find_norm("a=1;id=foo;b=2", "fb", mp)
    check("norm id path", (st.is_ok(), out, mp.find("a"),
                           mp.find("id"), mp.find("b")),
          (True, "foo", "1", None, "2"))
    mp = m.OptionsMap()
    st, out = m.find_norm("a=1;id=default", "fb", mp)
    check("norm id is default", (st.is_ok(), out), (True, ""))
    mp = m.OptionsMap()
    st, out = m.find_norm("a=1;b=2", "fb", mp)
    check("norm no id fallback", (st.is_ok(), out, mp.find("a")),
          (True, "fb", "1"))
    mp = m.OptionsMap()
    st, out = m.find_norm("a=1;b=2", "", mp)
    check("norm no id empty fallback", (st.is_ok(), out, len(mp)),
          (True, "a=1;b=2", 0))
    mp = m.OptionsMap()
    st, out = m.find_norm("a;b=1", "fb", mp)
    check("norm parser error swallowed",
          (st.is_ok(), out, len(mp)), (True, "a;b=1", 0))


# --- resolver ------------------------------------------------------------

def test_resolver():
    check("resolver plain", m.resolver(m.NameObject("abc")), "abc")
    check("resolver empty", m.resolver(m.NameObject("")), "")
    check("resolver quotes prefix", m.resolver(m.NameObject("ab=cd")),
          "{ab}")
    check("resolver only key", m.resolver(m.NameObject("ab=")), "{ab}")


# --- matcher -------------------------------------------------------------

def _node(kind=0, state=0, flags=0, flag_b1=False, obj=None):
    if obj is None:
        obj = m.NodeObj(name_object=m.NameObject("n"))
    return m.TableNode("node", obj, kind=kind, state=state,
                       flags=flags, flag_b1=flag_b1)


def test_matcher():
    val = m.Value(has_value=0)
    out = [""]
    st = m.matcher(_node(), val, "n", None, out)
    check("matcher null prefix", (st.is_ok(), out[0]), (True, ""))
    out = [""]
    st = m.matcher(_node(state=4), val, "n", object(), out)
    check("matcher state 4", (st.is_ok(), out[0]), (True, ""))
    out = [""]
    st = m.matcher(_node(flags=0x2000), val, "n", object(), out)
    check("matcher 0x2000 code", st.code, m.NOT_SUPPORTED)
    check("matcher 0x2000 msg", st.msg, "n: " + m.MSG_CANNOT_SERIALIZE)
    # Virtual slot 0x40 fills out directly.
    seen = []
    def virt(value, name, value_out):
        seen.append((value, name))
        return m.Status.build(4, 0, "virt", "err")
    obj = m.NodeObj(has_virtual=True, virtual_serialize=virt)
    out = [""]
    st = m.matcher(_node(obj=obj), val, "n", object(), out)
    check("matcher virtual", (st.code, st.msg, len(seen)),
          (4, "virt: err", 1))
    # Kind 0x15: resolver path, assigned unconditionally.
    obj = m.NodeObj(name_object=m.NameObject("pre=post"))
    out = [""]
    st = m.matcher(_node(kind=0x15, obj=obj), val, "n", object(), out)
    check("matcher 0x15", (st.is_ok(), out[0]), (True, "{pre}"))
    # Kind 0x16, flags 0x8000, field28 != 2, has_value clear:
    # delegate-name path.
    obj = m.NodeObj(name_object=m.NameObject("", "del-name"))
    out = [""]
    st = m.matcher(_node(kind=0x16, flags=0x8000, obj=obj),
                   m.Value(has_value=0, field28=1), "n",
                   object(), out)
    check("matcher 0x16 delegate", (st.is_ok(), out[0]),
          (True, "del-name"))
    # Same gate with has_value set needs +0xd8 & 0x100 too.
    obj = m.NodeObj(name_object=m.NameObject("", "del-name"))
    out = [""]
    st = m.matcher(_node(kind=0x16, flags=0x8100, obj=obj),
                   m.Value(has_value=1, field28=1), "n",
                   object(), out)
    check("matcher 0x16 delegate needs 0x100",
          (st.is_ok(), out[0]), (True, "del-name"))
    obj = m.NodeObj(name_object=m.NameObject("", "del-name"))
    out = ["keep"]
    st = m.matcher(_node(kind=0x16, flags=0x8000, obj=obj),
                   m.Value(has_value=1, field28=1), "n",
                   object(), out)
    check("matcher 0x16 delegate gated", (st.is_ok(), out[0]),
          (True, ""))
    # field28 == 2 takes the resolver path instead.
    obj = m.NodeObj(name_object=m.NameObject("k=v"))
    out = [""]
    st = m.matcher(_node(kind=0x16, flags=0x8000, obj=obj),
                   m.Value(has_value=0, field28=2), "n",
                   object(), out)
    check("matcher 0x16 field28 2 resolves",
          (st.is_ok(), out[0]), (True, "{k}"))
    # Kind 0x16 flag chain: one link is followed, then the
    # body runs on the linked object.
    chained = m.NameObject("a=b")
    chained.link = m.NameObject("c=d")
    obj = m.NodeObj(name_object=chained)
    out = [""]
    st = m.matcher(_node(kind=0x16, flags=0x800, obj=obj),
                   m.Value(has_value=0), "n", object(), out)
    check("matcher 0x16 chain", (st.is_ok(), out[0]),
          (True, "{c}"))
    # Chain exhausted: default name, or "" when 0xb1 is clear
    # and has_value is set.
    dead = m.NameObject("x")
    dead.link = None
    obj = m.NodeObj(name_object=dead)
    out = [""]
    st = m.matcher(_node(kind=0x16, flags=0x800, obj=obj),
                   m.Value(has_value=0), "n", object(), out)
    check("matcher 0x16 chain exhausted",
          (st.is_ok(), out[0]), (True, "default"))
    obj = m.NodeObj(name_object=dead)
    out = [""]
    st = m.matcher(_node(kind=0x16, flags=0x800, obj=obj),
                   m.Value(has_value=1), "n", object(), out)
    check("matcher 0x16 chain exhausted has value",
          (st.is_ok(), out[0]), (True, ""))
    obj = m.NodeObj(name_object=dead)
    out = [""]
    st = m.matcher(_node(kind=0x16, flags=0x800, flag_b1=True,
                         obj=obj),
                   m.Value(has_value=1), "n", object(), out)
    check("matcher 0x16 chain exhausted b1",
          (st.is_ok(), out[0]), (True, "default"))
    # Kind 0x16 resolver path: 0xb1 flag set -> assign even
    # without '='; clear + has_value + no '=' -> cleared.
    obj = m.NodeObj(name_object=m.NameObject("plain"))
    out = [""]
    st = m.matcher(_node(kind=0x16, flag_b1=True, obj=obj),
                   m.Value(has_value=1), "n", object(), out)
    check("matcher 0x16 b1 set", (st.is_ok(), out[0]),
          (True, "plain"))
    obj = m.NodeObj(name_object=m.NameObject("plain"))
    out = [""]
    st = m.matcher(_node(kind=0x16, obj=obj),
                   m.Value(has_value=1), "n", object(), out)
    check("matcher 0x16 needs equals", (st.is_ok(), out[0]),
          (True, ""))
    # The resolver's result is either the whole name (no '='
    # in it) or "{key}" (the part before the first '='), so it
    # never contains '=': with has_value set and the 0xb1 flag
    # clear the 0x16 resolver path always clears, even for a
    # name that has '='.
    obj = m.NodeObj(name_object=m.NameObject("k=v"))
    out = [""]
    st = m.matcher(_node(kind=0x16, obj=obj),
                   m.Value(has_value=1), "n", object(), out)
    check("matcher 0x16 resolver result has no equals",
          (st.is_ok(), out[0]), (True, ""))
    # With has_value clear the same path assigns the result.
    obj = m.NodeObj(name_object=m.NameObject("k=v"))
    out = [""]
    st = m.matcher(_node(kind=0x16, obj=obj),
                   m.Value(has_value=0), "n", object(), out)
    check("matcher 0x16 no value assigns", (st.is_ok(), out[0]),
          (True, "{k}"))
    # Other kinds: serializer true -> no match; false -> code 4.
    out = [""]
    st = m.matcher(_node(kind=3), val, "n", object(), out,
                   serializer=lambda o, k, v: True)
    check("matcher serializer true", (st.is_ok(), out[0]),
          (True, ""))
    out = [""]
    st = m.matcher(_node(kind=3), val, "n", object(), out,
                   serializer=lambda o, k, v: False)
    check("matcher serializer false code", st.code,
          m.INVALID_ARGUMENT)
    check("matcher serializer false msg", st.msg,
          "n: " + m.MSG_CANNOT_SERIALIZE)
    # has_value set without the 0x100 flag -> no match, and the
    # serializer is not called.
    calls = []
    out = [""]
    st = m.matcher(_node(kind=3), m.Value(has_value=1), "n",
                   object(), out,
                   serializer=lambda o, k, v: calls.append(1) or False)
    check("matcher gated serializer", (st.is_ok(), calls),
          (True, []))
    # Flag chain: 0x15 with a link that resolves, then a null
    # link is no match.
    chained = m.NameObject("a=b")
    chained.link = m.NameObject("c=d")
    obj = m.NodeObj(name_object=chained)
    out = [""]
    st = m.matcher(_node(kind=0x15, flags=0x800, obj=obj), val,
                   "n", object(), out)
    check("matcher 0x15 chain", (st.is_ok(), out[0]), (True, "{c}"))
    dead = m.NameObject("x")
    dead.link = None
    obj = m.NodeObj(name_object=dead)
    out = ["keep"]
    st = m.matcher(_node(kind=0x15, flags=0x800, obj=obj), val,
                   "n", object(), out)
    check("matcher 0x15 dead chain", (st.is_ok(), out[0]),
          (True, "keep"))


# --- worker / thunk / find_entry ------------------------------------------

def _delegate_with(node, prefix=""):
    entry = m.TableEntry("elem", [node])
    return m.Delegate([entry], slot_0x78_name="del",
                      slot_0x80_target=m.CANONICAL_DELEGATE,
                      slot_0x70_name="del", slot_0x90_name="other")


def test_worker():
    # A 0x15 node resolves and the pair accumulates.
    obj = m.NodeObj(name_object=m.NameObject("k=v"))
    node = m.TableNode("opt", obj, kind=0x15)
    d = _delegate_with(node)
    out = [""]
    st = m.worker(d, m.Value(), "", out)
    check("worker accumulates", (st.is_ok(), out[0]),
          (True, "opt={k}"))
    # A serializer failure returns at once (first match wins).
    node2 = m.TableNode("bad", m.NodeObj(), kind=3)
    d2 = m.Delegate([m.TableEntry("e", [node2])])
    st = m.worker(d2, m.Value(), "",
                  [""], serializer=lambda o, k, v: False)
    check("worker serializer error", st.code, m.INVALID_ARGUMENT)
    # Skipped nodes never match.
    skip = m.TableNode("s", m.NodeObj(), kind=3, state=4)
    skip2 = m.TableNode("s2", m.NodeObj(), kind=3, flags=0x2000)
    d3 = m.Delegate([m.TableEntry("e", [skip, skip2])])
    out = [""]
    st = m.worker(d3, m.Value(), "", out,
                  serializer=lambda o, k, v: False)
    check("worker skips", (st.is_ok(), out[0]), (True, ""))
    # Copy path: has_value + 0x100 runs the matcher on a copy
    # with +0x04 forced to 1.
    got = []
    def virt(value, name, value_out):
        got.append(value.has_value)
        return m.Status.ok()
    obj = m.NodeObj(has_virtual=True, virtual_serialize=virt)
    node = m.TableNode("c", obj, kind=3, flags=0x100)
    d4 = m.Delegate([m.TableEntry("e", [node])])
    st = m.worker(d4, m.Value(has_value=1), "", [""])
    check("worker copy path", (st.is_ok(), got), (True, [1]))
    # 0x6097ef8 path: kind 0x15 + has_value + field28 != 2 +
    # 0x8000 set -> skipped; field28 == 2 -> runs.
    obj = m.NodeObj(name_object=m.NameObject("k=v"))
    node = m.TableNode("e15", obj, kind=0x15, flags=0x8000)
    d5 = m.Delegate([m.TableEntry("e", [node])])
    out = [""]
    st = m.worker(d5, m.Value(has_value=1, field28=1), "", out)
    check("worker 0x8000 skips", (st.is_ok(), out[0]), (True, ""))
    out = [""]
    st = m.worker(d5, m.Value(has_value=1, field28=2), "", out)
    check("worker field28 2 runs", (st.is_ok(), out[0]),
          (True, "e15={k}"))
    # No match anywhere: success, empty accumulator.
    d6 = m.Delegate([m.TableEntry("e", [])])
    out = [""]
    st = m.worker(d6, m.Value(), "", out)
    check("worker empty", (st.is_ok(), out[0]), (True, ""))


def test_find_entry():
    # Empty and default names clear the out-string and the map.
    mp = m.OptionsMap()
    mp.index("x").set("1")
    out = ["keep"]
    st, res = m.find_entry(m.Value(), None, "", out, mp)
    check("entry empty name", (st.is_ok(), res, len(mp)),
          (True, "", 0))
    mp = m.OptionsMap()
    mp.index("x").set("1")
    out = ["keep"]
    st, res = m.find_entry(m.Value(), None, "default", out, mp)
    check("entry default name", (st.is_ok(), res, len(mp)),
          (True, "", 0))
    # Null delegate: Find normal drives the result.
    mp = m.OptionsMap()
    out = [""]
    st, res = m.find_entry(m.Value(), None, "a=1;id=foo", out, mp)
    check("entry null delegate", (st.is_ok(), res, mp.find("a")),
          (True, "foo", "1"))
    # Non-canonical slot 0x80 predicate false: return, the
    # out-string keeps Find normal's result (the name itself,
    # since "plain" has no '='; the delegate name is only the
    # fallback).
    d = m.Delegate([], slot_0x78_name="del",
                   slot_0x80_target=0x1234,
                   slot_0x80_predicate=lambda s: False)
    mp = m.OptionsMap()
    out = [""]
    st, res = m.find_entry(m.Value(), d, "plain", out, mp)
    check("entry predicate false", (st.is_ok(), res),
          (True, "plain"))
    # Canonical match: the register path accumulates the
    # worker's pairs and merges them insert-if-absent. The
    # out-string must equal a delegate name (slot 0x70/0x90)
    # for the register path to run, so the delegate name here
    # is "plain".
    obj = m.NodeObj(name_object=m.NameObject("k=v"))
    node = m.TableNode("opt", obj, kind=0x15)
    d = m.Delegate([m.TableEntry("elem", [node])],
                   slot_0x78_name="del",
                   slot_0x80_target=m.CANONICAL_DELEGATE,
                   slot_0x70_name="plain", slot_0x90_name="other")
    mp = m.OptionsMap()
    mp.index("opt").set("existing")
    out = [""]
    st, res = m.find_entry(m.Value(), d, "plain", out, mp)
    check("entry register path",
          (st.is_ok(), res, mp.find("opt")),
          (True, "plain", "existing"))
    # A worker error is swallowed: success, out-string keeps
    # Find normal's result, and nothing is merged. The
    # delegate name is "plain" so the register path runs.
    node2 = m.TableNode("bad", m.NodeObj(), kind=3)
    d2 = m.Delegate([m.TableEntry("e", [node2])],
                    slot_0x78_name="del",
                    slot_0x80_target=m.CANONICAL_DELEGATE,
                    slot_0x70_name="plain")
    mp = m.OptionsMap()
    out = [""]
    st, res = m.find_entry(m.Value(), d2, "plain", out, mp,
                           serializer=lambda o, k, v: False)
    check("entry worker error swallowed",
          (st.is_ok(), res, len(mp)), (True, "plain", 0))


def test_fallback():
    class Obj:
        def __init__(self, status):
            self._status = status

        def slot_0x48(self):
            return self._status

    st = m.fallback(None, Obj(m.Status.build(4, 0, "x", "y")), False)
    check("fallback delegate", (st.code, st.msg), (4, "x: y"))
    st = m.fallback(None, None, False)
    check("fallback null empty c", st, m.Status.ok())
    st = m.fallback(None, None, True)
    check("fallback null object", (st.code, st.msg),
          (4, ": " + m.MSG_CANNOT_CONFIGURE_NULL))
    st = m.fallback_delegate(Obj(m.Status.ok()))
    check("fallback_delegate ok", st.is_ok(), True)


def main():
    test_hash()
    test_trim()
    test_value_extract()
    test_parse_options()
    test_options_map()
    test_find_norm()
    test_resolver()
    test_matcher()
    test_worker()
    test_find_entry()
    test_fallback()
    print("ALL %d CHECKS PASSED" % PASSED)


if __name__ == "__main__":
    main()
