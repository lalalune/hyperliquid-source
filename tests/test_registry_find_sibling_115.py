#!/usr/bin/env python3
"""Tests for tools/registry_find_sibling_115.py (RE-001, node #115).

Run directly with python3 (pytest is not installed on this VM):

    python3 tests/test_registry_find_sibling_115.py

Every check is counted; the script prints the total and exits
non-zero on the first failure. The delegate/node virtuals
(slot 0x28/0x40/0x48/0x50/0x68/0x78) are supplied by small
recording stubs, because the binary reaches them through the
object's vtable and their bodies are delegate-provided, not
part of this packet.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import registry_find_sibling_115 as m

CHECKS = 0


def check(cond, label):
    global CHECKS
    CHECKS += 1
    if not cond:
        raise AssertionError("check %d failed: %s" % (CHECKS, label))


def eq(got, want, label):
    check(got == want, "%s: got %r, want %r" % (label, got, want))


def slot50_recorder(log, result=None):
    def slot50(out, obj, value, found, name, arg7, extra):
        log.append((obj, value, found, name, arg7, extra))
        return result if result is not None else m.Status.ok()
    return slot50


def make_node(**kw):
    return m.ConfigNode(**kw)


def make_value(**kw):
    shared = m.SharedControl()
    kw.setdefault("shared", shared)
    return m.Value(**kw), shared


# --- ends_with (0x61d1390) -------------------------------------------
eq(m.ends_with("abc.id", ".id"), 1, "ends_with .id")
eq(m.ends_with("abc", ".id"), 0, "ends_with missing")
eq(m.ends_with("", ".id"), 0, "ends_with empty haystack")
eq(m.ends_with("x", ""), 1, "ends_with empty suffix")
eq(m.ends_with(".id", ".id"), 1, "ends_with exact")
eq(m.ends_with("ab.id", ".idx"), 0, "ends_with longer suffix")
eq(m.ends_with("abcid", "id"), 1, "ends_with id")
eq(m.ends_with("abc", "abcd"), 0, "ends_with suffix too long")

# --- str_compare (0x61d13e0) -----------------------------------------
eq(m.str_compare("abc", "abc"), 0, "str_compare equal")
check(m.str_compare("a", "b") < 0, "str_compare less")
check(m.str_compare("b", "a") > 0, "str_compare greater")
check(m.str_compare("ab", "abc") < 0, "str_compare prefix short")
check(m.str_compare("abc", "ab") > 0, "str_compare prefix long")
eq(m.str_compare("", ""), 0, "str_compare empty")
check(m.str_compare("", "a") < 0, "str_compare empty vs a")

# --- move_assign (0x60b79e0) ------------------------------------------
holder = [""]
m.move_assign(holder, "hello")
eq(holder[0], "hello", "move_assign delivers")

# --- hash_bytes --------------------------------------------------------
eq(m.hash_bytes(b""), m.hash_bytes(b""), "hash stable")
check(m.hash_bytes(b"a") != m.hash_bytes(b"b"), "hash differs")
check(m.hash_bytes("Statistics") != 0, "hash nonzero")

# --- name_lookup, linear walk (0x60ba0b0) -----------------------------
table = m.NameTable([m.TableNode("alpha", kind=0x13),
                     m.TableNode("beta", kind=0x15),
                     m.TableNode("gamma", kind=0x16)])
out = [""]
node = m.name_lookup("beta", table, out)
check(node is table.nodes[1], "lookup exact node")
eq(out[0], "beta", "lookup exact out")
out = ["keep"]
eq(m.name_lookup("delta", table, out), None, "lookup miss")
eq(out[0], "keep", "lookup miss leaves out")
# Dotted: prefix kind 0x13 / 0x15 / 0x16 admit, others do not.
for kind, ok in ((0x13, True), (0x15, True), (0x16, True),
                 (0x14, False), (0x17, False), (0, False)):
    t2 = m.NameTable([m.TableNode("pre", kind=kind)])
    o = [""]
    n = m.name_lookup("pre.suf", t2, o)
    if ok:
        check(n is t2.nodes[0], "dotted kind %#x admits" % kind)
        eq(o[0], "suf", "dotted kind %#x out" % kind)
    else:
        eq(n, None, "dotted kind %#x rejects" % kind)
        eq(o[0], "", "dotted kind %#x out untouched" % kind)
eq(m.name_lookup("nodot", table, ["x"]), None, "lookup no dot")
eq(m.name_lookup(".lead", table, ["x"]), None, "lookup dot at 0")
o = [""]
n = m.name_lookup("pre.", m.NameTable(
    [m.TableNode("pre", kind=0x13)]), o)
check(n is not None, "lookup trailing dot returns node")
eq(o[0], "", "lookup trailing dot out is empty suffix")

# --- hash_name_find (0x60b84b0) ----------------------------------------
many = [m.TableNode("k%02d" % i, kind=0x13) for i in range(25)]
htab = m.NameTable(many, bucket_count=7)
found = m.hash_name_find("k07", htab)
check(found is many[7], "hash find k07")
eq(m.hash_name_find("k99", htab), None, "hash find miss")
# The >20 path of name_lookup uses the hash find.
o = [""]
n = m.name_lookup("k20", htab, o)
check(n is many[20], "lookup hash path")
eq(o[0], "k20", "lookup hash path out")

# --- element_scan (0x6096f40) ------------------------------------------
elems = [
    m.TableEntry("e0", table=m.NameTable(
        [m.TableNode("aa", kind=0x13)]), field20=0x1111),
    m.TableEntry("e1", table=None, field20=0x2222),
    m.TableEntry("e2", table=m.NameTable(
        [m.TableNode("bb", kind=0x15)]), field20=0x3333),
]
o = [""]
node, f20 = m.element_scan(elems, "bb", o)
check(node is not None and node.name == "bb", "scan second element")
eq(f20, 0x3333, "scan field20")
eq(o[0], "bb", "scan out")
o = [""]
node, f20 = m.element_scan(elems, "zz", o)
eq(node, None, "scan miss node")
eq(f20, None, "scan miss field20")
o = [""]
node, f20 = m.element_scan(elems, "aa", o)
check(node is not None and node.name == "aa", "scan first element")
eq(f20, 0x1111, "scan first field20")

# --- delegate_impl / fallback_delegate (0x6097110 / 0x6097150) ---------
seen = []
def slot48(out, obj, value, ctx_map, flag):
    seen.append(flag)
    return m.Status.build(4, 0, "from48", "x")
nd = make_node(slot_0x48=slot48)
st = m.delegate_impl(m.Status.ok(), nd, None, None, 7)
eq(st.code, 4, "delegate_impl code")
eq(st.msg, "from48: x", "delegate_impl msg")
eq(seen, [7], "delegate_impl flag passes through")
seen.clear()
st = m.fallback_delegate(m.Status.ok(), nd, None, None)
eq(seen, [0], "fallback_delegate flag is 0")

# --- zero_stub (0x60956f0) ---------------------------------------------
eq(m.zero_stub(m.Status.ok()), m.Status.ok(), "zero_stub ok")

# --- kind_dispatch (0x609b700) -----------------------------------------
log = []
nd = make_node(slot_0x50=slot50_recorder(log))
# Equal names -> slot-0x50 regardless of kind.
st = m.kind_dispatch(m.Status.ok(), None, nd,
                     m.TableNode("n", kind=0x99), "same", "same",
                     "a7", 0x42)
eq(st.code, 0, "kind equal names ok")
eq(len(log), 1, "kind equal names calls slot50")
eq(log[0][3], "same", "kind equal names arg")
eq(log[0][5], 0x42, "kind equal names extra")
# Kind 0x13 / 0x15 with different names -> slot-0x50.
for kind in (0x13, 0x15):
    log.clear()
    st = m.kind_dispatch(m.Status.ok(), None, nd,
                         m.TableNode("n", kind=kind), "aa", "bb",
                         "a7", 0x42)
    eq(st.code, 0, "kind %#x slot50" % kind)
    eq(len(log), 1, "kind %#x called" % kind)
# Other kinds -> code 1 "Could not find option: <str_b>".
for kind in (0x14, 0x17, 0, 0x12):
    st = m.kind_dispatch(m.Status.ok(), None, nd,
                         m.TableNode("n", kind=kind), "aa", "bb",
                         "a7", 0x42)
    eq(st.code, 1, "kind %#x error code" % kind)
    eq(st.msg, "Could not find option: : bb",
       "kind %#x error msg" % kind)
# Kind 0x16 recurses into the entry: the recursive entry
# resolves desc from the found node (sub_first 0, flags 0)
# against a memory where base+0 is the delegate node itself,
# and name5 == key6 (both str_b) takes slot-0x50.
log.clear()
rec_delegate = make_node(slot_0x50=slot50_recorder(log))
mem = {0x5000: rec_delegate}
found16 = m.TableNode("n", kind=0x16, sub_first=0, flags=0)
val, shared = make_value()
st = m.kind_dispatch(m.Status.ok(), val, rec_delegate, found16,
                     "aa", "bb", "a7", 0x5000)
eq(st.code, 0, "kind 0x16 recursion ok")
eq(len(log), 1, "kind 0x16 recursion calls slot50 once")
eq(log[0][3], "bb", "kind 0x16 recursion name is str_b")
eq(log[0][4], "a7", "kind 0x16 recursion arg7")
eq(shared.use_count, 1, "kind 0x16 recursion releases copy")

# --- resolve_no_equals (0x609b8a0) --------------------------------------
log.clear()
nd = make_node(
    slot_0x68=lambda obj, k: "found-name",
    slot_0x50=slot50_recorder(log),
    elements=[m.TableEntry("e", table=m.NameTable(
        [m.TableNode("found-name", kind=0x13)]), field20=0x77)])
st = m.resolve_no_equals(m.Status.ok(), None, nd, "key6", "a7")
eq(st.code, 0, "resolve_no_equals ok")
eq(len(log), 1, "resolve_no_equals dispatches")
eq(log[0][3], "found-name", "resolve_no_equals name")
eq(log[0][5], 0x77, "resolve_no_equals extra is field20")
nd2 = make_node(
    slot_0x68=lambda obj, k: "missing",
    elements=[m.TableEntry("e", table=m.NameTable(
        [m.TableNode("other", kind=0x13)]))])
st = m.resolve_no_equals(m.Status.ok(), None, nd2, "key6", "a7")
eq(st.code, 1, "resolve_no_equals miss code")
eq(st.msg, "Could not find option: : key6",
   "resolve_no_equals miss msg")

# --- find_e70 (0x6099e70) ------------------------------------------------
# Empty arg7, +0x03 clear -> ok; +0x03 set -> slot-0x28.
nd = make_node(slot_0x28=lambda o, v: m.Status.build(7, 0, "s28", ""))
v, _ = make_value(code=0)
eq(m.find_e70(nd, v, ""), m.Status.ok(), "e70 empty b03 clear")
v, _ = make_value(code=0x03000000)
st = m.find_e70(nd, v, "")
eq(st.code, 7, "e70 empty b03 set calls slot28")
# ';' path: parse ok -> delegate_impl with the parsed map.
seen48 = []
def slot48b(out, obj, value, ctx_map, flag):
    seen48.append(dict(ctx_map.items()))
    return m.Status.build(2, 0, "did48", "")
nd = make_node(slot_0x48=slot48b)
v, _ = make_value()
st = m.find_e70(nd, v, "a=1;b=2")
eq(st.code, 2, "e70 parse path delegates")
eq(seen48, [{"a": "1", "b": "2"}], "e70 parse path map")
# '=' path: same, through '='.
seen48.clear()
st = m.find_e70(nd, v, "a=1")
eq(st.code, 2, "e70 equals path delegates")
eq(seen48, [{"a": "1"}], "e70 equals path map")
# Parse failure on the ';' path: the error is kept, no delegate.
seen48.clear()
st = m.find_e70(nd, v, "a;1")
eq(st.code, 4, "e70 parse failure code")
eq(seen48, [], "e70 parse failure skips delegate")
# No ';' / '=' with the zero stub -> ok, then the +0x03 check.
nd = make_node(is_zero_stub_0x40=True,
               slot_0x28=lambda o, v: m.Status.build(7, 0, "s28", ""))
v, _ = make_value(code=0)
eq(m.find_e70(nd, v, "abc"), m.Status.ok(), "e70 zero stub ok")
v, _ = make_value(code=0x01000000)
st = m.find_e70(nd, v, "abc")
eq(st.code, 7, "e70 zero stub then slot28")
# No ';' / '=' with a real slot-0x40: error returns at once.
nd = make_node(slot_0x40=lambda o, v: m.Status.build(5, 0, "s40", ""),
               slot_0x28=lambda o, v: m.Status.build(7, 0, "s28", ""))
v, _ = make_value(code=0x01000000)
st = m.find_e70(nd, v, "abc")
eq(st.code, 5, "e70 slot40 error returns")
# Slot-0x40 ok -> falls to the +0x03 check.
nd = make_node(slot_0x40=lambda o, v: m.Status.ok(),
               slot_0x28=lambda o, v: m.Status.build(7, 0, "s28", ""))
v, _ = make_value(code=0x01000000)
st = m.find_e70(nd, v, "abc")
eq(st.code, 7, "e70 slot40 ok then slot28")

# --- entry (0x609a740) ----------------------------------------------------
def slot50_ok(log):
    return slot50_recorder(log)

# Flag-chain resolution: base + offset, one link on 0x800.
target = make_node(slot_0x50=slot50_ok([]))
mem = {0x1010: {"link": 0x2000}, 0x2000: target}
log = []
delegate = make_node(slot_0x50=slot50_recorder(log))
val, shared = make_value()
desc = m.Desc(offset=0x10, flags=0x800)
st = m.entry(m.Status.ok(), val, delegate, desc, "n", "n",
             "a7", 0x1000, mem)
eq(st.code, 0, "entry flag-chain ok")
eq(len(log), 1, "entry flag-chain reaches slot50")
check(log[0][0] is delegate, "entry flag-chain delegate obj")
eq(shared.use_count, 1, "entry releases local copy")
# Flags 0x400 and 0x200 also follow one link; 0 does not.
for flags in (0x400, 0x200):
    log.clear()
    delegate = make_node(slot_0x50=slot50_recorder(log))
    st = m.entry(m.Status.ok(), val, delegate,
                 m.Desc(offset=0x10, flags=flags), "n", "n",
                 "a7", 0x1000, mem)
    eq(st.code, 0, "entry flags %#x ok" % flags)
    eq(len(log), 1, "entry flags %#x slot50" % flags)
log.clear()
delegate = make_node(slot_0x50=slot50_recorder(log))
st = m.entry(m.Status.ok(), val, delegate,
             m.Desc(offset=0x10, flags=0), "n", "n", "a7",
             0x1000, mem)
eq(st.code, 0, "entry flags 0 ok")
eq(len(log), 1, "entry flags 0 slot50 (no deref)")
# Base null -> node null; the dispatch still runs.
log.clear()
delegate = make_node(slot_0x50=slot50_recorder(log))
st = m.entry(m.Status.ok(), val, delegate,
             m.Desc(offset=0, flags=0), "n", "n", "a7", None, {})
eq(len(log), 1, "entry base null still dispatches")
# flag_b1 set clears the copy's +0x04 byte (seen by slot-0x50).
seen_copy = []
def slot50_capture(out, obj, value, found, name, arg7, extra):
    seen_copy.append(value.has_value)
    return m.Status.ok()
delegate = make_node(slot_0x50=slot50_capture)
v, _ = make_value(has_value=1)
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0, flag_b1=True), "n", "n",
             "a7", None, {})
eq(seen_copy, [0], "entry flag_b1 clears copy +0x04")
# key6 == "id" -> slot-0x50.
log.clear()
delegate = make_node(slot_0x50=slot50_recorder(log))
v, _ = make_value()
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "other", "id", "a7",
             None, {})
eq(len(log), 1, "entry id key dispatches")
# name5 ends with ".id" -> slot-0x50.
log.clear()
delegate = make_node(slot_0x50=slot50_recorder(log))
v, _ = make_value()
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "thing.id", "zzz", "a7",
             None, {})
eq(len(log), 1, "entry .id suffix dispatches")
# flag_b1 clear + has_value set + node null + arg7 -> code 4.
v, _ = make_value(has_value=1)
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "nm", "other", "a7",
             None, {})
eq(st.code, 4, "entry null node + arg7 code")
eq(st.msg, "Option not changeable: : nm",
   "entry null node + arg7 msg")
# Same, arg7 empty -> success.
v, _ = make_value(has_value=1)
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "nm", "other", "",
             None, {})
eq(st.code, 0, "entry null node empty arg7 ok")
# Variant 1: node-name + "." equals key6, arg7 with '=' -> e70.
seen48.clear()
nd = make_node(
    slot_0x78=lambda o: "comp",
    slot_0x48=slot48b)
log.clear()
delegate = make_node(slot_0x50=slot50_recorder(log))
mem = {0x1000: nd}
v, _ = make_value()
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "thing", "comp.", "a=1",
             0x1000, mem)
eq(st.code, 2, "entry variant1 equals path delegates")
eq(seen48, [{"a": "1"}], "entry variant1 equals map")
eq(len(log), 0, "entry variant1 equals skips slot50")
# Variant 1: same, arg7 without '=' -> no_equals (slot-0x68).
seen68 = []
nd = make_node(
    slot_0x78=lambda o: "comp",
    slot_0x68=lambda o, k: "comp",
    slot_0x50=slot50_recorder(log),
    elements=[m.TableEntry("e", table=m.NameTable(
        [m.TableNode("comp", kind=0x13)]), field20=0x5)])
mem = {0x1000: nd}
log.clear()
v, _ = make_value()
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "thing", "comp.", "a7",
             0x1000, mem)
eq(st.code, 0, "entry variant1 no-equals ok")
eq(len(log), 1, "entry variant1 no-equals dispatches")
# Variant 1: node-name + "." differs from key6 -> slot-0x50.
log.clear()
nd = make_node(slot_0x78=lambda o: "other")
mem = {0x1000: nd}
v, _ = make_value()
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "thing", "comp.", "a7",
             0x1000, mem)
eq(len(log), 1, "entry variant1 mismatch dispatches")
# Variant 1: arg7 empty -> success (before the node-name path).
log.clear()
nd = make_node(slot_0x78=lambda o: "comp")
mem = {0x1000: nd}
v, _ = make_value()
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "thing", "comp.", "",
             0x1000, mem)
eq(st.code, 0, "entry variant1 empty arg7 ok")
eq(len(log), 0, "entry variant1 empty arg7 skips slot50")
# Variant 2: has_value set, node non-null, ".id" suffix,
# arg7 == node name -> ok; arg7 != node name -> code 4.
nd = make_node(slot_0x78=lambda o: "comp")
mem = {0x1000: nd}
v, _ = make_value(has_value=1)
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "thing.id", "zzz", "comp",
             0x1000, mem)
eq(st.code, 0, "entry variant2 name match ok")
v, _ = make_value(has_value=1)
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "thing.id", "zzz", "nope",
             0x1000, mem)
eq(st.code, 4, "entry variant2 name mismatch code")
eq(st.msg, "Option not changeable: : thing.id",
   "entry variant2 name mismatch msg")
# Variant 2: name5 == key6 -> find_norm path. arg7 "id=foo":
# find_norm returns "foo"; node name "foo" matches; map
# empty -> ok.
nd = make_node(slot_0x78=lambda o: "foo")
mem = {0x1000: nd}
v, _ = make_value(has_value=1)
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "same", "same", "id=foo",
             0x1000, mem)
eq(st.code, 0, "entry variant2 find_norm id ok")
# Same, node name differs from find_norm's out -> code 4.
nd = make_node(slot_0x78=lambda o: "bar")
mem = {0x1000: nd}
v, _ = make_value(has_value=1)
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "same", "same", "id=foo",
             0x1000, mem)
eq(st.code, 4, "entry variant2 find_norm mismatch code")
eq(st.msg, "Option not changeable: : same",
   "entry variant2 find_norm mismatch msg")
# Variant 2: name5 == key6 but arg7 has no '=': find_norm
# returns the name itself; node name equal -> ok.
nd = make_node(slot_0x78=lambda o: "plain")
mem = {0x1000: nd}
v, _ = make_value(has_value=1)
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "same", "same", "plain",
             0x1000, mem)
eq(st.code, 0, "entry variant2 find_norm plain ok")
# Variant 2: neither .id, id, nor name equality -> no_equals.
seen68.clear()
nd = make_node(
    slot_0x78=lambda o: "comp",
    slot_0x68=lambda o, k: "comp",
    slot_0x50=slot50_recorder(log),
    elements=[m.TableEntry("e", table=m.NameTable(
        [m.TableNode("comp", kind=0x15)]), field20=0x9)])
mem = {0x1000: nd}
log.clear()
v, _ = make_value(has_value=1)
st = m.entry(m.Status.ok(), v, delegate,
             m.Desc(offset=0, flags=0), "thing", "other", "a7",
             0x1000, mem)
eq(st.code, 0, "entry variant2 fallback no_equals ok")
eq(len(log), 1, "entry variant2 fallback dispatches")

# --- find_norm / parser reuse (from #3485) -----------------------------
ctx = m.OptionsMap()
st, out_s = m.find_norm("id=foo", "fb", ctx)
eq((st.code, out_s), (0, "foo"), "find_norm id path")
ctx = m.OptionsMap()
st = m.parse_options("a=1;b=2", ctx)
eq(st.code, 0, "parse_options ok")
eq(sorted(ctx.items()), [("a", "1"), ("b", "2")],
   "parse_options pairs")
ctx = m.OptionsMap()
st = m.parse_options("a;1", ctx)
eq(st.code, 4, "parse_options bad pair")

print("ALL %d CHECKS PASSED" % CHECKS)
