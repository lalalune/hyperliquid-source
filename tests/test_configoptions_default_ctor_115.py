"""Tests for tools/configoptions_default_ctor_115.py.

Grounds: the ConfigOptions default ctor 0x60bb890, the dtor 0x5e33fb0,
ObjectRegistry::NewInstance 0x61f9400 and the nine construction sites
in research/work-items/RE-001-configoptions-default-ctor-115/.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import configoptions_default_ctor_115 as m

N = 0


def check(cond, what):
    global N
    N += 1
    if not cond:
        raise AssertionError(what)


# --- ctor defaults -------------------------------------------------------
cfg = m.ConfigOptions.default()
check(cfg.flags() == (0, 1, 1, 1, 0), "flag defaults 0,1,1,1,0")
check(cfg.delimiter == ";", "delimiter default ';'")
check(len(cfg.delimiter) == 1, "delimiter length 1")
check(cfg.scalar28 == 0, "scalar28 default 0")
check(cfg.scalar2c == 0xFF, "scalar2c default 0xff")
check(cfg.scalar30 == 0x80000, "scalar30 default 0x80000")
check(cfg.scalar30 == 524288, "scalar30 decimal 524288")
check(cfg.env is m.Env.Default(), "env is Env::Default()")
check(m.Env.Default() is m.Env.Default(), "Env::Default() singleton")
check(cfg.registry.ptr is not None, "registry ptr set")
check(cfg.registry.ptr.parent is m.ObjectRegistry.Default(),
      "registry parent is the Default singleton")
check(cfg.registry.ptr.parent is not cfg.registry.ptr,
      "registry is a fresh child, not the singleton")
check(cfg.registry.cb.use_count == 1, "control block use 1")
check(cfg.registry.cb.weak_count == 1, "control block weak 1")
check(cfg.registry.cb.vtable == 0x64D8F00, "control block vtable")
check(cfg.registry.cb.SIZE == 0xD0, "control block size 0xd0")
check(cfg.registry.ptr.zeroed == (0x70, 0xB8),
      "zeroed region +0x70..+0xb7")
check(cfg.registry.ptr.SIZE == 0xC0, "registry size 0xc0")
check(m.SIZE_BYTES == 0x50, "ConfigOptions size 0x50")

# A second ConfigOptions is an independent object: fresh child registry.
cfg2 = m.ConfigOptions.default()
check(cfg2.registry.ptr is not cfg.registry.ptr,
      "two ctors give two child registries")
check(cfg2.registry.ptr.parent is m.ObjectRegistry.Default(),
      "both children parented at Default")
check(cfg2.env is cfg.env, "both share Env::Default()")

# --- NewInstance ---------------------------------------------------------
sp = m.ObjectRegistry.NewInstance()
check(sp.ptr.parent is m.ObjectRegistry.Default(), "NewInstance parent")
check(sp.ptr.zeroed == (0x70, 0xB8), "NewInstance zeroed region")
check(sp.cb.use_count == 1 and sp.cb.weak_count == 1,
      "NewInstance packed counts (1,1)")
check(sp.ptr.libraries == [] and sp.ptr.names == [] and sp.ptr.map == {},
      "NewInstance empty libraries/names/map")

# --- dtor ----------------------------------------------------------------
trace = cfg.destroy()
check(trace[0] == "release: (1,1) fast path",
      "dtor releases the registry first")
check(trace[1].startswith("dispose:"), "dtor disposes the registry block")
check(trace[2] == "destroy: operator delete 0xd0",
      "dtor destroys the control block")
check(trace[3] == "dispose delimiter: SSO, no free",
      "dtor disposes the SSO delimiter last")
check(cfg.registry.cb.disposed and cfg.registry.cb.destroyed,
      "dtor leaves the block disposed and destroyed")
check(cfg.registry.cb.use_count == 0, "dtor leaves use 0")
check(cfg.env is m.Env.Default(), "dtor does not release env")

# Heap delimiter: a long delimiter is freed, not SSO-skipped.
cfg3 = m.ConfigOptions.default()
cfg3.delimiter = "\n  " + "x" * 20
trace3 = cfg3.destroy()
check(trace3[-1] == "dispose delimiter: heap buffer freed",
      "long delimiter heap-freed by the dtor")

# --- _M_release paths ----------------------------------------------------
cb = m.ControlBlock(object(), vtable=0x64D8F00)
cb.use_count = 3
sp2 = m.SharedPtr(object(), cb)
t = []
sp2.release(t, selector_zero=True)
check(t == ["release: selector 0, lock addl -1"], "selector-0 decrement")
check(cb.use_count == 2, "decrement leaves use 2")
check(not cb.disposed, "no dispose on a shared release")
t = []
sp2.release(t, selector_zero=False)
check(t == ["release: selector non-zero, plain addl -1"],
      "selector non-zero decrement")
check(cb.use_count == 1, "second decrement leaves use 1")
check(not cb.disposed, "still no dispose with one owner left")
t = []
sp2.release(t)
check(t[0] == "release: (1,1) fast path", "last owner takes the fast path")
check(cb.disposed and cb.destroyed, "fast path disposes and destroys")

# Last use with weak references outstanding goes through the cold path:
# dispose happens, weak drops by one, destroy waits for the last weak.
cb2 = m.ControlBlock(object(), vtable=0x64D8F00)
cb2.use_count = 1
cb2.weak_count = 2
t = []
m.SharedPtr(object(), cb2).release(t)
check(t[0] == "release: selector 0, lock addl -1",
      "cold path first decrements with the selector path")
check(t[1] == "release: last use, _M_release_last_use_cold",
      "last use with weak>1 goes through the cold path")
check(cb2.disposed and not cb2.destroyed,
      "cold path disposes but does not destroy while weak>0")
check(cb2.use_count == 0 and cb2.weak_count == 1,
      "cold path leaves use 0, weak 1")

# Null control block release is a no-op.
t = []
m.SharedPtr(None, None).release(t)
check(t == ["release: null control block, return"], "null release no-op")

# --- Persist field-by-field copy ----------------------------------------
src = m.ConfigOptions.default()
src.apply_override("+0x04", 1)
src.apply_override("+0x08", "\n  ")
src.apply_override("+0x30", 0x1234)
t = []
dst = src.copy(t)
check(dst.flags() == src.flags(), "copy carries flags")
check(dst.delimiter == "\n  ", "copy carries delimiter")
check(dst.scalar28 == 0 and dst.scalar2c == 0xFF, "copy carries scalars")
check(dst.scalar30 == 0x1234, "copy carries +0x30")
check(dst.env is src.env, "copy shares the env pointer")
check(dst.registry.ptr is src.registry.ptr, "copy shares the registry ptr")
check(dst.registry.cb is src.registry.cb, "copy shares the control block")
check(src.registry.cb.use_count == 2, "copy bumps the use count")
check(t == ["copy delimiter via string copy helper",
            "copy registry: use-count bump"], "copy trace order")
check(dst is not src, "copy is a distinct object")

# --- the nine sites ------------------------------------------------------
check(len(m.SITES) == 9, "nine construction sites")
want = {
    "0x5d8eacf": ((0, 1, 1, 1, 1), ";", 0x80000),
    "0x5e3406f": ((0, 1, 1, 0, 0), ";", 0x80000),
    "0x5e34458": ((1, 1, 1, 0, 0), ";", 0x80000),
    "0x5ffad84": ((0, 1, 1, 1, 0), ";", 0x80000),
    "0x60a1dcf": ((0, 1, 1, 1, 0), ";", 0x80000),
    "0x60a20cd": ((0, 1, 1, 1, 0), ";", 0x80000),
    "0x60d4a48": ((0, 1, 1, 0, 0), "\n  ", 0x80000),
    "0x612073b": ((0, 1, 1, 1, 0), ";", 0x80000),
    "0x61c83aa": ((0, 1, 1, 1, 0), ";", 0x80000),
}
for site, host, _addr, overrides, consumer in m.SITES:
    cfg = m.site_config(site)
    flags, delim, s30 = want[site]
    check(cfg.flags() == flags, "site %s flags" % site)
    check(cfg.delimiter == delim, "site %s delimiter" % site)
    check(cfg.scalar30 == s30, "site %s scalar30" % site)
    check(cfg.scalar28 == 0 and cfg.scalar2c == 0xFF,
          "site %s scalars untouched" % site)
    check(cfg.env is m.Env.Default(), "site %s env" % site)
    check(cfg.registry.ptr.parent is m.ObjectRegistry.Default(),
          "site %s registry parent" % site)
    check(host and consumer, "site %s has host and consumer" % site)

# Site consumers are distinct and cover the expected families.
consumers = [c for *_r, c in m.SITES]
check(len(set(consumers)) == 9, "nine distinct consumers")
check("0x60c4550" in consumers[0], "SetOptions consumer is the helper")
check("0x60c1bb0" in consumers[2], "Read consumer is ParseType")
check("0x61ca3d0" in consumers[7], "bbtopen consumer is the create host")

# AsString's delimiter re-assignment is a no-op.
check(m.site_config("0x61c83aa").delimiter == m.DELIMITER_DEFAULT,
      "AsString delimiter re-assignment changes nothing")

# --- bbtopen gate --------------------------------------------------------
check(m.bbtopen_gate(True, False) is True, "gate: name, no transform")
check(m.bbtopen_gate(True, True) is False, "gate: name, transform present")
check(m.bbtopen_gate(False, False) is False, "gate: no name")
check(m.bbtopen_gate(False, True) is False, "gate: no name, transform")

# --- Persist +0x30 conditional ------------------------------------------
check(m.persist_scalar30(None) == 0x80000, "Persist keeps default on null")
check(m.persist_scalar30(0x9999) == 0x9999, "Persist overwrites on non-null")

# --- unknown offset guard ------------------------------------------------
try:
    m.ConfigOptions.default().apply_override("+0x99", 1)
    raise AssertionError("unknown offset accepted")
except ValueError:
    pass
try:
    m.site_config("0x0")
    raise AssertionError("unknown site accepted")
except ValueError:
    pass

print("%d tests passed" % N)
