"""Tests for tools/composite_env_wrapper_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_composite_env_wrapper_115.py

Every expectation is grounded in the RE-001-composite-env-wrapper-115
evidence packet: the builder/install/dtor roles, the slot 5/12/14/16/17
overrides, the 20 forwarder slots, the holder initializer, the node
slot-2 forwarding and the control-block dispose/destroy pair, with
the shared_ptr release rule and the options-vector rules from the
RE-001-systemclock-installers-115 packet.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from composite_env_wrapper_115 import (
    BASE_SIZE, CONFIGURABLE_VTABLE, COMPOSITE_ENV_VTABLE,
    DSO_HANDLE, ENV_VTABLE, FACTORY_ALLOC, FACTORY_CB_VTABLE,
    FLOAT_ONE_ADDR, FORWARDERS, FRESH_COUNTS, HOLDER,
    HOLDER_GUARD, MOCK_DIFF_SLOTS, MOCK_ENV_VTABLE, MUTEX_NAME,
    MUTEX_NAME_ADDR, NAME_STRING, NAME_STRING_ADDR, NODE_VTABLE,
    RECORD_GLOBALS, RECORD_SIZE, SELECTOR_CELL, TARGET_PREFIX,
    TARGET_PREFIX_ADDR, TSU_DTOR, TSU_OBJECT, TSU_VTABLE,
    WRAPPER_DIFF_SLOTS, WRAPPER_SIZE, WRAPPER_VTABLE,
    CompositeEnv, CompositeEnvWrapper, ControlBlock,
    DefaultHolder, Env, FactoryControlBlock, OptionsVector,
    RegistryNode, SharedPtr, ThreadStatusUpdater,
    dispose_tail, holder_accessor, release_with_prior_decrement,
    selector_is_atomic,
)

CHECKS = 0


def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(label)


def eq(actual, expected, label):
    check(actual == expected, "%s: %r != %r" % (label, actual, expected))


# --- constants ------------------------------------------------------------

eq(ENV_VTABLE, 0x64CDAD0, "Env vtable address")
eq(COMPOSITE_ENV_VTABLE, 0x64CE2D8, "CompositeEnv vtable address")
eq(WRAPPER_VTABLE, 0x64CE590, "wrapper vtable address")
eq(CONFIGURABLE_VTABLE, 0x64D3430, "Configurable vtable address")
eq(MOCK_ENV_VTABLE, 0x64D1398, "MockEnv vtable address")
eq(NODE_VTABLE, 0x64CDE68, "registry node vtable address")
eq(FACTORY_CB_VTABLE, 0x64D1C38, "factory control-block vtable")
eq(TSU_VTABLE, 0x64CE8E0, "ThreadStatusUpdater vtable address")
eq(WRAPPER_SIZE, 0x60, "wrapper size")
eq(BASE_SIZE, 0x50, "base size")
eq(RECORD_SIZE, 0x30, "record size")
eq(FACTORY_ALLOC, 0x60, "factory allocation")
eq(FRESH_COUNTS, 0x100000001, "fresh counts (1, 1)")
eq(SELECTOR_CELL, 0x64ED290, "selector cell address")
eq(RECORD_GLOBALS, (0x6504C60, 0x6504C20, 0x6504BE0), "record globals")
eq(HOLDER, 0x6504CC0, "default holder address")
eq(HOLDER_GUARD, 0x6504CA8, "holder guard address")
eq(TSU_OBJECT, 0x6504CE0, "ThreadStatusUpdater address")
eq(TSU_DTOR, 0x5FE2C30, "TSU atexit dtor")
eq(DSO_HANDLE, 0x64EFA20, "DSO handle")
eq(NAME_STRING, "CompositeEnv", "name string")
eq(NAME_STRING_ADDR, 0x43E762, "name string address")
eq(TARGET_PREFIX, "target=", "target prefix")
eq(TARGET_PREFIX_ADDR, 0x4496D1, "target prefix address")
eq(MUTEX_NAME, "mutex_init", "mutex name")
eq(MUTEX_NAME_ADDR, 0x4429A3, "mutex name address")
eq(FLOAT_ONE_ADDR, 0x459E78, "float 1.0 address")
eq(len(WRAPPER_DIFF_SLOTS), 27, "27 wrapper diff slots")
eq(len(MOCK_DIFF_SLOTS), 3, "3 MockEnv diff slots")
eq(MOCK_DIFF_SLOTS, (0, 1, 14), "MockEnv differs in 0, 1, 14")
check(selector_is_atomic(0), "selector 0 is atomic")
check(not selector_is_atomic(1), "selector 1 is plain")
check(not selector_is_atomic(0xFF), "selector 0xff is plain")

# The 20 forwarder slots: exact set, forms, and target offsets.
eq(sorted(FORWARDERS),
   [45, 46, 47, 48, 49, 50, 51, 52, 59, 63, 64, 65, 66, 67, 68, 69, 71,
    79, 80, 81], "20 forwarder slots")
call_form = sorted(s for s, (_a, f) in FORWARDERS.items() if f == "call")
eq(call_form, [45, 59, 65, 68, 71, 79], "call-form forwarder slots")
jmp_form = sorted(s for s, (_a, f) in FORWARDERS.items() if f == "jmp")
eq(jmp_form, [46, 47, 48, 49, 50, 51, 52, 63, 64, 66, 67, 69, 80, 81],
   "jmp-form forwarder slots")
eq(FORWARDERS[45][0], 0x5FD4E80, "slot 45 address")
eq(FORWARDERS[81][0], 0x5FD51B0, "slot 81 address")
eq(FORWARDERS[65][0], 0x5FD5040, "slot 65 address")
for slot, (_addr, _form) in FORWARDERS.items():
    check(slot * 8 < 0x1000, "slot %d target offset fits" % slot)

# --- shared_ptr -----------------------------------------------------------

cb = ControlBlock(use=1, weak=1)
eq(cb.counts, 0x100000001, "fresh counts pack to (1, 1)")
cb2 = ControlBlock(use=3, weak=2)
eq(cb2.counts, 0x200000003, "counts pack (3, 2)")

# Copy bumps the use count and shares the control block.
sp = SharedPtr("obj", ControlBlock(use=1, weak=1))
copy = sp.copy()
eq(sp.control.use, 2, "copy bumps use to 2")
check(copy.control is sp.control, "copy shares the control block")
check(copy.obj == "obj", "copy shares the object")

# Release fast path: (1, 1) disposes and destroys with no traffic.
sp = SharedPtr("obj", ControlBlock(use=1, weak=1))
ctrl = sp.control
eq(sp.release(), ["dispose", "destroy"], "fast-path release events")
check(ctrl.disposed, "fast path disposed")
check(ctrl.destroyed, "fast path destroyed")
check(sp.obj is None and sp.control is None, "released pointer cleared")

# Release slow path: use 2 -> 1, no dispose; then at (1, 1) the fast
# path disposes and destroys.
sp = SharedPtr("obj", ControlBlock(use=2, weak=1))
ctrl = sp.control
eq(sp.release(), [], "release at use 2 is silent")
eq(ctrl.use, 1, "use decremented to 1")
sp2 = SharedPtr("obj", ctrl)
eq(sp2.release(), ["dispose", "destroy"],
   "last-use release at (1, 1) takes the fast path")
check(ctrl.disposed, "last-use disposed")
check(ctrl.destroyed, "last-use destroyed at weak 1")

# Last use at weak 2 goes through the dispose tail: dispose, weak--,
# no destroy.
sp = SharedPtr("obj", ControlBlock(use=1, weak=2))
ctrl = sp.control
eq(sp.release(), ["dispose", "weak--"],
   "last-use release at weak 2 runs the dispose tail")
check(ctrl.disposed, "dispose-tail disposed")
check(not ctrl.destroyed, "dispose-tail kept the block at weak 2")

# Weak count 2: dispose happens, control block survives.
sp = SharedPtr("obj", ControlBlock(use=1, weak=2))
ctrl = sp.control
eq(sp.release(), ["dispose", "weak--"], "weak 2: dispose, no destroy")
check(ctrl.disposed, "weak-2 disposed")
check(not ctrl.destroyed, "weak-2 not destroyed")
eq(ctrl.weak, 1, "weak decremented to 1")

# Null control block: release is a no-op.
sp = SharedPtr("obj", None)
eq(sp.release(), [], "null control release is silent")

# The dispose tail directly: weak 1 destroys, weak 2 does not.
ctrl = ControlBlock(use=0, weak=1)
eq(dispose_tail(ctrl), ["dispose", "weak--", "destroy"],
   "dispose tail at weak 1 destroys")
ctrl = ControlBlock(use=0, weak=3)
eq(dispose_tail(ctrl), ["dispose", "weak--"],
   "dispose tail at weak 3 keeps the block")
eq(ctrl.weak, 2, "dispose tail decremented weak to 2")

# Holder-init temp release: fast path and slow path.
ctrl = ControlBlock(use=1, weak=1)
eq(release_with_prior_decrement(ctrl), ["dispose", "destroy"],
   "temp release fast path")
ctrl = ControlBlock(use=3, weak=1)
eq(release_with_prior_decrement(ctrl), [],
   "temp release at use 3 is silent")
eq(ctrl.use, 2, "temp release decremented use to 2")
ctrl = ControlBlock(use=1, weak=2)
eq(release_with_prior_decrement(ctrl), ["dispose", "weak--"],
   "temp release last-use at weak 2")

# --- options vector -------------------------------------------------------

vec = OptionsVector()
rec = vec.append("", "this+0x48", 0x6504C60)
eq(rec, {"name": "", "ptr1": "this+0x48", "ptr2": 0x6504C60, "heap": False},
   "empty-name record is SSO")
eq(vec.capacity, 1, "first append grows to capacity 1")
vec.append("", "this+0x28", 0x6504C20)
eq(vec.capacity, 2, "second append doubles capacity")
eq(len(vec.records), 2, "two records stored")
long_rec = vec.append("a" * 16, "p", 0)
check(long_rec["heap"], "16-char name is heap-allocated")
eq(vec.capacity, 4, "third append doubles capacity to 4")
try:
    vec.capacity = OptionsVector.MAX_CAPACITY
    vec.grow()
    check(False, "grow past max must raise")
except OverflowError:
    check(True, "grow past max raises OverflowError")
vec2 = OptionsVector()
vec2.append("x", 1, 2)
vec2.append("y" * 20, 3, 4)
eq(vec2.destroy(), 2, "destroy disposes 2 records")
eq(vec2.records, [], "destroy empties the vector")
check(vec2.buffer_freed, "destroy frees the buffer")

# --- install helper -------------------------------------------------------

obj = CompositeEnv()
sp_a = SharedPtr("a", ControlBlock(use=1, weak=1))
sp_b = SharedPtr("b", ControlBlock(use=2, weak=1))
CompositeEnv.install(obj, sp_a, sp_b)
eq(obj.vtable, ENV_VTABLE, "install sets the Env vtable")
check(obj.sp_a.obj == "a" and obj.sp_b.obj == "b",
      "install copies both shared_ptrs")
eq(obj.sp_a.control.use, 2, "install bumps sp_a use")
eq(obj.sp_b.control.use, 3, "install bumps sp_b use")
eq(len(obj.options.records), 0, "install starts with an empty vector")

obj2 = CompositeEnv()
CompositeEnv.install(obj2, None, None)
check(obj2.sp_a is None and obj2.sp_b is None,
      "install with null shared_ptrs keeps them null")

# --- builder --------------------------------------------------------------

wrapped = Env()
sp_a = SharedPtr("a", ControlBlock(use=1, weak=1))
sp_b = SharedPtr("b", ControlBlock(use=1, weak=1))
w = CompositeEnvWrapper.builder(wrapped, sp_a, sp_b)
eq(w.vtable, WRAPPER_VTABLE, "builder installs the wrapper vtable")
check(w.wrapped is wrapped, "builder stores the wrapped env at +0x48")
check(w.sp_c is None, "builder zeroes shared_ptr C")
eq(w.size, WRAPPER_SIZE, "wrapper is 0x60 bytes")
eq(len(w.options.records), 3, "builder appends three records")
eq(w.options.records[0],
   {"name": "", "ptr1": "this+0x48", "ptr2": 0x6504C60, "heap": False},
   "record 0 is the wrapped-env slot")
eq(w.options.records[1],
   {"name": "", "ptr1": "this+0x28", "ptr2": 0x6504C20, "heap": False},
   "record 1 is the sp_a slot")
eq(w.options.records[2],
   {"name": "", "ptr1": "this+0x38", "ptr2": 0x6504BE0, "heap": False},
   "record 2 is the sp_b slot")
eq(w.sp_a.control.use, 2, "builder bumps sp_a via install")
eq(w.sp_b.control.use, 2, "builder bumps sp_b via install")

# Builder with null shared_ptrs (the MockEnv ctor pass-through shape).
w2 = CompositeEnvWrapper.builder(Env(), None, None)
eq(len(w2.options.records), 3, "null-arg builder still appends 3 records")
check(w2.sp_a is None and w2.sp_b is None, "null-arg builder keeps nulls")

# --- destructors ----------------------------------------------------------

# Wrapper D2: releases sp_c (last owner), then the base D2 drops
# sp_b and sp_a — but the builder bumped those, so the wrapper is
# not their last owner and they only decrement.
ctrl_a = ControlBlock(use=1, weak=1)
ctrl_b = ControlBlock(use=1, weak=1)
w = CompositeEnvWrapper.builder(Env(), SharedPtr("a", ctrl_a),
                                SharedPtr("b", ctrl_b))
w.sp_c = SharedPtr("c", ControlBlock(use=1, weak=1))
events = w.dtor_d2()
eq(events, ["dispose", "destroy", "vector-destroy:3"],
   "wrapper D2 releases C then the vector")
eq(ctrl_a.use, 1, "D2 dropped sp_a use back to 1")
eq(ctrl_b.use, 1, "D2 dropped sp_b use back to 1")
eq(w.vtable, CONFIGURABLE_VTABLE, "D2 ends on the Configurable vtable")
check(w.sp_a is None and w.sp_b is None and w.sp_c is None,
      "D2 clears all shared_ptrs")

# Wrapper D0 adds operator delete 0x60.
w = CompositeEnvWrapper.builder(Env(), None, None)
events = w.dtor_d0()
eq(events[-1], "delete:0x60", "D0 ends with operator delete 0x60")
check("vector-destroy:3" in events, "D0 runs the D2 body")

# Base D2 alone with last ownership: B before A, then the vector.
base = CompositeEnv()
base.sp_a = SharedPtr("a", ControlBlock(use=1, weak=1))
base.sp_b = SharedPtr("b", ControlBlock(use=1, weak=1))
base.options.append("x", 1, 2)
events = base.dtor_d2()
eq(events, ["dispose", "destroy", "dispose", "destroy",
            "vector-destroy:1"], "base D2 releases B, then A, then vector")
eq(base.vtable, CONFIGURABLE_VTABLE, "base D2 installs Configurable")

# D2 with shared (non-last) owners: no dispose, counts drop by one.
shared_ctrl = ControlBlock(use=3, weak=1)
w = CompositeEnvWrapper.builder(
    Env(), SharedPtr("a", shared_ctrl), None)
ctrl_c = ControlBlock(use=2, weak=1)
w.sp_c = SharedPtr("c", ctrl_c)
events = w.dtor_d2()
eq(events, ["vector-destroy:3"], "shared owners: D2 is silent")
eq(shared_ctrl.use, 3, "shared sp_a use back to 3 (3, bump, release)")
eq(ctrl_c.use, 1, "shared sp_c use dropped to 1")

# --- slot 5 PrepareOptions ------------------------------------------------

holder_env = Env(wrapped=Env(), sp_a=SharedPtr("ha", ControlBlock(1, 1)),
                 sp_b=SharedPtr("hb", ControlBlock(1, 1)),
                 is_default_holder=True)
holder = Env(wrapped=holder_env)

# Target with sp_c set: wrapped comes from sp_c.
from_c_env = Env()
target = Env(sp_c=SharedPtr(from_c_env, ControlBlock(1, 1)))
w = CompositeEnvWrapper()
events = w.prepare_options(target, options=None, holder=holder)
check("wrapped-from-sp-c" in events, "slot 5 takes wrapped from sp_c")
check(target.wrapped is from_c_env, "slot 5 stored the sp_c object")

# Target with +0x48 already set: kept as-is.
inner = Env()
target = Env(wrapped=inner)
events = w.prepare_options(target, options=None, holder=holder)
check("wrapped-kept" in events, "slot 5 keeps an existing wrapped env")
check(target.wrapped is inner, "slot 5 did not replace the wrapped env")

# Target with neither: falls back to the holder.
target = Env()
events = w.prepare_options(target, options=None, holder=holder)
check("wrapped-from-holder" in events, "slot 5 falls back to the holder")
check(target.wrapped is holder_env, "slot 5 stored the holder env")

# sp_a copy-in when target sp_a is null.
src_a = SharedPtr("sa", ControlBlock(use=1, weak=1))
wrapped_env = Env(sp_a=src_a)
target = Env(wrapped=wrapped_env)
w.prepare_options(target, options=None, holder=holder)
check(target.sp_a is not None, "slot 5 copied sp_a in")
eq(target.sp_a.obj, "sa", "slot 5 copied the right sp_a object")
eq(src_a.control.use, 2, "slot 5 bumped the copied sp_a use")

# sp_b copy-in when target sp_b is null.
src_b = SharedPtr("sb", ControlBlock(use=1, weak=1))
wrapped_env = Env(sp_b=src_b)
target = Env(wrapped=wrapped_env)
w.prepare_options(target, options=None, holder=holder)
check(target.sp_b is not None, "slot 5 copied sp_b in")
eq(target.sp_b.obj, "sb", "slot 5 copied the right sp_b object")
eq(src_b.control.use, 2, "slot 5 bumped the copied sp_b use")

# Already-set sp_a/sp_b are left alone (no double bump).
src_a = SharedPtr("sa", ControlBlock(use=1, weak=1))
src_b = SharedPtr("sb", ControlBlock(use=1, weak=1))
wrapped_env = Env(sp_a=src_a, sp_b=src_b)
target = Env(wrapped=wrapped_env, sp_a=SharedPtr("ta", ControlBlock(1, 1)),
             sp_b=SharedPtr("tb", ControlBlock(1, 1)))
w.prepare_options(target, options=None, holder=holder)
eq(src_a.control.use, 1, "slot 5 does not bump an already-set sp_a")
eq(src_b.control.use, 1, "slot 5 does not bump an already-set sp_b")
check("base-prepare-options" in
      w.prepare_options(Env(wrapped=Env()), options=None, holder=holder),
      "slot 5 always tail-calls the base PrepareOptions")

# --- slot 12 SerializeOptions ----------------------------------------------

w = CompositeEnvWrapper()


def fake_serialize(wrapped_env, options):
    return "<wrapped:%s>" % wrapped_env.tag


plain = Env()
eq(w.serialize_options([], plain, None, fake_serialize),
   "base-serialization", "slot 12 with no wrapped env is base only")

holder_wrapped = Env(is_default_holder=True)
env_with_holder = Env(wrapped=holder_wrapped)
eq(w.serialize_options([], env_with_holder, None, fake_serialize),
   "base-serialization", "slot 12 skips the default holder")

real = Env(tag="real-env")
env_with_real = Env(wrapped=real)
eq(w.serialize_options([], env_with_real, None, fake_serialize),
   "base-serializationtarget=<wrapped:real-env>",
   "slot 12 appends target= plus the wrapped serialization")

# --- slots 14/16/17 ---------------------------------------------------------

eq(w.name(), "CompositeEnv", "slot 14 returns CompositeEnv")
eq(w.is_instance_of("CompositeEnv"), 1, "slot 16 matches CompositeEnv")
eq(w.is_instance_of("MockEnv"), 0, "slot 16 rejects MockEnv")
eq(w.is_instance_of("CompositeEn"), 0, "slot 16 rejects a short string")
eq(w.is_instance_of("CompositeEnvX"), 0, "slot 16 rejects a long string")
eq(w.is_instance_of(""), 0, "slot 16 rejects an empty string")
inner = Env()
w3 = CompositeEnvWrapper.builder(inner, None, None)
check(w3.wrapped_env() is inner, "slot 17 returns this+0x48")

# --- forwarders -------------------------------------------------------------

for slot, (addr, form) in FORWARDERS.items():
    target_calls = []

    def target_fn(wrapped_env, *args, _slot=slot, _calls=target_calls):
        _calls.append(wrapped_env)
        return "slot-%d-result" % _slot

    w = CompositeEnvWrapper.builder(Env(), None, None)
    if form == "jmp":
        got_form, result = w.forward(slot, target=target_fn)
        eq(got_form, "jmp", "slot %d is jmp-form" % slot)
        eq(result, "slot-%d-result" % slot, "slot %d forwards the result"
           % slot)
        check(target_calls[0] is w.wrapped,
              "slot %d forwards this+0x48" % slot)
    else:
        arg_env = Env(wrapped=Env())
        got_form, result = w.forward(slot, target=target_fn,
                                     arg_env=arg_env)
        eq(got_form, "call", "slot %d is call-form" % slot)
        check(result is w, "slot %d call-form returns this" % slot)
        check(target_calls[0] is arg_env.wrapped,
              "slot %d forwards arg+0x48" % slot)

# The forwarder target offset is always slot*8.
for slot in (45, 59, 65, 68, 71, 79):
    eq(slot * 8, {45: 0x168, 59: 0x1D8, 65: 0x208, 68: 0x220, 71: 0x238,
                  79: 0x278}[slot], "slot %d dispatch offset" % slot)

eq(CompositeEnvWrapper.mock_env_vtable_differs(), (0, 1, 14),
   "MockEnv differs from the wrapper in 0, 1, 14 only")

# --- holder initializer ------------------------------------------------------

holder_obj = DefaultHolder()
check(not holder_obj.initialized, "holder starts uninitialized")
events = holder_obj.initialize(
    SharedPtr("clock", ControlBlock(use=1, weak=1)),
    SharedPtr("fs", ControlBlock(use=1, weak=1)))
eq(events, ["holder-installed", "records-built:4", "tsu-built",
            "atexit-registered", "guard-released"],
   "holder init events in order")
check(holder_obj.initialized, "holder is initialized after init")
check(holder_obj.guard_released, "holder released the guard")
check(holder_obj.atexit_registered, "holder registered __cxa_atexit")
eq(holder_obj.records, ["record-0", "record-1", "record-2", "record-3"],
   "holder built the 4-entry record array")
eq(holder_obj.mutex_name, "mutex_init", "holder mutex is mutex_init")
eq(holder_obj.initialize(SharedPtr("c", ControlBlock(1, 1)),
                         SharedPtr("f", ControlBlock(1, 1))),
   ["already-initialized"], "second init is a no-op")
tsu = holder_obj.tsu
eq(tsu.vtable, TSU_VTABLE, "TSU vtable")
eq(tsu.field_38, 1, "TSU +0x38 is 1")
eq(tsu.field_70, 1, "TSU +0x70 is 1")
eq(tsu.field_a8, 1, "TSU +0xA8 is 1")
eq(tsu.float_50, 1.0, "TSU +0x50 float is 1.0")
eq(tsu.float_88, 1.0, "TSU +0x88 float is 1.0")
eq(tsu.float_c0, 1.0, "TSU +0xC0 float is 1.0")
eq(tsu.ptr_30, TSU_OBJECT + 0x60, "TSU +0x30 self-pointer")
eq(tsu.ptr_68, TSU_OBJECT + 0x98, "TSU +0x68 self-pointer")
eq(tsu.ptr_a0, TSU_OBJECT + 0xD0, "TSU +0xA0 self-pointer")
eq(len(tsu.field_map()), 9, "TSU has 9 pinned non-zero fields")

# --- registry node and control block -----------------------------------------

class FakeEntry:
    def slot2(self, *args):
        return ("entry-slot2", args)


node = RegistryNode(FakeEntry())
eq(node.vtable, NODE_VTABLE, "node vtable")
eq(node.slot2(7), ("entry-slot2", (7,)),
   "node slot 2 forwards entry+0x08's slot 2")


class FakeManaged:
    def __init__(self):
        self.dtor_calls = 0

    def dtor_d2(self):
        self.dtor_calls += 1


managed = FakeManaged()
fcb = FactoryControlBlock(managed)
eq(fcb.vtable, FACTORY_CB_VTABLE, "factory control-block vtable")
fcb.dispose()
eq(managed.dtor_calls, 1, "cb dispose calls the managed D2")
check(fcb.disposed, "cb dispose marked")
fcb.destroy()
check(fcb.destroyed, "cb destroy marked")

# The accessor returns the holder's +0x38 slot.
holder_env = Env(sp_b=SharedPtr("hb", ControlBlock(1, 1)))
check(holder_accessor(holder_env) is holder_env.sp_b,
      "accessor returns arg+0x38")

print("ALL CHECKS PASSED (%d checks)" % CHECKS)
