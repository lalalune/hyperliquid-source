"""Tests for tools/systemclock_installers_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_systemclock_installers_115.py

Every expectation is grounded in the RE-001-systemclock-
installers-115 evidence packet: the installer roles, the
append/grow rules, the shared_ptr release rule, the mode 0/1
factory paths, the manager op dispatch and the invoker swap.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from systemclock_installers_115 import (
    BASE_VTABLE, EMULATED_SIZE, EMULATED_VTABLE, ENTRY_VTABLE,
    FACTORY_ALLOC, FACTORY_COUNTS, FACTORY_CB_VTABLE,
    FACTORY_ENTRY_HEADERS, INVOKERS, NODE_VTABLE, RECORD_SIZE,
    THUNKS, WRAPPER_SIZE, WRAPPER_VTABLE, ControlBlock,
    EmulatedClock, OptionsVector, Registry, RegistryEntry,
    RegistryNode, SharedPtr, ThunkFunction, Wrapper,
    holder_accessor, invoker_swap, last_use_helper,
    make_shared_emulated, manager_dispatch, scaled_add,
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

eq(WRAPPER_VTABLE, 0x64CDD88, "wrapper vtable address")
eq(EMULATED_VTABLE, 0x64D1650, "emulated vtable address")
eq(BASE_VTABLE, 0x64D3420 + 0x10, "base vtable address")
eq(NODE_VTABLE, 0x64CDE68, "registry node vtable address")
eq(ENTRY_VTABLE, 0x64D8ED0, "registry entry vtable address")
eq(FACTORY_CB_VTABLE, 0x64D1C38, "factory control-block vtable")
eq(WRAPPER_SIZE, 0x30, "wrapper size")
eq(EMULATED_SIZE, 0x50, "emulated size")
eq(RECORD_SIZE, 0x30, "record size")
eq(FACTORY_ALLOC, 0x60, "factory allocation")
eq(FACTORY_COUNTS, 0x100000001, "factory counts (1, 1)")
eq(len(FACTORY_ENTRY_HEADERS), 5, "five FactoryEntry headers")
eq(sorted(THUNKS), [0x5FCC5D0, 0x5FCC600, 0x5FCC630], "three thunks")
eq(THUNKS[0x5FCC5D0], 0x64CD9D0, "MockEnv thunk vtable")
eq(THUNKS[0x5FCC600], 0x64CD9E0, "CompositeEnv thunk vtable")
eq(THUNKS[0x5FCC630], 0x64CD9F0, "TimeEmulated thunk vtable")
eq(INVOKERS["TimeEmulatedSystemClock"][2], 0, "time-emu invoker mode 0")
eq(INVOKERS["MockEnv"][0], 0x5FCD5B0, "MockEnv invoker address")
eq(INVOKERS["CompositeEnv"][0], 0x5FCF450, "CompositeEnv invoker address")

# --- scaled_add (from the canonical packet's model) ------------------------

eq(scaled_add(0), 0, "scaled_add(0)")
eq(scaled_add(2 ** 40), 1099511, "scaled_add(2**40)")
check(scaled_add(2 ** 60) > 0, "scaled_add(2**60) positive")
check(scaled_add(-1) == 0, "scaled_add(-1) rounds to 0")
check(scaled_add(-(2 ** 40)) < 0, "scaled_add(-2**40) negative")

# --- shared_ptr release ----------------------------------------------------

cb = ControlBlock(use=2, weak=1)
eq(last_use_helper(cb), [], "use 2 -> 1: no events")
eq(cb.use, 1, "use count decremented")
eq(cb.disposed, False, "not disposed yet")
eq(last_use_helper(cb), ["dispose", "weak--", "destroy"],
   "last use: dispose, weak--, destroy")
check(cb.disposed, "disposed at last use")
check(cb.destroyed, "destroyed at old weak 1")
eq(cb.weak, 0, "weak count decremented to 0")

cb2 = ControlBlock(use=1, weak=3)
eq(last_use_helper(cb2), ["dispose", "weak--"],
   "weak 3 survives: no destroy")
check(cb2.disposed, "disposed")
check(not cb2.destroyed, "not destroyed while weak observers remain")
eq(cb2.weak, 2, "weak count 3 -> 2")

cb3 = ControlBlock(use=3, weak=2)
eq(last_use_helper(cb3), [], "use 3 -> 2: silent")
eq(cb3.use, 2, "use 3 -> 2")

# The atomic selector: the byte at 0x64ed290 chooses lock xadd.
cb4 = ControlBlock(use=1, weak=1, atomic=True)
check(cb4.atomic, "atomic flag recorded")
eq(last_use_helper(cb4), ["dispose", "weak--", "destroy"],
   "atomic path has the same events")

# SharedPtr copy bumps the use count; release follows the helper.
obj = object()
ctrl = ControlBlock(use=1, weak=1)
ptr = SharedPtr(obj, ctrl)
copy = ptr.copy()
eq(ctrl.use, 2, "copy bumps use count")
eq(ptr.release(), [], "release of a shared copy is silent")
eq(ctrl.use, 1, "use 2 -> 1")
eq(copy.release(), ["dispose", "weak--", "destroy"],
   "release of the last copy disposes and destroys")
check(ctrl.disposed and ctrl.destroyed, "control block finished")

# --- options vector ----------------------------------------------------------

vec = OptionsVector()
eq(vec.capacity, 0, "vector starts empty")
rec = vec.append("", "this+0x20", 0x6504B80)
eq(len(vec.records), 1, "one record appended")
eq(vec.capacity, 1, "first append grows to capacity 1")
check(not rec["heap"], "empty name is SSO")
eq(rec["ptr2"], 0x6504B80, "record third field")
vec.append("x" * 15, "a", 1)
check(not vec.records[1]["heap"], "len 15 stays SSO")
vec.append("x" * 16, "a", 1)
check(vec.records[2]["heap"], "len 16 goes to the heap")
eq(vec.capacity, 4, "capacity doubled 1 -> 2 -> 4")
for i in range(5):
    vec.append("r%d" % i, i, i)
eq(len(vec.records), 8, "eight records total")
eq(vec.capacity, 8, "capacity doubled to 8")
check(vec.buffer_freed, "grow freed the old buffer")

# Grow moves heap strings and nulls the source.
vec2 = OptionsVector()
vec2.append("long-name-over-fifteen", "p", 1)
vec2.append("short", "p", 2)
vec2.grow()
eq(vec2.records[0]["name"], "long-name-over-fifteen", "heap string moved")
eq(vec2.capacity, 4, "capacity doubled from 2")

# Destroy disposes each record and frees the buffer.
eq(vec2.destroy(), 2, "destroy disposes 2 records")
eq(vec2.records, [], "records cleared")
eq(vec2.capacity, 0, "capacity reset")
check(vec2.buffer_freed, "buffer freed")

# Capacity overflow guard.
vec3 = OptionsVector()
vec3.capacity = OptionsVector.MAX_CAPACITY
vec3.records = [None] * OptionsVector.MAX_CAPACITY if False else []
try:
    vec3.grow()
    raise AssertionError("overflow not raised")
except OverflowError:
    pass

# --- wrapper ctor / dtor ------------------------------------------------------

wrapped_ctrl = ControlBlock(use=1, weak=1)
wrapped_ptr = SharedPtr(object(), wrapped_ctrl)
wrapper = Wrapper.ctor_c1(wrapped_ptr)
eq(wrapper.vtable, WRAPPER_VTABLE, "ctor installs wrapper vtable")
eq(wrapper.size, 0x30, "wrapper is 0x30 bytes")
eq(wrapped_ctrl.use, 2, "ctor copy bumps the wrapped use count")
eq(len(wrapper.options.records), 1, "ctor appends one record")
eq(wrapper.options.records[0]["ptr2"], 0x6504B80, "ctor record field")
eq(wrapper.options.records[0]["name"], "", "ctor record name is empty")

events = wrapper.dtor_d2()
eq(wrapper.vtable, BASE_VTABLE, "D2 installs the base vtable")
check("vector-destroy:1" in events, "D2 destroys the one record")
eq(wrapped_ctrl.use, 1, "D2 release decrements the wrapped use count")
check(wrapper.wrapped is None, "D2 clears the wrapped pointer")

# D0 adds operator delete 0x30.
wrapper2 = Wrapper.ctor_c1(SharedPtr(object(), ControlBlock(use=1, weak=1)))
events2 = wrapper2.dtor_d0()
check("delete:0x30" in events2, "D0 deletes 0x30 bytes")
check(wrapper2.deleted, "D0 marks the object deleted")

# A bare wrapper (no wrapped clock) still destroys its vector.
wrapper3 = Wrapper.ctor_c1(None)
check(wrapper3.wrapped is None, "bare wrapper has no target")
eq(wrapper3.dtor_d2(), ["vector-destroy:1"], "bare D2 only destroys vector")

# --- emulated ctor ------------------------------------------------------------

def fake_slot24(preloaded):
    """A wrapped slot-24 that returns the preloaded value."""
    return (0, preloaded)


emu_ctrl = ControlBlock(use=1, weak=1)
emu = EmulatedClock.ctor_c1(SharedPtr(object(), emu_ctrl), 0, fake_slot24)
eq(emu.vtable, EMULATED_VTABLE, "emulated ctor installs emulated vtable")
eq(emu.size, 0x50, "emulated clock is 0x50 bytes")
eq(emu.seeded, 0x4FB647D0, "seeded from the preloaded value_out")
eq(emu.mode, 0, "mode 0 stored")
eq(emu.mode_dup, 0, "mode byte duplicated at +0x49")
eq(emu.offset40, 0, "+0x40 zeroed")
eq(len(emu.options.records), 3, "emulated ctor appends three records")
eq(emu.options.records[0]["ptr2"], 0x6504B80, "first record field")
eq(emu.options.records[1]["ptr2"], 0x6505960, "second record field")
eq(emu.options.records[2]["ptr2"], 0x6505920, "third record field")
eq(emu_ctrl.use, 2, "emulated ctor copies the wrapped clock")

# Mode 1 (the factory path).
emu1 = EmulatedClock.ctor_c1(SharedPtr(object(), ControlBlock(use=1, weak=1)),
                              1, fake_slot24)
eq(emu1.mode, 1, "mode 1 stored")
eq(emu1.mode_dup, 1, "mode 1 duplicated")

# Emulated D2 / D0.
emu_events = emu.dtor_d2()
eq(emu.vtable, BASE_VTABLE, "emulated D2 installs the base vtable")
check("vector-destroy:3" in emu_events, "emulated D2 destroys 3 records")
emu2 = EmulatedClock.ctor_c1(SharedPtr(object(), ControlBlock(use=1, weak=1)),
                              0, fake_slot24)
check("delete:0x50" in emu2.dtor_d0(), "emulated D0 deletes 0x50 bytes")
check(emu2.deleted, "emulated D0 marks deleted")

# Emulated slot-24: frozen (mode set) returns seed + scaled add.
emu3 = EmulatedClock.ctor_c1(SharedPtr(object(), ControlBlock(use=1, weak=1)),
                              1, fake_slot24)
emu3.offset40 = 2 ** 40
code, value = emu3.get_current_time(0)
eq(code, 0, "frozen slot-24 code 0")
eq(value, 0x4FB647D0 + 1099511, "frozen value is seed + scaled add")

# Emulated slot-24: unfrozen recurses to the wrapped clock.
class FakeWrapped:
    def get_current_time(self, value_out):
        return (0, 1000)

wrapped2 = SharedPtr(FakeWrapped(), ControlBlock(use=1, weak=1))
emu4 = EmulatedClock.ctor_c1(wrapped2, 0, fake_slot24)
code, value = emu4.get_current_time(0)
eq((code, value), (0, 1000), "unfrozen recurses to the wrapped clock")

# --- thunk manager ------------------------------------------------------------

fn = ThunkFunction(0x5FCC5D0, 0x5FCD5B0)
eq(manager_dispatch(0x5FCC5D0, fn, 0x64CD9D0, 0), 0, "op 0 returns 0")
eq(fn.storage, 0x64CD9D0, "op 0 installs the vtable at the storage")
eq(manager_dispatch(0x5FCC5D0, fn, 0x5FCD5B0, 1), 0, "op 1 returns 0")
eq(fn.storage, 0x5FCD5B0, "op 1 stores rsi at the storage")
fn2 = ThunkFunction(0x5FCC600, 0x5FCF450)
fn2.storage = 0x1234
dest = ThunkFunction(0x5FCC600, 0x5FCF450)
eq(manager_dispatch(0x5FCC600, dest, fn2, 2), 0, "op 2 returns 0")
eq(dest.storage, 0x1234, "op 2 clones the storage")
eq(manager_dispatch(0x5FCC600, dest, None, 3), 0, "op 3 returns 0")

# Clone keeps manager/invoker; destroy is a no-op.
clone = fn.clone()
eq(clone.manager, 0x5FCC5D0, "clone keeps the manager")
eq(clone.invoker, 0x5FCD5B0, "clone keeps the invoker")
eq(clone.storage, 0x5FCD5B0, "clone copies the storage")
eq(clone.destroy(), 0, "op 3 destroy is a no-op for a function pointer")

# --- registry -------------------------------------------------------------------

reg = Registry()
reg.register_builtin_system_clocks()
eq(sorted(reg.nodes), ["CompositeEnv", "MockEnv"],
   "reg-sysclocks registers MockEnv and CompositeEnv")
eq(reg.nodes["MockEnv"].function.manager, 0x5FCC5D0, "MockEnv manager")
eq(reg.nodes["MockEnv"].function.invoker, 0x5FCD5B0, "MockEnv invoker")
eq(reg.nodes["CompositeEnv"].function.manager, 0x5FCC600,
   "CompositeEnv manager")
eq(reg.nodes["CompositeEnv"].function.invoker, 0x5FCF450,
   "CompositeEnv invoker")
eq(reg.nodes["MockEnv"].entry.name, "MockEnv", "entry name")
eq(reg.nodes["MockEnv"].entry.vtable, ENTRY_VTABLE, "entry vtable")
eq(reg.nodes["MockEnv"].vtable, NODE_VTABLE, "node vtable")
check(not reg.locked, "registry unlocked after insert")

reg.default_init()
check("TimeEmulatedSystemClock" in reg.nodes,
      "default-init registers TimeEmulatedSystemClock")
eq(reg.nodes["TimeEmulatedSystemClock"].function.invoker, 0x5FCD550,
   "time-emu invoker")
eq(reg.nodes["TimeEmulatedSystemClock"].function.manager, 0x5FCC630,
   "time-emu manager")
eq(reg.nodes["TimeEmulatedSystemClock"].entry.flag_0x48, 1,
   "entry +0x48 byte is 1")

# Node D2 destroys the stored function (op 3) and the entry.
node = reg.nodes["MockEnv"]
events = node.dtor_d2()
eq(events, ["manager-op3", "entry-d0"], "node D2 events in order")
check(node.function is None, "node D2 clears the function")
check(node.entry is None, "node D2 clears the entry")

# --- invokers and factory ---------------------------------------------------------

cell = [None]
old = invoker_swap(cell, Wrapper.ctor_c1(None))
eq(old, None, "swap into an empty cell returns None")
check(cell[0] is not None, "swap installs the new clock")
old2 = invoker_swap(cell, Wrapper.ctor_c1(None))
check(old2 is not None and old2.deleted,
      "swap D0-deletes the old clock")

# The factory: mode 1, control block (1, 1), 0x60 allocation.
factory_ctrl_holder = {}
wrapped3 = SharedPtr(object(), ControlBlock(use=1, weak=1))
shared = make_shared_emulated(wrapped3, 1, fake_slot24)
eq(shared.obj.mode, 1, "factory builds a mode-1 emulated clock")
eq(shared.control.use, 1, "factory control block use 1")
eq(shared.control.weak, 1, "factory control block weak 1")
eq(shared.obj.seeded, 0x4FB647D0, "factory seeds from the wrapped clock")
eq(len(shared.obj.options.records), 3, "factory clock has 3 records")

# The holder accessor returns arg+0x38.
class Holder:
    def __init__(self):
        self.wrapped = SharedPtr(object(), ControlBlock(use=1, weak=1))

holder = Holder()
eq(holder_accessor(holder), holder.wrapped, "accessor returns +0x38 slot")

# End-to-end: factory -> registry -> invoker swap -> teardown.
reg2 = Registry()
reg2.register_builtin_system_clocks()
reg2.default_init()
eq(len(reg2.nodes), 3, "all three entries registered")
clock_cell = [None]
clock = make_shared_emulated(SharedPtr(object(), ControlBlock(use=1, weak=1)),
                              1, fake_slot24)
invoker_swap(clock_cell, clock.obj)
check(clock_cell[0] is clock.obj, "cell holds the factory clock")
eq(clock.control.use, 1, "factory shared_ptr still owned once")
eq(clock_cell[0].mode, 1, "cell clock is mode 1")

print("ALL CHECKS PASSED (%d checks)" % CHECKS)
