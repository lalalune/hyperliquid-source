"""Python model of node #115's SystemClockWrapper vtable (RE-001).

Faithful model of the 33 windows in
research/work-items/RE-001-systemclock-wrapper-vtable-115/:
the SystemClockWrapper vtable (stored pointer 0x64cdd88, 26 slots),
the EmulatedSystemClock overrides (vtable 0x64d1650) and the
PosixClock slots that identify the shared slots (vtable 0x64ce930),
with the wrapper constructor C1 0x5fd0090 and the destructor D0
0x6029500 by contract.

The wrapper is 0x30 bytes: +0x00 vtable, +0x08..+0x18 zeroed by the
ctor (a 3-pointer range whose exact container identity is open),
+0x20 shared_ptr<SystemClock> target, +0x28 its control block.

Three dispatch rules cover the time methods:
- chain-walk (slots 19 NowMicros, 23 SleepForMicroseconds, 24
  GetCurrentTime): an 8-level unrolled walk; each level compares
  its slot pointer against the GOT canonical for that slot
  (slot 19: GOT 0x64ecf80 -> 0x5d4d490; slot 23: GOT 0x64ed5f8 ->
  0x5dd41a0; slot 24: GOT 0x64ed3e8 -> 0x5d4b100); the first level
  whose slot differs from the canonical is called; when all 8
  levels match, the 9th level's slot is called unconditionally.
- single-level forwarding (slots 20 NowNanos, 21 CPUMicros, 22
  CPUNanos): a plain tail-jump to the wrapped clock's same slot.
- slot 25 TimeToString calls the wrapped clock's slot 25 with
  (Status-out, this).

The Configurable/Customizable base methods (slots 2, 3, 6, 7, 9,
10, 11, 13) are pinned by identity, entry contract and callees;
their full internals are the Configurable component's own work and
are modelled here as named hooks, exactly as the binary calls them.

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
"""

# --- vtable geometry ---------------------------------------------------

WRAPPER_VTABLE = 0x64CDD88
EMULATED_VTABLE = 0x64D1650
POSIX_VTABLE = 0x64CE930

# GOT canonicals the chain-walk compares each level's slot against.
CHAIN_CANONICAL = {
    19: (0x64ECF80, 0x5D4D490),  # NowMicros
    23: (0x64ED5F8, 0x5DD41A0),  # SleepForMicroseconds
    24: (0x64ED3E8, 0x5D4B100),  # GetCurrentTime
}

# Slot -> (function address, identity). None means the slot is null
# (no R_X86_64_RELATIVE record): the wrapper leaves slots 0, 1 and
# 14 null.
WRAPPER_SLOTS = {
    0: None,  # D1 (null in the wrapper vtable)
    1: None,  # D0 (null in the wrapper vtable)
    2: (0x609D760, "rocksdb::Customizable::GetOption"),
    3: (0x609DC40, "rocksdb::Customizable::AreEquivalent"),
    4: (0x5D32560, "returns empty std::string (C++ name open)"),
    5: (0x5FCF590, "rocksdb::SystemClockWrapper::PrepareOptions"),
    6: (0x6096790, "rocksdb::Configurable::ValidateOptions"),
    7: (0x5D2E090, "rocksdb::Customizable::GetOptionsPtr"),
    8: (0x60956F0, "returns empty Status (C++ name open)"),
    9: (0x609D0E0, "rocksdb::Configurable::ConfigureOptions"),
    10: (0x60986B0, "rocksdb::Configurable::ParseOption"),
    11: (0x6095710, "rocksdb::Configurable::OptionsAreEqual"),
    12: (0x5FCDAE0, "rocksdb::SystemClockWrapper::SerializeOptions"),
    13: (0x609D980, "rocksdb::Customizable::GetOptionName"),
    14: None,  # Name() (null in the wrapper vtable)
    15: (0x5D32A30, "rocksdb::Customizable::GetId"),
    16: (0x5D2E770, "rocksdb::Customizable::IsInstanceOf"),
    17: (0x5FCC3F0, "returns *(this+0x20), the wrapped clock"),
    18: (0x5D2CA10, 'returns "" (C++ name open)'),
    19: (0x5D4D490, "rocksdb::SystemClockWrapper::NowMicros"),
    20: (0x5FCC340, "forwards to wrapped slot 20 (NowNanos)"),
    21: (0x5FCC360, "forwards to wrapped slot 21 (CPUMicros)"),
    22: (0x5FCC380, "forwards to wrapped slot 22 (CPUNanos)"),
    23: (0x5DD41A0, "rocksdb::SystemClockWrapper::SleepForMicroseconds"),
    24: (0x5D4B100, "GetCurrentTime (canonical chain-walk)"),
    25: (0x5FCC3A0, "rocksdb::SystemClockWrapper::TimeToString"),
}

EMULATED_OVERRIDES = {
    0: (0x6029110, "EmulatedSystemClock D1 (installs the wrapper vtable)"),
    1: (0x6029620, "EmulatedSystemClock D0 (installs the wrapper vtable)"),
    14: (0x60257A0, 'Name() -> "TimeEmulatedSystemClock"'),
    19: (0x60259E0, "EmulatedSystemClock::NowMicros"),
    20: (0x60259A0, "EmulatedSystemClock::NowNanos"),
    21: (0x6025A30, "EmulatedSystemClock::CPUMicros"),
    22: (0x6025A10, "EmulatedSystemClock::CPUNanos"),
    23: (0x6025B40, "EmulatedSystemClock::SleepForMicroseconds"),
    24: (0x6025EB0, "EmulatedSystemClock::GetCurrentTime"),
}

POSIX_SLOTS = {
    5: (0x6095E70, "rocksdb::Configurable::PrepareOptions (base)"),
    12: (0x609DE80, "rocksdb::Customizable::SerializeOptions (base)"),
    14: (0x5FE0FE0, 'Name() -> "DefaultClock"'),
    17: (0x5D2CA00, "returns null"),
    18: (0x5FE0FF0, 'returns "PosixClock"'),
    19: (0x5FE1540, "PosixClock::NowMicros"),
    20: (0x5FE14F0, "PosixClock::NowNanos"),
    21: (0x5FE1480, "PosixClock::CPUMicros"),
    22: (0x5FE1430, "PosixClock::CPUNanos"),
    23: (0x5FE1420, "PosixClock::SleepForMicroseconds"),
    24: (0x5FE2230, "PosixClock::GetCurrentTime"),
    25: (0x5FE1340, "PosixClock::TimeToString"),
}


def slot_address(vtable_slots, slot):
    """The function address a vtable holds at `slot`, or None when
    the slot is null."""
    entry = vtable_slots.get(slot)
    return entry[0] if entry else None


# --- clocks ------------------------------------------------------------

class Status:
    """An OK Status is a 16-byte zero; the model keeps only the ok flag."""

    def __init__(self, ok=True, message=""):
        self.ok = ok
        self.message = message

    def __repr__(self):
        return "Status(ok=%r)" % self.ok


class Clock:
    """A clock object: a vtable (slot -> callable) plus the fields
    the wrapper family reads. `slot_fn` holds the function address
    each slot resolves to, for the chain-walk identity compare."""

    def __init__(self, vtable, slot_fn):
        self.vtable = vtable
        self.slot_fn = dict(slot_fn)
        self.target = None  # +0x20 shared_ptr<SystemClock> target
        self.config_flag = 0  # the AreEquivalent config flag
        self.name = None  # slot 14 (Name), None when the slot is null
        self.secondary_name = ""  # slot 18
        self.options = {}  # the Configurable options map
        self.deeper_check = None  # AreEquivalent hook for flag > 2

    def call_slot(self, slot, *args):
        """Call the vtable slot. Entries are bound callables taking
        only the call arguments (self is already bound)."""
        fn = self.vtable.get(slot)
        if fn is None:
            raise ValueError("null vtable slot %d" % slot)
        return fn(*args)

    def slot_ptr(self, slot):
        """The function address the clock's vtable holds at `slot`,
        or None when the slot is null. Used by the chain-walk
        identity compare against the GOT canonicals."""
        entry = self.slot_fn.get(slot)
        return entry[0] if entry else None


class PosixClock(Clock):
    """The default clock (vtable 0x64ce930). Its time methods are
    the leaves the wrapper chain-walk lands on."""

    def __init__(self, now_micros=1_000_000, now_nanos=1_000_000_000):
        super().__init__({}, {})
        self.name = "DefaultClock"
        self.secondary_name = "PosixClock"
        self._now_micros = now_micros
        self._now_nanos = now_nanos
        self.slept_micros = 0
        self.vtable = {
            5: self._prepare_options,
            12: self._serialize_options,
            14: lambda: self.name,
            15: lambda: self.name,
            16: self._is_instance_of,
            17: lambda: None,
            18: lambda: self.secondary_name,
            19: lambda: self._now_micros,
            20: lambda: self._now_nanos,
            21: lambda: self._now_micros,
            22: lambda: self._now_nanos,
            23: self._sleep,
            24: lambda: self._now_micros,
            25: lambda status_out: "PosixClock time",
        }
        self.slot_fn = dict(POSIX_SLOTS)
        for slot in (2, 3, 4, 6, 7, 8, 9, 10, 11, 13):
            self.slot_fn[slot] = WRAPPER_SLOTS[slot]

    def _prepare_options(self, config):
        return Status(True)

    def _serialize_options(self, config, prefix):
        return Status(True)

    def _is_instance_of(self, name):
        return name in ("DefaultClock", "PosixClock")

    def _sleep(self, micros):
        self.slept_micros += micros
        self._now_micros += micros
        self._now_nanos += micros * 1000


def default_clock_accessor():
    """The accessor 0x5fe2680: returns the process default PosixClock."""
    return PosixClock()


class SystemClockWrapper(Clock):
    """The wrapper (vtable 0x64cdd88, 0x30 bytes). The +0x20 target
    is a shared_ptr: `target` here is the wrapped Clock, or None."""

    def __init__(self, target=None):
        super().__init__({}, {})
        self.target = target
        self.name = None  # slot 14 is null in the wrapper vtable
        self.secondary_name = ""  # slot 18 returns ""
        self.vtable = {
            2: self._get_option,
            3: self._are_equivalent,
            4: lambda: "",
            5: self._prepare_options,
            6: lambda config: Status(True),  # ValidateOptions hook
            7: lambda: self.options,
            8: lambda: Status(True),
            9: lambda config: Status(True),  # ConfigureOptions hook
            10: lambda name, value: Status(True),  # ParseOption hook
            11: lambda other: True,  # OptionsAreEqual hook
            12: self._serialize_options,
            13: lambda name: name,  # GetOptionName hook
            15: self._get_id,
            16: self._is_instance_of,
            17: lambda: self.target,
            18: lambda: "",
            19: self._now_micros,
            20: self._forward_20,
            21: self._forward_21,
            22: self._forward_22,
            23: self._sleep,
            24: self._get_current_time,
            25: self._time_to_string,
        }
        self.slot_fn = dict(WRAPPER_SLOTS)

    # -- Configurable/Customizable slots --------------------------------

    def _get_option(self, name):
        """Slot 2 GetOption: the "id" fast path. Name length 2 with
        bytes "id" (0x6469) calls slot 15 (GetId) on this and returns
        the id string with an OK Status; any other name goes to the
        generic path 0x6099030 (modelled as a miss)."""
        if len(name) == 2 and name == "id":
            return self._get_id(), Status(True)
        return None, Status(False, "unknown option")

    def _are_equivalent(self, other):
        """Slot 3 AreEquivalent: config flag <= 1 or this == other
        returns 1; a null other returns 0; otherwise memcmp the two
        GetId() strings. Equal ids with flag <= 2 return 1; equal
        ids with flag > 2 tail-jump to the deeper check 0x60996a0
        (the hook); different ids write "id" into the out string
        and return 0."""
        if self.config_flag <= 1 or self is other:
            return 1, ""
        if other is None:
            return 0, ""
        mine = self.call_slot(15)
        theirs = other.call_slot(15)
        if mine != theirs:
            return 0, "id"
        if self.config_flag <= 2:
            return 1, ""
        if self.deeper_check is not None:
            return self.deeper_check(self, other), ""
        return 1, ""

    def _prepare_options(self, config):
        """Slot 5 PrepareOptions: when the wrapper target (+0x20)
        is null, install the default PosixClock via the accessor
        0x5fe2680 with shared_ptr refcounting, then call the base
        Configurable::PrepareOptions 0x6095e70."""
        if self.target is None:
            self.target = default_clock_accessor()
        return Status(True)

    def _get_id(self):
        """Slot 15 GetId: calls slot 14 (Name) on this and builds a
        std::string from the result via 0x5d32940. A bare wrapper's
        slot 14 is null, so a bare wrapper has no id of its own:
        the id comes from the wrapped clock's Name when one is
        installed (see the open unknown in the packet README)."""
        if self.name is not None:
            return self.name
        if self.target is not None:
            return self.target.call_slot(15)
        return ""

    def _is_instance_of(self, name):
        """Slot 16 IsInstanceOf: the wrapper answers for its own
        names and defers to the wrapped clock otherwise."""
        if name in ("SystemClockWrapper",):
            return True
        if self.target is not None:
            return self.target.call_slot(16, name)
        return False

    def _serialize_options(self, config, prefix):
        """Slot 12 SerializeOptions: serializes via the base
        Customizable::SerializeOptions 0x609de80, then, when a
        wrapped clock is installed, checks it against the default
        clock (its slot 16 IsInstanceOf against "DefaultClock",
        compared with the GOT slot 0x64eceb8) to decide whether the
        wrapped clock's serialization is emitted. The exact branch
        outcome is open; the model emits the wrapped identity when
        the target is present and is not the default clock."""
        if self.target is None:
            return Status(True), prefix
        if self.target.call_slot(16, "DefaultClock"):
            return Status(True), prefix
        return Status(True), prefix + "/" + self.target.call_slot(15)

    # -- time-method dispatch -------------------------------------------

    def _chain(self, slot):
        """The chain-walk list: this wrapper followed by the wrapped
        clocks, outermost first. The binary unrolls 8 levels and
        calls the 9th unconditionally when all 8 match."""
        chain = [self]
        node = self.target
        while node is not None and len(chain) < 9:
            chain.append(node)
            node = getattr(node, "target", None)
        return chain

    def _chain_walk(self, slot, *args):
        """Slots 19/23/24: walk the chain; the first level whose
        slot pointer differs from the GOT canonical is called; when
        all 8 compared levels match, the 9th level's slot is called
        unconditionally (a 9th-level canonical re-walks from there,
        exactly as the binary does). A chain that ends before any
        level differs has no defined target in the binary either,
        so the model raises."""
        _, canonical = CHAIN_CANONICAL[slot]
        chain = self._chain(slot)
        for level in chain[:8]:
            if level.slot_ptr(slot) != canonical:
                return level.call_slot(slot, *args)
        if len(chain) < 9:
            raise ValueError(
                "chain-walk ran off the end of the chain at slot %d" % slot)
        return chain[8].call_slot(slot, *args)

    def _now_micros(self):
        return self._chain_walk(19)

    def _sleep(self, micros):
        return self._chain_walk(23, micros)

    def _get_current_time(self):
        return self._chain_walk(24)

    def _forward_20(self):
        """Slot 20: mov 0x20(%rdi),%rdi; jmp *0xa0(%rax) -- tail-jump
        to the wrapped clock's slot 20 (NowNanos)."""
        return self.target.call_slot(20)

    def _forward_21(self):
        """Slot 21: jmp *0xa8(%rax) -- the wrapped clock's CPUMicros."""
        return self.target.call_slot(21)

    def _forward_22(self):
        """Slot 22: jmp *0xb0(%rax) -- the wrapped clock's CPUNanos."""
        return self.target.call_slot(22)

    def _time_to_string(self, status_out):
        """Slot 25: calls the wrapped clock's slot 25 with
        (Status-out, this)."""
        return self.target.call_slot(25, status_out)


class EmulatedSystemClock(SystemClockWrapper):
    """The emulated clock (vtable 0x64d1650): shares the wrapper's
    slots 2-13, 15-18 and 25 and overrides 0, 1, 14 and 19-24. Its
    extra state is the emulated offset at +0x40, the sleep counter
    at +0x38, the CPU counter at +0x3c and the flags at +0x48/+0x49."""

    def __init__(self, target=None):
        super().__init__(target)
        self.name = "TimeEmulatedSystemClock"
        self.emulated_offset = 0  # +0x40
        self.sleep_count = 0  # +0x38
        self.cpu_count = 0  # +0x3c
        self.frozen = False  # flag +0x48: emulated time is frozen
        self.sleep_advances = False  # flag +0x49
        self.vtable.update({
            14: lambda: self.name,
            19: self._emu_now_micros,
            20: self._emu_now_nanos,
            21: self._emu_cpu_micros,
            22: self._emu_cpu_nanos,
            23: self._emu_sleep,
            24: self._emu_get_current_time,
        })
        for slot, entry in EMULATED_OVERRIDES.items():
            self.slot_fn[slot] = entry

    def _emu_now_micros(self):
        """Slot 19: flag +0x48 set -> return *(node+0x40); else the
        wrapped slot 19 plus *(node+0x40)."""
        if self.frozen:
            return self.emulated_offset
        return self.target.call_slot(19) + self.emulated_offset

    def _emu_now_nanos(self):
        """Slot 20: same, but the offset is scaled by 1000."""
        if self.frozen:
            return self.emulated_offset * 1000
        return self.target.call_slot(20) + self.emulated_offset * 1000

    def _emu_cpu_micros(self):
        """Slot 21: lock addl $1, +0x3c, then forward to wrapped
        slot 21."""
        self.cpu_count += 1
        return self.target.call_slot(21)

    def _emu_cpu_nanos(self):
        """Slot 22: lock addl $1, +0x3c, then forward to wrapped
        slot 22."""
        self.cpu_count += 1
        return self.target.call_slot(22)

    def _emu_sleep(self, micros):
        """Slot 23: lock addl $1, +0x38 and lock add %rax, +0x40
        (the slept time accumulates into the emulated offset), then
        the wrapped slot 23 runs. The +0x48/+0x49 flags are also
        read here; their exact role in Sleep is open, so the model
        accumulates unconditionally and records the flags as an
        open unknown."""
        self.sleep_count += 1
        self.emulated_offset += micros
        return self.target.call_slot(23, micros)

    def _emu_get_current_time(self):
        """Slot 24: the emulated GetCurrentTime (315 B); it reads
        the emulated offset and the flags the same way slot 19
        does and otherwise follows the wrapped slot 24."""
        if self.frozen:
            return self.emulated_offset
        return self.target.call_slot(24) + self.emulated_offset
