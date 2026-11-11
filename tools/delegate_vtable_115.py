"""Python model of node #115's Find delegate vtable family.

RE-001 work item (research/work-items/RE-001-delegate-vtable-115/).
The model follows the binary's observed behavior, not a C++ spelling:
the exact source names of the classes and their methods are inference,
the mechanics below are the packet's.

The delegate is the Customizable object find_entry (0x609e510)
dispatches through: its vtable sits at the matcher node's +0x28
object pointer (the create host 0x6077820 passes *(rbp), its 4th
argument, as find_entry's delegate). Nineteen vtable bases form the
family; their slot maps are pinned in the packet's vtables.tsv and
re-derived from the binary's .rela.dyn by gen_records.py.

Vtable layout (verified against all 406 strict vtables in the
binary): the vtable base B has B-0x8 = the typeinfo pointer and
B-0x10 = 0 (offset-to-top); slots sit at B+offset exactly as the
call sites use them. A slot holds a concrete function (a RELATIVE
reloc into .text), __cxa_pure_virtual (NULL in the model), or 0.

The delegate interface is slots 0x10..0x98. Two structural facts
shape it:
  * Env, StatisticsImpl, SystemClockWrapper and the wrapper classes
    share slots 0x10..0x68, 0x78, 0x80, 0x90; they differ at 0x00/0x08
    (destructors), 0x70 (Name), 0x88 (wrapped object) and 0x98+.
  * Configurable (14 slots, 0x00..0x68) and Logger (11 slots) have no
    identity slots 0x70+, so a find_entry delegate is an Env /
    Statistics / SystemClock-family Customizable, never a
    Configurable or a Logger.
  * SystemClockWrapper's slot 0x70 (Name) is NULL (pure virtual):
    calling Name() on it would crash; the binary never does.
  * Only 6 of the 19 classes have a `lea` install site anywhere in
    the binary (PosixEnv 3, PosixClock 1, PosixFileSystem 5,
    TestMemLogger 4, MockEnvDirectory 1, MockEnvFileLock 3); the
    other vtable bases never appear as an instruction operand and no
    relocation holds them, so their objects are not constructed by
    any code in this binary's .text.

Slot contracts (0x10..0x98), each pinned by a whole-function excerpt:
  0x10 GetOption: name == "id" returns the delegate's own name and a
      zeroed Status; otherwise forwards to Configurable 0x6099030.
  0x18 ConfigureOption: returns 1 when the value's +0x2c byte is <= 1
      or out == delegate, 0 when the delegate is null; on a name
      mismatch rewrites the option name to "id", then forwards to
      Configurable 0x60996a0 when +0x2c > 2, else returns 1.
  0x20 init: initializes a std::string (pointer rdi+0x10, length 0).
  0x28 parse/apply records: walks 0x30-byte records; the worker
      0x60b9e00 fires when (HIGH dword of *(record+0xd0) - 4) > 1
      (unsigned; a high dword of 0..3 wraps and also passes) and
      the 0x40 bit of the byte at record+0xd9 is clear and (the
      materialized +0xa0 sub-value's first qword is non-null or
      (LOW dword of *(record+0xd0) - 0x15) <= 1 unsigned).
  0x30 parse/apply records (worker 2): same walk, worker 0x60b9f50
      fires when (HIGH dword of *(record+0xd0) - 4) > 1 (unsigned)
      and (the raw +0xc0 function pointer is non-null or (LOW
      dword of *(record+0xd0) - 0x15) <= 1 unsigned); no 0x40 flag
      check. When +0xc0 is null the binary skips materializing it
      and jumps to a second gate site that runs the same predicate
      without the +0xc0 branch.
  0x38 resolve name: the shared resolver 0x60958c0 scans the
      0x30-byte (name, +0x20 field) record array at *(rdi+0x08)..
      *(rdi+0x10) and returns the matching record's +0x20 field, or
      null; otherwise forwards through the wrapped object's slot 0x38.
  0x40 zero Status: writes a zeroed 16-byte Status and returns rdi.
  0x48 merge host: 0x609d0e0 first; the overrides return early when
      its Status is non-zero, then call the delegate's slot 0x28.
  0x50 SetOption: kind byte (+0x04) 0 forwards to 0x60bedc0; kind != 0
      and the changeable flag set copies the value struct and calls
      0x60bedc0; kind != 0 and the flag clear reports
      "Option not changeable: " + name through 0x61cf670 (code 4).
  0x58 validate: calls 0x60bf980, then 0x60bf7c0; blanks the target
      name when both reject; always returns 1.
  0x60 serialize: kind (+0x28) 1 or an empty delegate name composes
      <options name> + "id" + "=" + <delegate name> + <value name>;
      otherwise forwards to Configurable 0x60985e0.
  0x68 dotted-name: strips the delegate's Name() + '.' prefix from
      the input name; otherwise falls back to Configurable 0x6095a60
      (a std::string copy); a null Name() throws std::logic_error.
  0x70 Name(): the class name literal (see NAME); NULL for
      SystemClockWrapper; absent for Configurable/Logger tables.
  0x78 name as std::string: Name() assigned into the sret string.
  0x80 IsInstanceOf: canonical 0x5d2e770 returns 1 when the input
      matches Name() or NickName() by length then memcmp, else 0;
      MockEnv and CompositeEnvWrapper override it (0x5fd6240):
      "CompositeEnv" (length 12) returns 1, anything else
      tail-jumps to the canonical.
  0x88 wrapped object: Env 0; SystemClockWrapper *(obj+0x20);
      MockEnv *(obj+0x48); StatisticsImpl *(obj+0x28).
  0x90 NickName(): "" for Env, "PosixClock" for PosixClock,
      "DefaultEnv" for PosixEnv.
  0x98 unwrap/status/time: Env zeroed Status; SystemClockWrapper
      walks the +0x20 chain (10 levels unrolled); PosixClock returns
      gettimeofday microseconds; EmulatedSystemClock returns
      (flag ? 0 : wrapped time) + the offset at +0x40; StatisticsImpl
      runs the +0x38 field's pre/post hooks around core 0x6070430.
"""

# --- vtable bases ---------------------------------------------------------

VTABLES = {
    "EnvLogger": 0x64CDA68,
    "Env": 0x64CDAD0,
    "SystemClockWrapper": 0x64CDD88,
    "CompositeEnv": 0x64CE2D8,
    "CompositeEnvWrapper": 0x64CE590,
    "PosixClock": 0x64CE930,
    "PosixEnv": 0x64CEA10,
    "MockEnv": 0x64D1398,
    "EmulatedSystemClock": 0x64D1650,
    "MockEnvDirectory": 0x64D1940,
    "MockEnvFileLock": 0x64D1980,
    "TestMemLogger": 0x64D19A0,
    "AutoRollLogger": 0x64D1F00,
    "StatisticsImpl": 0x64D2D88,
    "ConfigurableMutableCFOptions": 0x64D3138,
    "ConfigurableCFOptions": 0x64D31B8,
    "Configurable": 0x64D3430,
    "MutableDBConfigurable": 0x64D3638,
    "DBOptionsConfigurable": 0x64D36B8,
}

NSLOTS = {
    "EnvLogger": 11, "Env": 85, "SystemClockWrapper": 26,
    "CompositeEnv": 85, "CompositeEnvWrapper": 85, "PosixClock": 26,
    "PosixEnv": 85, "MockEnv": 85, "EmulatedSystemClock": 26,
    "MockEnvDirectory": 6, "MockEnvFileLock": 2, "TestMemLogger": 11,
    "AutoRollLogger": 11, "StatisticsImpl": 32,
    "ConfigurableMutableCFOptions": 14, "ConfigurableCFOptions": 14,
    "Configurable": 14, "MutableDBConfigurable": 14,
    "DBOptionsConfigurable": 14,
}

# --- canonical functions --------------------------------------------------

IS_INSTANCE_OF = 0x5D2E770      # slot 0x80, shared by the family
NAME_AS_STRING = 0x5D32A30      # slot 0x78, shared
ZERO_STATUS = 0x60956F0         # slot 0x40, shared
SLOT10_GET_OPTION = 0x609D760   # slot 0x10, shared
SLOT18_CONFIGURE = 0x609DC40    # slot 0x18, shared
SLOT28_PARSE = 0x6095E70        # slot 0x28, shared
SLOT30_PARSE = 0x6096790        # slot 0x30, shared
SLOT38_RESOLVE = 0x5D2E090      # slot 0x38, shared
SLOT38_RESOLVER = 0x60958C0     # the shared name->field scan
SLOT48_HOST_A = 0x609D0E0       # slot 0x48, shared
SLOT50_SET_OPTION = 0x60986B0   # slot 0x50, shared
SLOT58_VALIDATE = 0x6095710     # slot 0x58, shared
SLOT60_SERIALIZE = 0x609DE80    # slot 0x60, shared
SLOT68_DOTTED = 0x609D980       # slot 0x68, shared
SLOT98_UNWRAP = 0x5FD5A00       # slot 0x98, Composite/Posix/Mock
SLOT98_UNWRAP_SCW = 0x5D4D490   # slot 0x98, SystemClockWrapper
SLOT98_TERMINAL = 0x5FCC240     # the terminal slot-0x98 stub
SLOT98_POSIX_CLOCK = 0x5FE1540  # slot 0x98, PosixClock
SLOT98_EMULATED = 0x60259E0     # slot 0x98, EmulatedSystemClock
SLOT98_STATISTICS = 0x6070490   # slot 0x98, StatisticsImpl
MOCKENV_IS_INSTANCE_OF = 0x5FD6240

# find_entry (0x609e510) delegate dispatch sites.
FIND_ENTRY = 0x609E510
DELEGATE_IMPL = 0x6097110
CREATE_HOST = 0x6077820

# GOT landmarks: GOT slot -> the function the relocation binds.
GOT = {
    0x64ECEB8: 0x5D2E770,  # canonical IsInstanceOf
    0x64ECEB0: 0x5D2CA10,  # canonical NickName (Env "")
    0x64ECF50: 0x5D48960,  # forwarder
    0x64ECF80: 0x5D4D490,  # unwrap (slot 0x98, SCW)
    0x64ED8B0: 0x5FCC240,  # terminal slot-0x98 stub
}

# --- Name() / NickName() literals (slots 0x70 / 0x90) --------------------

# Classes whose slot 0x70 returns a literal. SystemClockWrapper's
# slot 0x70 is NULL (pure virtual); the Configurable and Logger
# tables have no slot 0x70 at all.
NAME = {
    "Env": "",
    "CompositeEnv": "",
    "CompositeEnvWrapper": "CompositeEnv",
    "PosixClock": "DefaultClock",
    "PosixEnv": "PosixEnv",
    "MockEnv": "MockEnv",
    "EmulatedSystemClock": "TimeEmulatedSystemClock",
    "StatisticsImpl": "BasicStatistics",
}

NULL_NAME_SLOT = {"SystemClockWrapper"}

NO_NAME_SLOT = {
    "EnvLogger", "TestMemLogger", "AutoRollLogger",
    "MockEnvDirectory", "MockEnvFileLock",
    "Configurable", "ConfigurableCFOptions",
    "ConfigurableMutableCFOptions", "MutableDBConfigurable",
    "DBOptionsConfigurable",
}

# NickName() per class; every family class not listed here uses the
# shared 0x5d2ca10, which returns "".
NICKNAME = {
    "PosixClock": "PosixClock",
    "PosixEnv": "DefaultEnv",
}

# Slot 0x88: the object offset the wrapped object is read from.
# Env (and the classes that share its 0x5d2ca00) return 0.
WRAPPED_OFFSET = {
    "SystemClockWrapper": 0x20,
    "EmulatedSystemClock": 0x20,
    "CompositeEnvWrapper": 0x48,
    "MockEnv": 0x48,
    "StatisticsImpl": 0x28,
}

# Slot 0x98 function per class (only classes whose table reaches
# 0x98 have one).
SLOT98 = {
    "Env": 0x5FCC0E0,
    "CompositeEnv": SLOT98_UNWRAP,
    "CompositeEnvWrapper": SLOT98_UNWRAP,
    "PosixEnv": SLOT98_UNWRAP,
    "MockEnv": SLOT98_UNWRAP,
    "SystemClockWrapper": SLOT98_UNWRAP_SCW,
    "PosixClock": SLOT98_POSIX_CLOCK,
    "EmulatedSystemClock": SLOT98_EMULATED,
    "StatisticsImpl": SLOT98_STATISTICS,
}

# --- the 80-byte option value struct --------------------------------------

VALUE_STRUCT_SIZE = 80
VALUE_KIND_OFFSET = 0x28   # u32 kind (slots 0x28/0x30/0x60 gates)
VALUE_FLAGS_OFFSET = 0x2C  # u8 flags (slot 0x18 gate: > 2 forwards)
VALUE_KIND_BYTE_OFFSET = 0x04  # u8 kind byte (slot 0x50 dispatch)

MASK64 = (1 << 64) - 1


def vtable_base(cls):
    """The vtable base address for a delegate-family class."""
    return VTABLES[cls]


def name(cls):
    """Name() (slot 0x70): the class name literal.

    Returns None for SystemClockWrapper, whose slot 0x70 is NULL
    (pure virtual); raises ValueError for classes whose table has
    no slot 0x70 at all (Configurable/Logger families).
    """
    if cls in NULL_NAME_SLOT:
        return None
    if cls in NO_NAME_SLOT:
        raise ValueError("no slot 0x70 for %s" % cls)
    return NAME[cls]


def nickname(cls):
    """NickName() (slot 0x90): "" except PosixClock/PosixEnv."""
    if cls in NO_NAME_SLOT:
        raise ValueError("no slot 0x90 for %s" % cls)
    return NICKNAME.get(cls, "")


def is_instance_of(cls, candidate):
    """IsInstanceOf (slot 0x80): 1 when candidate matches Name() or
    NickName() by length then memcmp, else 0.

    MockEnv and CompositeEnvWrapper override the canonical
    (0x5fd6240): "CompositeEnv" returns 1, anything else tail-jumps
    to the canonical. SystemClockWrapper has a NULL Name(), so only
    its NickName "" can match.
    """
    if cls in NO_NAME_SLOT:
        raise ValueError("no slot 0x80 for %s" % cls)
    if cls in ("MockEnv", "CompositeEnvWrapper") \
            and candidate == "CompositeEnv":
        return 1
    n = name(cls)
    if n is not None and len(candidate) == len(n) and candidate == n:
        return 1
    nick = nickname(cls)
    if len(candidate) == len(nick) and candidate == nick:
        return 1
    return 0


def is_instance_of_canonical(cls):
    """Whether find_entry's slot-0x80 identity check passes for this
    delegate: find_entry compares the delegate's slot-0x80 pointer
    against the canonical 0x5d2e770 (GOT 0x64eceb8). MockEnv and
    CompositeEnvWrapper override it (0x5fd6240), so both fail the
    check."""
    if cls in NO_NAME_SLOT:
        raise ValueError("no slot 0x80 for %s" % cls)
    return cls not in ("MockEnv", "CompositeEnvWrapper")


def wrapped_object(cls, fields):
    """The wrapped/parent object (slot 0x88).

    fields maps object offsets to values. Env returns 0 (no wrapped
    object); the wrappers read their wrapped-object offset.
    """
    if cls in NO_NAME_SLOT:
        raise ValueError("no slot 0x88 for %s" % cls)
    off = WRAPPED_OFFSET.get(cls)
    if off is None:
        return 0
    return fields.get(off, 0)


def zero_status():
    """A zeroed 16-byte Status (slot 0x40: u32 0, u16 0, u64 0)."""
    return b"\x00" * 16


def resolve_name(records, candidate):
    """The shared resolver 0x60958c0 (slot 0x38's worker).

    records is a list of (name_bytes, field) pairs in array order,
    the 0x30-byte records the resolver scans. Returns the first
    record's +0x20 field whose name matches candidate by length
    then memcmp, or None when no record matches.
    """
    for rec_name, field in records:
        if len(rec_name) == len(candidate) and rec_name == candidate:
            return field
    return None


def dotted_name(cls, candidate):
    """Dotted-name lookup (slot 0x68): strip the delegate's Name()
    + '.' prefix from candidate and return the remainder; return
    None when the name does not start with that prefix (the binary
    then falls back to Configurable 0x6095a60, a std::string copy).
    Raises when Name() is NULL (SystemClockWrapper: the binary
    throws std::logic_error)."""
    n = name(cls)
    if n is None:
        raise ValueError("Name() is NULL for %s" % cls)
    prefix = n + "."
    if candidate.startswith(prefix):
        return candidate[len(prefix):]
    return None


def get_option_id(option_name, delegate_name):
    """GetOption (slot 0x10) fast path: when the option name is
    exactly "id", return (delegate_name, zero_status()); otherwise
    return None, meaning the binary forwards to Configurable's
    slot 0x10 (0x6099030)."""
    if option_name == "id":
        return delegate_name, zero_status()
    return None


def configure_option(value_flags, delegate, this_name, delegate_name):
    """ConfigureOption (slot 0x18) guards, in order.

    value_flags is the value struct's +0x2c byte; delegate is the
    delegate object (None when null); this_name/delegate_name are
    the two names compared through slot 0x78. Returns
    (action, code, new_name):
      ("return", 1, None) -- value_flags <= 1, or out == delegate,
          or the names match;
      ("return", 0, None) -- the delegate is null;
      ("forward", None, "id") -- the names mismatch and
          value_flags > 2: the option name is rewritten to "id"
          and the binary forwards to Configurable 0x60996a0;
      ("return", 1, "id") -- the names mismatch and
          value_flags <= 2: the name is rewritten to "id" and it
          returns 1.
    """
    if value_flags <= 1:
        return ("return", 1, None)
    if delegate is None:
        return ("return", 0, None)
    if this_name == delegate_name:
        return ("return", 1, None)
    if value_flags > 2:
        return ("forward", None, "id")
    return ("return", 1, "id")


def set_option(kind_byte, changeable, option_name):
    """SetOption (slot 0x50) dispatch on the value kind byte (+0x04)
    and the changeable flag. Returns:
      ("forward",) -- kind 0, or kind != 0 with the flag set (the
          binary forwards to worker 0x60bedc0);
      ("error", msg) -- kind != 0 with the flag clear: the binary
          reports "Option not changeable: " + name (code 4).
    """
    if kind_byte == 0 or changeable:
        return ("forward",)
    return ("error", "Option not changeable: " + option_name)


def validate(kind_ok, fallback_ok, target_name):
    """Validate (slot 0x58): calls the kind validator 0x60bf980,
    then 0x60bf7c0. Returns (1, name): always 1; the target name is
    blanked (replaced with "") only when both validators reject."""
    if kind_ok or fallback_ok:
        return 1, target_name
    return 1, ""


def serialize_id(options_name, delegate_name, value_name, kind):
    """Serialize (slot 0x60) id composition: when the value kind
    (+0x28) is 1 or the delegate name is empty, the out string is
    <options name> + "id" + "=" + <delegate name> + <value name>;
    otherwise return None, meaning the binary forwards to
    Configurable 0x60985e0."""
    if kind == 1 or delegate_name == "":
        return options_name + "id" + "=" + delegate_name + value_name
    return None


def parse_gate_28(kind_qword, flag_40_clear, sub_a0_nonnull):
    """Slot 0x28 worker gate: the worker 0x60b9e00 fires when
    (HIGH dword of the +0xd0 qword - 4) > 1 (unsigned; a high dword
    of 0..3 wraps and also passes) and the 0x40 bit of the byte at
    +0xd9 is clear and (the materialized +0xa0 sub-value's first
    qword is non-null or (LOW dword of the +0xd0 qword - 0x15)
    <= 1 unsigned). The binary has two identical gate sites: when
    +0xc0 is null it skips materializing that sub-value and jumps
    to the second site, which runs the same predicate."""
    hi = (kind_qword >> 32) & 0xFFFFFFFF
    lo = kind_qword & 0xFFFFFFFF
    if (hi - 4) & 0xFFFFFFFF <= 1:
        return False
    if not flag_40_clear:
        return False
    if sub_a0_nonnull:
        return True
    return (lo - 0x15) & 0xFFFFFFFF <= 1


def parse_gate_30(kind_qword, sub_c0_nonnull):
    """Slot 0x30 worker gate: the worker 0x60b9f50 fires when
    (HIGH dword of the +0xd0 qword - 4) > 1 (unsigned) and (the raw
    +0xc0 function pointer is non-null or (LOW dword of the +0xd0
    qword - 0x15) <= 1 unsigned). No 0x40 flag check. When +0xc0 is
    null the binary skips materializing it and jumps to a second
    gate site that runs the same predicate without the +0xc0
    branch."""
    hi = (kind_qword >> 32) & 0xFFFFFFFF
    lo = kind_qword & 0xFFFFFFFF
    if (hi - 4) & 0xFFFFFFFF <= 1:
        return False
    if sub_c0_nonnull:
        return True
    return (lo - 0x15) & 0xFFFFFFFF <= 1


def posix_clock_now(tv_sec, tv_usec):
    """PosixClock slot 0x98 (0x5fe1540): gettimeofday, returned as
    tv_sec * 1,000,000 + tv_usec (microseconds since the epoch)."""
    return (tv_sec & MASK64) * 1000000 + tv_usec


def emulated_clock_now(flag_set, wrapped_now, offset):
    """EmulatedSystemClock slot 0x98 (0x60259e0): when the flag byte
    at +0x48 is clear, call the wrapped clock's (at +0x20) slot
    0x98; return that result plus the offset at +0x40 (0 when the
    flag is set)."""
    base = 0 if flag_set else wrapped_now
    return (base + offset) & MASK64


def unwrap_chain(slot98_chain):
    """SystemClockWrapper slot 0x98 (0x5d4d490): walk the +0x20
    chain, comparing each level's slot-0x98 against the GOT slot
    0x64ecf80 (0x5d4d490 itself), 10 levels unrolled, then tail-jump
    to the innermost slot-0x98.

    slot98_chain is the list of slot-0x98 function addresses from
    the outermost wrapper inward. Returns the address the binary
    tail-jumps to: the first level whose slot-0x98 is not the
    unwrap itself, or the innermost level's slot-0x98 when every
    level in the chain is the unwrap (None for an empty chain).
    """
    for fn in slot98_chain[:10]:
        if fn != SLOT98_UNWRAP_SCW:
            return fn
    if not slot98_chain:
        return None
    return slot98_chain[min(len(slot98_chain), 10) - 1]
