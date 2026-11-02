"""RE-001: node #94 member construction with probe install (0x5169250).

The binary builds a 0x80-byte member object from a host object, an
options object and an inner object:

* Factory: the inner object's +0x18 virtual is called with
  (inner, 0x80, 0) and its result is the member.  The factory's
  internals are by contract; the model takes it as a callable.
* Zeroing: 0x541ca90 zeroes member +0x8 and member +0x20.
* Field installs (all by plain stores): vtable address points
  0x575b230 at +0x0, 0x575b1f8 at +0x38, 0x5757be0 at +0x40;
  +0x30 = host +0xc58; +0x48 = host +0x10; +0x58 (u16) = 0x100;
  +0x5a (u8) = host +0x31 byte XOR 1; +0x60 = host +0x6c u32
  zero-extended; +0x68 (u32) = 0; +0x6c (u16) = 0; +0x70 = 0;
  +0x78 = host +0x60; +0x28 = 0 unless the probe gate fires.
* Probe gate: host +0xc58 non-null AND options +0x30 byte == 0
  AND options +0x31 byte == 0.  On the probe path member +0x28 =
  host +0xc60.
* +0x50 dispatch: the default path calls the host +0xa50 object's
  +0x90 virtual with (that object, inner).  On the probe path the
  +0x98 field of *(host +0xa50) is compared against GOT slot
  0x57783c0 (RELATIVE addend 0x5164750): equal takes the +0x90
  virtual arm, unequal calls the +0x98 field value directly with
  the same two arguments.  The result is stored to member +0x50.
* Exception cleanup (0x5169220): when member +0x70 is non-null it
  is freed with operator delete[]; the member vtable pointer is
  reset to 0x57593f8; the member +0x8 subobject is drained through
  0x541cab0; unwinding then resumes.  The model reports the freed
  flag and the reset vtable instead of raising.

The model returns the member as a dict keyed by field offset, so
tests can check every install end to end.  It does not claim class
names: "host", "options", "inner" and "member" are roles.
"""

KNOWN_98 = 0x5164750  # R_X86_64_RELATIVE addend of GOT slot 0x57783c0
VTABLE_MAIN = 0x575B230
VTABLE_38 = 0x575B1F8
VTABLE_40 = 0x5757BE0
VTABLE_RESET = 0x57593F8


class FactoryObject:
    """The host +0xa50 object: a +0x90 virtual result and a +0x98 field."""

    def __init__(self, virtual90_result, field98):
        self.virtual90_result = virtual90_result
        self.field98 = field98


def construct_member(host, options, factory, a50):
    """Build the member dict.

    host: dict with keys f10, b31, f60, f6c, c58, c60.
    options: dict with keys b30, b31.
    factory: callable(inner) -> anything (its identity is not modelled;
        the member dict is the result, as the binary returns the
        factory's object after filling it).
    a50: FactoryObject for host +0xa50; inner is passed through as
        the factory/a50 call argument and is not inspected.
    Returns (member, probe_path_taken).
    """
    inner = host.get("inner")
    factory(inner)  # the +0x18 virtual call with (inner, 0x80, 0)
    member = {}
    member[0x00] = VTABLE_MAIN
    member[0x08] = 0  # via 0x541ca90 on member + 0x8
    member[0x20] = 0  # via 0x541ca90 (argument + 0x18)
    member[0x28] = 0
    member[0x30] = host["c58"]
    member[0x38] = VTABLE_38
    member[0x40] = VTABLE_40
    member[0x48] = host["f10"]
    member[0x58] = 0x100
    member[0x5A] = host["b31"] ^ 1
    member[0x60] = host["f6c"] & 0xFFFFFFFF
    member[0x68] = 0
    member[0x6C] = 0
    member[0x70] = 0
    member[0x78] = host["f60"]
    probe = (
        host["c58"] is not None
        and options["b30"] == 0
        and options["b31"] == 0
    )
    if probe:
        member[0x28] = host["c60"]
        if a50.field98 == KNOWN_98:
            member[0x50] = a50.virtual90_result
        else:
            member[0x50] = ("direct98", a50.field98)
    else:
        member[0x50] = a50.virtual90_result
    return member, probe


def cleanup_member(member):
    """Model the 0x5169220 exception cleanup.

    Returns (freed, vtable_after, drained) where drained records that
    the member +0x8 subobject was passed to 0x541cab0.
    """
    freed = member.get(0x70) is not None
    return freed, VTABLE_RESET, True
