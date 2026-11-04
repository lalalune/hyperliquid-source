"""Python model of node #115's lazy-init 0x605e860 and its callback
0x606a110.

Implements the semantics pinned by
research/work-items/RE-001-lazy-init-callback-115. The lazy-init was
mapped by #2244 only as far as its call site to this callback; this
packet closes that callee and models the two functions end to end,
from the holder through the flag gate to the callback's store.

State shapes (all plain dicts, no binary layout):

- A holder is ``{"inner": inner_or_None, "cb_arg": value,
  "flag10": int}``: ``inner`` mirrors [holder], ``cb_arg`` the qword
  at holder + 0x08, ``flag10`` the byte at holder + 0x10.
- An inner object is ``{"first": value_or_None, "field20": int,
  "field18": int}``: ``first`` mirrors [inner] (None stands for the
  qword 0), ``field20`` the qword at inner + 0x20, ``field18`` the
  qword at inner + 0x18 that the callback subtracts from.

Model-side guards (not binary behavior, stated explicitly): the
binary has no consistency check on the flag byte range and would
fault on a dangling pointer. ``lazy_init`` raises ValueError when
the flag is outside 0..255 so the Python model always stays
consistent; tests pin the guard.
"""

MASK64 = (1 << 64) - 1


def _check_flag(value, name):
    if not 0 <= value <= 255:
        raise ValueError("%s out of byte range: %r" % (name, value))


def callback(inner, amount):
    """Callback 0x606a110.

    If [inner] == 0, returns at once with no store; otherwise
    atomically subtracts ``amount`` from [inner + 0x18] (64-bit
    wrapping, the ``lock sub``). Returns void either way.
    """
    if inner["first"] is None:
        return
    inner["field18"] = (inner["field18"] - amount) & MASK64


def lazy_init(holder):
    """Lazy-init 0x605e860, end to end including its callback.

    Inner null returns at once, flag untouched; flag [holder + 0x10]
    != 0 returns at once, flag untouched; otherwise the callback
    runs exactly when [inner] != 0 or [inner + 0x20] != 0, then the
    flag is set to 1 whether or not the callback ran. Note the
    callback's own null arm is reachable exactly through the
    [inner] == 0 and [inner + 0x20] != 0 arm: the callback re-reads
    [inner] and returns without storing.
    """
    _check_flag(holder["flag10"], "flag10")
    inner = holder["inner"]
    if inner is None:
        return
    if holder["flag10"] != 0:
        return
    if inner["first"] is not None or inner["field20"] != 0:
        callback(inner, holder["cb_arg"])
    holder["flag10"] = 1
