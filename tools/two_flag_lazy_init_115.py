"""Python model of node #115's two-flag lazy-init variant 0x605e8a0,
its wrapper 0x605e8f0 and its callback 0x606a890.

Implements the semantics pinned by
research/work-items/RE-001-two-flag-lazy-init-115. The first-flag
lazy-init (0x605e860, mapped by #2244) is taken as an injected
callable rather than re-implemented, because it is mapped elsewhere;
the callback's call target 0x606a170 and tail-jump target 0x606a650
are likewise injected, because they are by contract only in this
packet.

State shapes (all plain dicts, no binary layout):

- A holder is ``{"inner": inner_or_None, "cb_arg": value,
  "flag10": int, "flag11": int}``: ``inner`` mirrors [holder],
  ``cb_arg`` the qword at holder + 0x08, ``flag10`` the byte at
  holder + 0x10, ``flag11`` the byte at holder + 0x11.
- An inner object is ``{"first": value_or_None, "field20": int,
  "field10": int}``: ``first`` mirrors [inner] (None stands for the
  qword 0), ``field20`` the qword at inner + 0x20, ``field10`` the
  qword at inner + 0x10 that the callback subtracts from.

Model-side guards (not binary behavior, stated explicitly): the
binary has no consistency check on the flag byte range and would
fault on a dangling pointer. ``variant_init`` and ``callback`` raise
ValueError when a flag is outside 0..255 so the Python model always
stays consistent; tests pin the guard.
"""

MASK64 = (1 << 64) - 1


def _check_flag(value, name):
    if not 0 <= value <= 255:
        raise ValueError("%s out of byte range: %r" % (name, value))


def callback(obj, amount, on_170, delegate):
    """Refcount-style callback 0x606a890.

    If [object + 0x20] != 0, calls ``on_170`` and skips the subtract;
    else if [object] == 0, skips the subtract; else atomically
    subtracts ``amount`` from [object + 0x10] (64-bit wrapping).
    Every path ends by calling ``delegate`` with the object, mirroring
    the tail jump to 0x606a650.
    """
    if obj["field20"] != 0:
        on_170(obj)
    elif obj["first"] is not None:
        obj["field10"] = (obj["field10"] - amount) & MASK64
    delegate(obj)


def variant_init(holder, lazy_init, callback_fn):
    """Two-flag lazy-init variant 0x605e8a0.

    ``lazy_init`` is the first-flag function 0x605e860 (mapped by
    #2244); ``callback_fn`` is ``callback`` above (or a recording
    stand-in with the same signature in tests). The inner pointer is
    re-read after the lazy-init call, exactly as in the binary.
    """
    _check_flag(holder["flag10"], "flag10")
    _check_flag(holder["flag11"], "flag11")
    if holder["flag10"] == 0:
        lazy_init(holder)
    inner = holder["inner"]
    if inner is None:
        return
    if holder["flag11"] != 0:
        return
    if inner["first"] is not None or inner["field20"] != 0:
        callback_fn(inner, holder["cb_arg"])
    holder["flag11"] = 1


def wrapper(holder, lazy_init, callback_fn):
    """Forwarding wrapper 0x605e8f0: forwards the holder unchanged."""
    variant_init(holder, lazy_init, callback_fn)
