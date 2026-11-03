"""Python model of node #115's drain driver 0x5f14180, its prepare
callee 0x5f13f90 and its refresh callee 0x5f13450.

Implements the semantics pinned by
research/work-items/RE-001-drain-driver-115. The drain (0x5f14000,
mapped by #2236) and the aggregate (0x5f13130, mapped by #2182) are
taken as injected callables rather than re-implemented, because they
are mapped elsewhere; the move helper (0x5f12840) and the init helper
(0x5f12a00) are likewise injected, because they are by contract only
in this packet.

State shapes (all plain dicts, no binary layout):

- An outer object is ``{"inner": inner, "flag": int, "agg": int,
  "nonempty": int}``: ``inner`` mirrors [outer + 0x08], ``flag`` the
  byte at outer + 0x01, ``agg`` [outer + 0x20], ``nonempty`` the byte
  at outer + 0x28.
- An inner object is ``{"refcount": int, "list": [...]}``: ``refcount``
  mirrors [inner + 0x40], ``list`` the list headed at inner + 0x18
  (first-to-last order; empty means the header points at itself).

Model-side guards (not binary behavior, stated explicitly): the
binary has no consistency check on the flag byte range and would
fault on a dangling pointer. ``drive`` raises ValueError when the
flag is outside 0..255 so the Python model always stays consistent;
tests pin the guard.
"""


def prepare(outer, move, init):
    """Copy-on-write prepare 0x5f13f90.

    Returns the inner object the driver must drain: the original one
    when its refcount is exactly 1, otherwise a fresh inner produced
    by the injected ``move``/``init`` pair, with the old inner
    released (its refcount decremented; the destroy-on-zero path is
    the caller's ``release`` bookkeeping, recorded on the old inner
    as ``released`` when it reaches zero).
    """
    inner = outer["inner"]
    if inner["refcount"] == 1:
        return inner
    new = move(outer, inner)
    init(new)
    outer["inner"] = new
    inner["refcount"] -= 1
    if inner["refcount"] == 0:
        inner["released"] = True
    return new


def refresh(outer, aggregate):
    """Aggregate cache + nonempty byte 0x5f13450."""
    inner = outer["inner"]
    outer["agg"] = aggregate(inner)
    outer["nonempty"] = 1 if inner["list"] else 0


def drive(outer, collection, pred_arg, prepare_fn, drain_fn, refresh_fn):
    """Driver 0x5f14180 end to end.

    Sequence, exactly as in the binary: prepare, reload the (possibly
    swapped) inner, drain, refresh, conditional flag clear, return
    the drain's result. The flag byte is cleared iff it is exactly 1;
    any other value is left unchanged (the binary's cmpxchg stack
    byte is dead and is not modelled).
    """
    if not 0 <= outer["flag"] <= 255:
        raise ValueError("flag byte out of range")
    prepare_fn(outer)
    inner = outer["inner"]
    popped = drain_fn(inner, collection, pred_arg)
    refresh_fn(outer)
    if outer["flag"] == 1:
        outer["flag"] = 0
    return popped
