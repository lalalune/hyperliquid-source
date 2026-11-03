"""Python model of node #115's sibling drain driver 0x5f140c0, its
wrapper 0x5f14090, its pre-call 0x5f127b0 and its lazy-init callee
0x605e860.

Implements the semantics pinned by
research/work-items/RE-001-sibling-driver-115. The prepare (0x5f13f90,
mapped by #2242), the drain (0x5f14000, mapped by #2236), the refresh
(0x5f13450, mapped by #2242) and the aggregate (0x5f0e2d0, mapped by
#2046) are taken as injected callables rather than re-implemented,
because they are mapped elsewhere; the dispatch slot callee, the
lazy-init callback (0x606a110) and the list hook are likewise
injected, because they are by contract only in this packet.

State shapes (all plain dicts, no binary layout):

- An outer object is ``{"inner": inner, "counter": int,
  "first_flag": int, "flag": int}``: ``inner`` mirrors [outer + 0x08],
  ``counter`` the signed 32-bit counter at outer + 0x10, ``first_flag``
  the byte at outer + 0x00, ``flag`` the byte at outer + 0x01.
- An inner object for the pre-call is ``{"position": object,
  "counter": int, "sum": int}``: ``position`` mirrors [inner],
  ``counter`` the qword at inner + 0x10, ``sum`` the qword pointed to
  by [inner + 0x48].
- A collection object is ``{"dispatch_object": obj,
  "lazy": lazy_arg}``: ``dispatch_object`` mirrors [collection +
  0xa50], ``lazy`` the lazy-init argument at collection + 0x80.
- A dispatch object is ``{"slot": slot}``: ``slot`` mirrors the qword
  at [dispatch_object + 0x50]; ``DEFAULT_SLOT`` stands for the
  function at 0x5f04d50, the runtime value of the .got sentinel.
- A lazy-init argument is ``{"inner": inner_or_None, "cb_arg": value,
  "flag": int}``: ``inner`` mirrors [arg], ``cb_arg`` the qword at
  arg + 0x08, ``flag`` the byte at arg + 0x10. Its inner object is
  ``{"first": value_or_None, "field20": int}`` mirroring [inner] and
  [inner + 0x20].

Model-side guards (not binary behavior, stated explicitly): the
binary has no consistency check on the flag byte range and would
fault on a dangling pointer. ``drive`` raises ValueError when a flag
is outside 0..255 so the Python model always stays consistent;
tests pin the guard.
"""

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
DEFAULT_SLOT = "default-0x5f04d50"


def _check_flag(value, name):
    if not 0 <= value <= 255:
        raise ValueError("%s out of byte range: %r" % (name, value))


def pre_call(inner, collection, aggregate, hook):
    """List-append pre-step 0x5f127b0.

    Allocates a fresh node holding ``collection``, hooks it with the
    position [inner] (recorded through ``hook``), increments the
    inner counter at +0x10, and adds the aggregate of the collection
    into the sum pointed to by [inner + 0x48]. Returns the node.
    The exception-path cold block is not modelled.
    """
    node = {"collection": collection}
    hook(node, inner["position"])
    inner["counter"] = (inner["counter"] + 1) & MASK64
    inner["sum"] = (inner["sum"] + aggregate(collection)) & MASK64
    return node


def wrapper(inner, collection, predicate_arg, pre_call_fn, drain):
    """Wrapper 0x5f14090: pre-call, then the drain with arg 0.

    The driver's predicate argument never reaches the drain: the
    wrapper replaces it with 0. Returns the drain's result.
    """
    pre_call_fn(inner, collection)
    return drain(inner, collection, 0)


def lazy_init(arg, callback):
    """Once-flag lazy init 0x605e860.

    Returns without touching the flag when the inner pointer is null
    or the flag is already nonzero. Otherwise calls ``callback`` with
    (inner, cb_arg) exactly when the inner's first qword is non-null
    or its +0x20 qword is nonzero, then sets the flag to 1 whether
    or not the callback ran.
    """
    _check_flag(arg["flag"], "lazy flag")
    inner = arg["inner"]
    if inner is None:
        return
    if arg["flag"] != 0:
        return
    if inner["first"] is not None or inner["field20"] != 0:
        callback(inner, arg["cb_arg"])
    arg["flag"] = 1


def drive(outer, collection, predicate_arg, prepare, wrapper_fn,
          dispatch, refresh, callback):
    """Sibling drain driver 0x5f140c0. Returns 1 unconditionally.

    Sequence: prepare (args forwarded unchanged); re-read the inner
    pointer (prepare may have replaced it); wrapper on the fresh
    inner; dispatch check on [collection + 0xa50] (call the slot
    unless it is the default, return ignored); lazy-init on
    collection + 0x80; wrapping 32-bit counter increment at
    outer + 0x10, setting the byte at outer + 0x00 exactly when the
    incremented counter equals 1; refresh; conditional clear of the
    byte at outer + 0x01 iff it is exactly 1.
    """
    _check_flag(outer["flag"], "outer flag")
    _check_flag(outer["first_flag"], "first-run byte")
    prepare(outer, collection, predicate_arg)
    inner = outer["inner"]
    wrapper_fn(inner, collection, predicate_arg)
    dispatch_object = collection["dispatch_object"]
    if dispatch_object["slot"] != DEFAULT_SLOT:
        dispatch(dispatch_object)
    lazy_init(collection["lazy"], callback)
    outer["counter"] = (outer["counter"] + 1) & MASK32
    if outer["counter"] == 1:
        outer["first_flag"] = 1
    refresh(outer)
    if outer["flag"] == 1:
        outer["flag"] = 0
    return 1
