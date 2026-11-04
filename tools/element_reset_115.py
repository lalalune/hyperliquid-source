"""Python model of node #115's element-reset function 0x5f54ee0.

Implements the semantics pinned by
research/work-items/RE-001-element-reset-115: a whole-function
reset/clear, not a lone-window fragment. The function zeroes head
scalars, disposes three arrays and one linked list, resets the list
header, and finishes with tail-scalar stores. The recursive callee
0x5f53f50 is by contract only (its internals were not read): the
model calls the supplied ``node_callback`` once per list node with
that node's callee argument, in walk order, and records the
operator-delete of the node itself. The PLT operator delete is also
by contract: a heap buffer is recorded as deleted, a null buffer is
a no-op, and an embedded (SSO) buffer is never deleted.

An object is a dict:

- "dword_0x00": int, "buf_0x08": bytearray or None, "qword_0x10": int
- "field_0x20": int, untouched by the function, carried through
- "buf_0x28": bytearray or None, "qword_0x30": int
- "block_0x48": bytearray of length 0x38, covering + 0x48..+ 0x7f;
  bytes at indices 0x1c..0x1f (+ 0x64..+ 0x67) are NOT written
- "array_0x80": {"elements": [...], "live": int}; each element holds
  one string field {"ptr": ..., "other": int} under "field", where
  "ptr" is EMBEDDED for an SSO buffer, None for no buffer, or a
  token for a heap buffer; "other" is the qword the binary adds 1
  to for the delete size argument
- "list_0xa8": {"head": node or None, "field_0xb0": ..., "field_0xb8":
  ..., "field_0xc0": ...}; a node is {"id": token, "next": node or
  None, "callee_arg": value}
- "array_0xc8": {"elements": [...], "live": int}; each element holds
  four string fields under "f_0x100", "f_0xe0", "f_0x50", "f_0x30",
  disposed in exactly that order
- "array_0xe0": {"elements": [...], "live": int}; each element holds
  two string fields under "f_0x38", "f_0x18", disposed in that order
- "field_0xf8", "field_0x100", "field_0x110", "field_0x118": ints
- "field_0x128", "field_0x130", "field_0x134", "field_0x140": ints;
  "buf_0x138": bytearray or None
- "field_0x158", "field_0x15c", "field_0x168": ints;
  "buf_0x160": bytearray or None

Arrays keep their element lists after the reset (the binary frees
no backing store); only "live" drops to 0, matching the binary's
end := begin store. Returns {"deletes": [(target, size), ...],
"node_calls": [callee_arg, ...]} in execution order.
"""

MASK64 = (1 << 64) - 1


class _Embedded:
    pass


EMBEDDED = _Embedded()


def string_field(ptr, other):
    """One string-like field: ptr is EMBEDDED, None, or a token."""
    return {"ptr": ptr, "other": other}


def _dispose(field, deletes):
    """The binary's dispose: skip SSO buffers, delete heap buffers."""
    ptr = field["ptr"]
    if ptr is EMBEDDED or ptr is None:
        return
    deletes.append((ptr, (field["other"] + 1) & MASK64))


def _clear_buffer(buf, what):
    if buf is None:
        raise ValueError("null buffer at %s would fault" % what)
    buf[0] = 0


def element_reset(obj, node_callback):
    """The 0x5f54ee0 window. Returns the delete/node-call log."""
    deletes = []
    node_calls = []

    # Head scalars: dword at + 0x00, qword at + 0x10, first byte of
    # the buffer at + 0x08; then the buffer at + 0x28 and the qword
    # at + 0x30. Field + 0x20 is never written.
    obj["dword_0x00"] = 0
    obj["qword_0x10"] = 0
    _clear_buffer(obj["buf_0x08"], "+0x08")
    obj["qword_0x30"] = 0
    _clear_buffer(obj["buf_0x28"], "+0x28")

    # Block + 0x48..+ 0x7f: everything zeroed except + 0x64..+ 0x67.
    block = obj["block_0x48"]
    for index in range(len(block)):
        if 0x1C <= index <= 0x1F:
            continue
        block[index] = 0

    # First array (+ 0x80, stride 0x28): one dispose per live element.
    first = obj["array_0x80"]
    for element in first["elements"][:first["live"]]:
        _dispose(element["field"], deletes)
    first["live"] = 0

    # Linked list (+ 0xa8): per node, the 0x5f53f50 call by contract
    # with the field at + 0x18, then delete of the 0x30-byte node;
    # then the header reset.
    lst = obj["list_0xa8"]
    node = lst["head"]
    while node is not None:
        node_calls.append(node["callee_arg"])
        node_callback(node["callee_arg"])
        deletes.append((node["id"], 0x30))
        node = node["next"]
    lst["head"] = None
    lst["field_0xb0"] = "embedded_0xa0"
    lst["field_0xb8"] = "embedded_0xa0"
    lst["field_0xc0"] = 0

    # Second array (+ 0xc8, stride 0x130): four disposes per element.
    second = obj["array_0xc8"]
    for element in second["elements"][:second["live"]]:
        for key in ("f_0x100", "f_0xe0", "f_0x50", "f_0x30"):
            _dispose(element[key], deletes)
    second["live"] = 0

    # Third array (+ 0xe0, stride 0x58): two disposes per element.
    third = obj["array_0xe0"]
    for element in third["elements"][:third["live"]]:
        for key in ("f_0x38", "f_0x18"):
            _dispose(element[key], deletes)
    third["live"] = 0

    # Tail scalars: conditional stores, then the zero stores and
    # the two buffer-byte stores.
    obj["field_0x100"] = obj["field_0xf8"]
    obj["field_0x118"] = obj["field_0x110"]
    obj["field_0x128"] = 0
    obj["field_0x130"] = 0
    obj["field_0x134"] = 0
    obj["field_0x140"] = 0
    _clear_buffer(obj["buf_0x138"], "+0x138")
    obj["field_0x158"] = 0
    obj["field_0x15c"] = 0
    obj["field_0x168"] = 0
    _clear_buffer(obj["buf_0x160"], "+0x160")

    return {"deletes": deletes, "node_calls": node_calls}
