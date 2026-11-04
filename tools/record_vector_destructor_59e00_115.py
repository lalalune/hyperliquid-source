#!/usr/bin/env python3
"""Model of node #115 routine 0x5d59e00 (FDE 0x5d59e00..0x5d5a1fe).

Record-vector destructor:

1. The holder in rdi is a vector triple: begin at holder+0x00, end
   at holder+0x08, capacity end at holder+0x10. Records are
   0x300 bytes; the loop walks [begin, end) in steps of 0x300.
   An empty range skips the loop. A null begin returns plainly
   with nothing freed.
2. Per record, thirteen phases run in a fixed order:
   (1) inlined refcounted release at +0x2f8, (2) the same at
   +0x2e8, (3) string-vector teardown at +0x2c8/+0x2d0/+0x2d8,
   (4) refcounted-pointer release at +0x2c0 via helper 0x5d350c0,
   (5) inlined refcounted release at +0x298, (6) helper release
   at +0x210, (7) helper release at +0x1f8, (8) helper release
   at +0x1d8, (9) shared-pointer vector teardown at
   +0x138/+0x140/+0x148, (10) helper release at +0x130,
   (11) plain buffer free at +0xb0/+0xc0, (12) plain buffer
   free at +0x70/+0x80, (13) helper release at +0x58.
3. Exit: the outer buffer is freed with a sized delete of
   ([holder+0x00], [holder+0x10] - [holder+0x00]) through the
   _ZdlPvm PLT at 0x63f0d80. The holder itself is never freed.

Refcounted release contract (shared by the inlined releases, the
shared-vector elements and helper 0x5d350c0): a null control
pointer skips; a count equal to the sentinel 0x100000001 or a
count of 1 destroys (virtual dispatch); any other count
decrements. The plain-vs-atomic choice (flag byte at 0x64ed290)
does not change the observable op.

Inputs are abstract: a control pointer is None or its count
(int); a string element is {"inline": bool, "capacity": int};
a buffer span is None (null begin, no free) or its byte size.
"""

SENTINEL = 0x100000001
RECORD_STRIDE = 0x300
DELETE_PLT = 0x63F0D80


def release(ctrl):
    """Release outcome for one refcounted control pointer.

    ctrl: None, or the count at control+0x08 (for helper releases,
    the count at pointer+0x08). Returns "skip", "decrement" or
    "destroy".
    """
    if ctrl is None:
        return "skip"
    if ctrl == SENTINEL or ctrl == 1:
        return "destroy"
    return "decrement"


def string_vector(elements, buffer_size):
    """Phase 3: 0x28-byte elements; short-form string rule.

    elements: [{"inline": bool, "capacity": int}]. buffer_size:
    None (null begin, no buffer free) or the span
    [record+0x2d8] - [record+0x2c8].
    """
    ops = []
    for el in elements:
        if not el["inline"]:
            ops.append(("free_string", el["capacity"] + 1))
    if buffer_size is not None:
        ops.append(("free_buffer", buffer_size))
    return ops


def shared_vector(elements, buffer_size):
    """Phase 9: 0x10-byte elements; control block at element+0x08.

    elements: control counts or None. buffer_size: None or the
    span [record+0x148] - [record+0x138].
    """
    ops = []
    for ctrl in elements:
        outcome = release(ctrl)
        if outcome != "skip":
            ops.append(("release", outcome))
    if buffer_size is not None:
        ops.append(("free_buffer", buffer_size))
    return ops


def destroy_record(rec):
    """Ordered ops for one 0x300-byte record.

    rec keys: "inlined" {field: ctrl}, "strings" (elements,
    buffer_size), "helpers" {field: ptr-or-None}, "shared"
    (elements, buffer_size), "plain" {field: size-or-None},
    "last" (ptr-or-None for +0x58). Helper fields are +0x2c0,
    +0x210, +0x1f8, +0x1d8, +0x130 in phase order; "last" is
    phase 13.
    """
    ops = []
    for field in ("0x2f8", "0x2e8"):
        outcome = release(rec["inlined"].get(field))
        if outcome != "skip":
            ops.append(("release", field, outcome))
    ops.extend(string_vector(*rec["strings"]))
    for field in ("0x2c0",):
        outcome = release(rec["helpers"].get(field))
        if outcome != "skip":
            ops.append(("release", field, outcome))
    outcome = release(rec["inlined"].get("0x298"))
    if outcome != "skip":
        ops.append(("release", "0x298", outcome))
    for field in ("0x210", "0x1f8", "0x1d8"):
        outcome = release(rec["helpers"].get(field))
        if outcome != "skip":
            ops.append(("release", field, outcome))
    ops.extend(shared_vector(*rec["shared"]))
    outcome = release(rec["helpers"].get("0x130"))
    if outcome != "skip":
        ops.append(("release", "0x130", outcome))
    for field in ("0xb0", "0x70"):
        size = rec["plain"].get(field)
        if size is not None:
            ops.append(("free_buffer", field, size))
    outcome = release(rec.get("last"))
    if outcome != "skip":
        ops.append(("release", "0x58", outcome))
    return ops


def empty_record():
    """A record whose every member is null/empty."""
    return {
        "inlined": {},
        "strings": ([], None),
        "helpers": {},
        "shared": ([], None),
        "plain": {},
        "last": None,
    }


def destroy_vector(records, outer_buffer_size):
    """Destroy every record, then free the outer buffer.

    records: list of record dicts. outer_buffer_size: None (null
    begin, plain return) or the span [holder+0x10] - [holder+0x00].
    """
    if outer_buffer_size is None:
        return []
    ops = []
    for rec in records:
        ops.extend(destroy_record(rec))
    ops.append(("free_outer_buffer", outer_buffer_size))
    return ops
