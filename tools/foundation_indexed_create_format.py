#!/usr/bin/env python3
"""RE-001: indexed create-and-format at node #94 function 0x514eb90.

The target function takes an outer object, a destination string and a
view (pointer at +0x0, length at +0x8), and returns 1 with the
destination set, or 0 with the destination unchanged:

    parsed, ok, remaining = parse_decimal(view)   # 0x54307c0
    if not ok: return 0
    if remaining != 0: return 0
    if int32(parsed) >= int32([outer + 0x778]): return 0
    status, record = get_or_create([outer + 0x788] + 0x30)  # 0x51e9220
    if status != 0: return 0          # entry already existed
    temp = format_record(record, "; ", "=")       # 0x5407f00
    dest = temp                        # move-assign 0x514b4f0
    return 1

The parser (0x54307c0) is the decimal parser already bound by the
level-ratio item: checked uint64 accumulation, failing when the
accumulated value exceeds 0x1999999999999999, or equals it with a
digit above 5; a non-digit stops the scan, and the parser succeeds
only when at least one digit was consumed, leaving the view at the
stopping character (so ``remaining`` is the unconsumed tail length).
The caller reads only the low 32 bits of the parsed value for its
index gate, comparing them as a signed 32-bit integer against the
count field at [outer + 0x778]; a parsed value whose low 32 bits are
in range passes the gate even if the full value is larger, and the
parsed index is otherwise never used by this function -- it is a
gate only, passed to neither the lookup nor the formatter.

The lookup (0x51e9220) is cited as a callee only: its internals are
not modelled here. What the caller-side code pins is its two-path
return contract, derived from the callee's own return paths together
with this function's dispatch on the status byte: on the path where
the entry already exists the callee returns a status struct whose
first byte is nonzero, and this function returns 0 without touching
the destination; on the path where the callee creates a fresh record
it returns a zero status struct together with a fresh record pointer
in the shared slot, and this function formats that record. The two
literal strings for the formatter are built with the string
constructor 0x514b6d0 from the bytes at 0x1f5e86 ("=") and 0x1efff7
("; "), and passed as the formatter's third ("; ") and fourth ("=")
arguments. The formatter's own output text is not modelled here: it
is an injected callable, so tests exercise the caller-side plumbing
(gates, dispatch, move-assign, disposal order) end to end with a stub
formatter, while the packet's verify script pins the real call sites.

Disposal order on the success path, as written in the bytes, is:
the formatter temporary first, then the "; " string, then the "="
string, then the lookup's owned pieces (the status struct's array
pointer, then the shared slot's control pointer) in the common
cleanup. On the found path the same cleanup runs with the
destination untouched and the return value cleared to 0. On the
parser/trailing/index failure paths no lookup-owned piece exists,
so the function returns 0 straight from the canary check.

Stdlib only. ``check_packet`` verifies a packet directory against a
node #94 binary; it returns a list of error strings (empty = pass).
"""

import hashlib
import os
import re
import struct

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
WINDOW_START = 0x514EB90
WINDOW_END = 0x514ED1B
PARSER_START = 0x54307C0
LOOKUP_START = 0x51E9220
FORMATTER_START = 0x5407F00
STRING_CTOR_START = 0x514B6D0
MOVE_ASSIGN_START = 0x514B4F0

OVERFLOW_THRESHOLD = 0x1999999999999999
SEPARATOR = "; "
EQUALS = "="


def to_signed32(value):
    """Interpret the low 32 bits of ``value`` as a signed int32."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def parse_decimal(view):
    """The 0x54307c0 parser: (ok, value, remaining_length).

    Returns ok=False without a usable value when no digit was
    consumed or when the checked accumulation overflows; otherwise
    ok=True, the accumulated value, and the length of the
    unconsumed tail.
    """
    view = bytes(view)
    value = 0
    i = 0
    while i < len(view) and 0x30 <= view[i] <= 0x39:
        digit = view[i] - 0x30
        if (value > OVERFLOW_THRESHOLD
                or (value == OVERFLOW_THRESHOLD and digit > 5)):
            return (False, 0, len(view) - i)
        value = value * 10 + digit
        i += 1
    if i == 0:
        return (False, 0, len(view))
    return (True, value, len(view) - i)


class Destination:
    """A mutable destination string, so failure-preservation is observable."""

    __slots__ = ("value",)

    def __init__(self, value=""):
        self.value = value


def indexed_create_format(count, container_field, dest, view, lookup,
                          formatter, trace=None):
    """The 0x514eb90 window.

    ``count`` is the int32 field at [outer + 0x778]; ``container_field``
    is the value at [[outer + 0x788] + 0x30] passed to the lookup.
    ``lookup`` is a callable ``(field) -> (status_byte, record)`` where
    status_byte is 0 for a freshly created record and nonzero when the
    entry already existed (the record is then ignored). ``formatter``
    is a callable ``(record, separator, equals) -> str``.
    Returns 1 on success (dest set) or 0 on any failure path
    (dest untouched). ``trace``, when given, records the step order.
    """
    def log(step):
        if trace is not None:
            trace.append(step)

    ok, parsed, remaining = parse_decimal(view)
    log("parse")
    if not ok:
        return 0
    if remaining != 0:
        log("trailing")
        return 0
    if to_signed32(parsed) >= to_signed32(count):
        log("index-gate")
        return 0
    status, record = lookup(container_field)
    log("lookup")
    if status != 0:
        log("found-cleanup")
        return 0
    temp = formatter(record, SEPARATOR, EQUALS)
    log("format")
    dest.value = temp
    log("move-assign")
    log("dispose-temp")
    log("dispose-separator")
    log("dispose-equals")
    log("cleanup")
    return 1
