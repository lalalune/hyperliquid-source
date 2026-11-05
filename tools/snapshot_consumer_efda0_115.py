#!/usr/bin/env python3
"""RE-001: node #115 stats-snapshot consumer 0x5eefda0.

Maps the Block-cache dump routine that formats a published stats snapshot
into a human-readable string: header line (name, capacity, usage, table
size, occupancy, collections, last copies, last seconds, seconds since),
the entry-stats header, one line per non-empty entry slot, and a trailing
newline.

Bound to artifact artifacts/node/115/hl-node, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
(provenance/artifacts.json).  All semantics below are read off the raw
disassembly excerpts in research/work-items/RE-001-snapshot-consumer-efda0-115/
(main.txt, fmt.txt, elapsed.txt, walker.txt, initializer.txt); nothing is
inferred from the names of the literals alone.

Snapshot layout (312 bytes, published copy; see the work-item README):
  +0x00 capacity      u64, slot +0x70 chain result, human-size formatted
  +0x08 usage         u64, slot +0x78 chain result, human-size formatted
  +0x10 table_size    u64, slot +0x88 result (0 when the slot is the identity)
  +0x18 occupancy     u64, slot +0x80 result (-1 when the slot is the identity)
  +0x20 name          std::string "name@0x<ptr>#<pid>"
  +0x40..+0xb0 values 14 x u64, one per entry slot
  +0xb0..+0x120 counts 14 x u64, one per entry slot (zero skips the line)
  +0x120 sequence     u32, incremented on every fill ("collections")
  +0x124 no_progress  u32, bumped when the progress check fails ("last_copies")
  +0x128 prev_value   u64, first slot +0x98 return at fill time
  +0x130 last_value   u64, second slot +0x98 return ("last produced value")

The +0x128 reading corrects open PR #3049's records.json, which called it
the chain-head value: the filler stores its FOURTH argument (rcx, the first
slot return) at +0x128, not its third argument (rdx, the chain head).
"""

import math
import struct

ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CONSUMER = 0x5EEFDA0
WALKER = 0x5D4D490
WALKER_GLOBAL = 0x64ECF80
NAME_TABLE = 0x6503DC0

# Entry-slot names, in slot order, as installed by the static initializer
# 0x5f007f0 (initializer.txt): std::string objects built from the literals
# at the addresses below.  Slot i reads table[i] as {data, length}.
NAMES = [
    "DataBlock", "FilterBlock", "FilterMetaBlock", "DeprecatedFilterBlock",
    "IndexBlock", "OtherBlock", "WriteBuffer",
    "CompressionDictionaryBuildingBuffer", "FilterConstruction",
    "BlockBasedTableReader", "FileMetadata", "BlobValue", "BlobCache",
    "Misc",
]
NAME_LITERALS = [
    0x443813, 0x444690, 0x44D04B, 0x44DEDE, 0x441A5A, 0x430F60, 0x44532E,
    0x95B240, 0x43A503, 0x433FE7, 0x4393E5, 0x44A2C1, 0x43A516, 0x433FFD,
]
# Sibling table at 0x6503C00, initialized by the same function, same roles
# in lowercase-hyphen form.  Its consumer is NOT pinned here (open lead:
# the sibling consumer 0x5ef8360 is the unexamined candidate).
SIBLING_NAMES = [
    "data-block", "filter-block", "filter-meta-block",
    "deprecated-filter-block", "index-block", "other-block",
    "write-buffer", "compression-dictionary-building-buffer",
    "filter-construction", "block-based-table-reader", "file-metadata",
    "blob-value", "blob-cache", "misc",
]

MASK64 = (1 << 64) - 1
_DIV_MAGIC = 0x431BDE82D7B634DB  # (x * magic >> 64) >> 18 == x // 1_000_000
_NEG_QNAN = struct.unpack("<d", struct.pack("<Q", 0xFFF8000000000000))[0]


def u64_to_f64(value):
    """Unsigned 64-bit to double, exactly as the binary's fixup does it.

    cvtsi2sd converts signed, so for a value with the sign bit set the
    code takes the fixup path: t = (v >> 1) | (v & 1), convert t, double
    it.  The fixup is the standard correctly-rounded unsigned conversion:
    spot-checked against float(v) on 200,000 random 64-bit values with no
    difference, so the branch is reproduced literally rather than
    short-circuited to float(v).
    """
    value &= MASK64
    if value < (1 << 63):
        return float(value)
    t = (value >> 1) | (value & 1)
    d = float(t)
    return d + d


def format_human_size(value):
    """The 0x61d0ba0 formatter: "%.2f KB|MB|GB|TB" (fmt.txt).

    x starts at the value as a double, is scaled by 1/1024 until it is
    below 1024.0 or the TB suffix is reached, then snprintf "%.2f %s".
    """
    x = u64_to_f64(value)
    for suffix in ("KB", "MB", "GB"):
        x *= 1.0 / 1024.0
        if x < 1024.0:
            return "%.2f %s" % (x, suffix)
    x *= 1.0 / 1024.0
    return "%.2f TB" % x


def elapsed_ns(last_value, prev_value):
    """The 0x5eee580 helper (elapsed.txt): last - prev when prev < last,
    else last.  Unsigned 64-bit arithmetic."""
    last_value &= MASK64
    prev_value &= MASK64
    if prev_value < last_value:
        return (last_value - prev_value) & MASK64
    return last_value


def divide_by_1e6(value):
    """The magic multiply at 0x5eeffab: (x * 0x431bde82d7b634db >> 64) >> 18.

    Verified against x // 1_000_000 on 200,010 values (0, 1, 10**6 - 1,
    10**6, 2**63, 2**64 - 1 and 200,000 random 64-bit values): no mismatch.
    """
    value &= MASK64
    return (((value * _DIV_MAGIC) >> 64) & MASK64) >> 18


def format_g6(value):
    """iostream default double formatting: %g with precision 6.

    Python's %.6g drops the sign of a NaN; the binary's stream prints
    "-nan" for a negative NaN (the x86 DIVSD 0.0/0.0 indefinite QNaN),
    so the sign is restored explicitly.
    """
    if math.isnan(value):
        return "-nan" if math.copysign(1.0, value) < 0 else "nan"
    return "%.6g" % value


def fdiv(a, b):
    """IEEE divsd: Python float division, except a zero divisor yields
    the x86 result instead of raising: +inf / -inf, or the indefinite
    QNaN (which the stream prints as "-nan") for 0.0 / 0.0."""
    if b == 0.0:
        if a == 0.0:
            return _NEG_QNAN
        return math.inf if a > 0 else -math.inf
    return a / b


def walk_chain(links):
    """The 3-link handler walk at 0x5eeff66 (main.txt).

    links is a list of {"slot": int, "value": int} in chain order.  The
    first link whose vtable slot +0x98 differs from the walker 0x5d4d490
    has its slot called with the link and its return is the result; when
    the first two links both carry the walker, the third link's slot is
    called unconditionally.  A chain shorter than the walk needs raises.
    """
    if not links:
        raise ValueError("walk_chain needs at least one link")
    if links[0]["slot"] != WALKER:
        return links[0]["value"]
    if len(links) < 2:
        raise ValueError("walk ran past the end of the chain at link 2")
    if links[1]["slot"] != WALKER:
        return links[1]["value"]
    if len(links) < 3:
        raise ValueError("walk ran past the end of the chain at link 3")
    return links[2]["value"]


def render_snapshot(snapshot, chain):
    """Format one published snapshot exactly as 0x5eefda0 does.

    snapshot fields: name (str), capacity, usage, table_size, occupancy,
    sequence, no_progress, prev_value, last_value (ints), counts and
    values (lists of 14 ints each).  chain is the walk input for
    walk_chain.  Returns the full text, including the trailing newline.
    """
    counts = snapshot["counts"]
    values = snapshot["values"]
    if len(counts) != 14 or len(values) != 14:
        raise ValueError("counts and values must each hold 14 slots")
    out = []
    out.append("Block cache ")
    out.append(snapshot["name"])
    out.append(" capacity: " + format_human_size(snapshot["capacity"]))
    out.append(" usage: " + format_human_size(snapshot["usage"]))
    out.append(" table_size: " + str(snapshot["table_size"] & MASK64))
    out.append(" occupancy: " + str(snapshot["occupancy"] & MASK64))
    out.append(" collections: " + str(snapshot["sequence"] & 0xFFFFFFFF))
    out.append(" last_copies: " + str(snapshot["no_progress"] & 0xFFFFFFFF))
    last_secs = fdiv(
        u64_to_f64(elapsed_ns(snapshot["last_value"], snapshot["prev_value"])),
        1000000.0,
    )
    out.append(" last_secs: " + format_g6(last_secs))
    slot_now = walk_chain(chain)
    secs_since = divide_by_1e6((slot_now - snapshot["last_value"]) & MASK64)
    out.append(" secs_since: " + str(secs_since))
    out.append("\n")
    out.append("Block cache entry stats(count,size,portion):")
    capacity = u64_to_f64(snapshot["capacity"])
    for i in range(14):
        if counts[i] == 0:
            continue
        portion = fdiv(u64_to_f64(values[i]) * 100.0, capacity)
        out.append(
            " " + NAMES[i]
            + "(" + str(counts[i] & MASK64)
            + "," + format_human_size(values[i])
            + "," + format_g6(portion) + "%)"
        )
    out.append("\n")
    return "".join(out)
