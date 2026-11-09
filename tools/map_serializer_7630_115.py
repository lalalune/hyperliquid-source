"""Model of node #115's options-map serializer 0x6097630 (RE-001).

Pins the dispatch table, the emission format, the Status propagation
and the empty-range outcome of the S0 writer behind the delimiter
pre-step 0x6098510, as read from work/hl-node-115.bin
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).
"""

TYPE_21 = 21
TYPE_22 = 22
FLAGS_SKIP_BIT = 0x2000

# Outcome tags returned by dispatch().
SKIP = "skip"
BLOCK_A = "block_a"
BLOCK_B = "block_b"
BLOCK_C = "block_c"

OK = 0


def dispatch_full(verification, flags, type_, opts_plus04, opts_plus28,
                  rec_d9_bit0, rec_d9_bit7):
    """Full dispatch including the record+0xd9 bit tests."""
    if verification in (4, 5):
        return SKIP, "verification in {4, 5}"
    if flags & FLAGS_SKIP_BIT:
        return SKIP, "flags & 0x2000"
    if opts_plus04 == 0:
        return BLOCK_A, "ConfigOptions+0x04 == 0"
    if rec_d9_bit0:
        return BLOCK_B, "record+0xd9 bit 0 set (ConfigOptions copy)"
    if type_ in (TYPE_21, TYPE_22):
        if opts_plus28 == 2 or not rec_d9_bit7:
            return BLOCK_C, "type in {21, 22}"
        return SKIP, "type in {21, 22} but +0x28 != 2 and +0xd9 bit 7 set"
    return SKIP, "type not in {21, 22}"


def emit_entry(prefix, name, value, delimiter):
    """The emission for one entry: prefix + name + '=' + value + delimiter.

    Returns '' when the serialized value is empty: such an entry emits
    nothing into S0.
    """
    if value == "":
        return ""
    return prefix + name + "=" + value + delimiter


def serialize_map(entries, prefix="", delimiter="; ",
                  opts_plus04=0, opts_plus28=0):
    """Simulate 0x6097630 over a list of entries.

    Each entry is a dict with keys: verification, flags, type,
    name, value (the serializer's value string, '' when empty),
    serialize_error (Status code the per-entry serializer returns,
    0 for kOk), rec_d9_bit0, rec_d9_bit7.
    Returns (status_code, out_text). On a serializer error the Status
    propagates and iteration stops immediately; an empty entry list
    yields (0, '').
    """
    out = ""
    for entry in entries:
        outcome, _reason = dispatch_full(
            entry["verification"], entry["flags"], entry["type"],
            opts_plus04, opts_plus28,
            entry.get("rec_d9_bit0", False),
            entry.get("rec_d9_bit7", False))
        if outcome == SKIP:
            continue
        if entry.get("serialize_error", 0) != 0:
            return entry["serialize_error"], out
        out += emit_entry(prefix, entry["name"], entry["value"], delimiter)
    return OK, out
