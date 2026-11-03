"""Node #115 need-score predicate at 0x5dbd6d0 (RE-001).

Literal model of the whole predicate, extracted from the digest-verified
node #115 work binary (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The predicate takes one object (rsi; rdi is never read) and returns 1 or 0.
It first checks five "need" sums, each of the shape
((end - begin) >> 4 arithmetic on the wrapped 64-bit difference) + base,
and returns 1 as soon as any sum is nonzero. When all five sums are zero
it scans the double array at [obj+0xf38] under a bound recomputed on
every iteration by the level gate at 0x5f6b720 (already pinned by #2330):
the gate returns 0 when the flag byte at obj+0xa90 is set, else
signed32(obj+0x10) - 2 (wrapping 32-bit). The scan reads scores[i] for
i = 0, 1, ... while the bound is >= i (signed 32-bit compare) and
returns 1 as soon as a score is >= 1.0 (rodata double at 0x4592b0);
a NaN score does not satisfy the compare and the scan continues.
Otherwise it returns 0.

State is plain data so the model runs without the binary:

    obj = {
        "needs": [(begin, end, base), ...],  # exactly five ranges, in
            # native order: (0xc78, 0xc70, 0xbe0), (0xd20, 0xd18, 0xc88),
            # (0xe70, 0xe68, 0xdd8), (0xbd0, 0xbc8, 0xb38),
            # (0xf18, 0xf10, 0xe80) -- begin/end/base are raw qwords
        "flag": 0 or 1,        # byte at obj+0xa90
        "count": int,          # signed 32-bit at obj+0x10
        "scores": [float, ...] # doubles at [obj+0xf38]
    }

need_sum() and level_gate() are the two pinned pieces; predicate(obj)
returns 1 or 0 and reads nothing else.

Assumptions, stated explicitly (see the work-item README):
- The caller guarantees scores has an entry for every index the scan
  reaches; the native code reads scores[i] without a length check, so
  running past the end of the list is a model guard error, not a
  native behavior.
- The bound is recomputed from the same object fields on every
  iteration; nothing in this function mutates the object, so the bound
  is constant across iterations for a fixed object.
"""

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

NEED_OFFSETS = (
    (0xC78, 0xC70, 0xBE0),
    (0xD20, 0xD18, 0xC88),
    (0xE70, 0xE68, 0xDD8),
    (0xBD0, 0xBC8, 0xB38),
    (0xF18, 0xF10, 0xE80),
)
SCORE_THRESHOLD = 1.0


def _s64(value):
    value &= MASK64
    return value - (1 << 64) if value >= (1 << 63) else value


def _s32(value):
    value &= MASK32
    return value - (1 << 32) if value >= (1 << 31) else value


def need_sum(begin, end, base):
    """One need sum: ((end - begin) >> 4 arithmetic) + base, wrapping."""
    diff = _s64(end - begin)
    return ((diff >> 4) + base) & MASK64


def level_gate(obj):
    """The 0x5f6b720 gate: 0 when flag set, else count - 2 (s32 wrap)."""
    if obj["flag"] != 0:
        return 0
    return _s32(obj["count"] - 2)


def predicate(obj):
    """The whole 0x5dbd6d0 predicate; returns 1 or 0."""
    try:
        needs = obj["needs"]
        scores = obj["scores"]
    except KeyError as exc:
        raise ValueError("missing object field: %s" % exc.args[0])
    if len(needs) != 5:
        raise ValueError("needs must hold exactly five ranges")
    for begin, end, base in needs:
        if need_sum(begin, end, base) != 0:
            return 1
    index = 0
    while True:
        bound = level_gate(obj)
        if bound < _s32(index & MASK32):
            return 0
        if index >= len(scores):
            raise ValueError("score scan ran past the scores list")
        score = scores[index]
        index += 1
        if score >= SCORE_THRESHOLD:
            return 1
