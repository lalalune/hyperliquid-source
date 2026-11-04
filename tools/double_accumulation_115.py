"""Node #115 double-accumulation pass at 0x5f6c750 (RE-001).

Literal model of the whole pass, extracted from the digest-verified node #115
work binary (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The pass recomputes a cached total at obj+0xfc8 from the level groups at
[obj+0xa98] (24-byte records: element-pointer begin, element-pointer end,
third qword never read). Each element is a pointer to a record whose +0x10
qword is summed. The index array at [obj+0x18] holds one qword per level.

State is plain data so the model runs without the binary:

    obj = {
        "flag": 0 or 1,            # byte at obj+0xa90
        "groups": [[f10, ...], ...],  # per-group element +0x10 values
        "count": int,              # signed 32-bit at obj+0x10
        "level0": int,             # signed 32-bit at obj+0xaf0
        "index": [qword, ...],     # index array at [obj+0x18]
        "cache": int,              # qword at obj+0xfc8, read and written
    }
    arg2 = {"count70": int,        # signed 32-bit at arg2+0x70
            "threshold": int}     # qword at arg2+0xa0

run(obj, arg2) mutates obj["cache"] and returns None (the native function
returns void; its epilogue value is not part of the contract).

Rules, stated literally (see research/work-items/RE-001-double-accumulation-115/
for the evidence packet):

1. If flag is set: cache = 0, return.
2. total = wrapping sum of group 0's element fields; N = len(group 0).
   If arg2.count70 > N (signed 32-bit): if total >= threshold (unsigned)
   the pass proceeds with flag live; else flag goes dead and total = 0.
   Otherwise the pass proceeds with flag live.
3. cache = total. level starts at level0. The loop head returns when
   level > helper(obj), where helper returns 0 when flag is set, else
   count - 2 (signed 32-bit, wrapping).
4. Each iteration: acc = (previous group sum + remainder) wrapping; when
   the previous group sum is 0 the current group's sum is computed first.
   When the current level still equals level0 and the flag is live, the
   current group sum is added to the cache.
5. index = index[level] (the leaf at 0x5f6c740). If index >= acc
   (unsigned): group sum and remainder reset to 0. If index < acc
   (unsigned): remainder = acc - index, group sum resets to 0, and when
   count > level + 1 (signed) the next group's sum g is computed and,
   when g != 0, cache += unsigned_double_to_int64(
   (g / acc + 1.0) * remainder) with all three operands converted from
   unsigned 64-bit to double exactly as the binary does.
6. level increments by one (signed 32-bit wrapping) per iteration.

The SIMD pair loop in the binary is an implementation detail: addition
modulo 2**64 commutes, so the plain wrapping sum equals it.
"""

import math

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
TWO63 = 1 << 63


def _u64(x):
    return x & MASK64


def _s32(x):
    x &= MASK32
    return x - (1 << 32) if x >= (1 << 31) else x


def _group_sum(values):
    total = 0
    for v in values:
        total = _u64(total + v)
    return total


def _require(obj, key):
    if key not in obj:
        raise ValueError("missing field: %s" % key)
    return obj[key]


def helper(obj):
    """The 0x5f6b720 helper: 0 when flag is set, else count - 2."""
    flag = _require(obj, "flag")
    count = _s32(_require(obj, "count"))
    if flag:
        return 0
    return _s32(count - 2)


def index_leaf(obj, level):
    """The 0x5f6c740 leaf: index[level] with level sign-extended."""
    index = _require(obj, "index")
    level = _s32(level)
    if level < 0 or level >= len(index):
        raise ValueError("index out of range: level %d" % level)
    return _u64(index[level])


def group_sum(obj, level):
    """Wrapping sum of one group's element +0x10 fields."""
    groups = _require(obj, "groups")
    level = _s32(level)
    if level < 0 or level >= len(groups):
        raise ValueError("group out of range: level %d" % level)
    return _group_sum(groups[level])


def unsigned_to_double(x):
    """Correctly rounded unsigned-64 to double conversion (cvtsi2sd path)."""
    return float(_u64(x))


def double_to_unsigned_bits(x):
    """The binary's double-to-int64 conversion with the 2**63 bias trick.

    comisd against 2**63: when x >= 2**63 the code subtracts 2**63,
    converts with cvttsd2si (truncate toward zero, indefinite value
    0x8000000000000000 on invalid input) and xors the sign bit.
    Otherwise it converts directly. Returns the 64-bit pattern.
    """
    if math.isnan(x):
        return TWO63  # cvttsd2si indefinite value
    if x >= float(TWO63):
        y = x - float(TWO63)
        if not math.isfinite(y):
            t = TWO63  # cvttsd2si indefinite, xored -> 0
            return _u64(t ^ TWO63)
        t = int(y)  # truncate toward zero
        if t > TWO63 - 1 or t < -TWO63:
            return 0  # indefinite xored
        return _u64(t ^ TWO63)
    if not math.isfinite(x):
        return TWO63  # only -inf could reach here; not produced by the pass
    t = int(x)
    if t > TWO63 - 1 or t < -TWO63:
        return TWO63
    return _u64(t)


def _ieee_div_mul(g, acc, rem):
    """(g / acc + 1.0) * rem in IEEE doubles, as the binary computes it."""
    gd = unsigned_to_double(g)
    ad = unsigned_to_double(acc)
    rd = unsigned_to_double(rem)
    if ad == 0.0:
        q = math.inf  # g > 0 on this path, so g / 0 is +inf
    else:
        q = gd / ad
    q = q + 1.0
    return q * rd  # inf * 0.0 -> nan, as in hardware


def run(obj, arg2):
    """Run the 0x5f6c750 pass, mutating obj['cache']. Returns None."""
    flag = _require(obj, "flag")
    groups = _require(obj, "groups")
    count = _s32(_require(obj, "count"))
    level0 = _s32(_require(obj, "level0"))
    _require(obj, "cache")
    count70 = _s32(_require(arg2, "count70"))
    threshold = _u64(_require(arg2, "threshold"))

    if flag:
        obj["cache"] = 0
        return None

    # Step 2: group 0 baseline and the arg2 gate.
    if groups:
        total = _group_sum(groups[0])
        n = len(groups[0])
    else:
        total = 0
        n = 0
    flag_live = True
    if count70 > _s32(n):
        if total >= threshold:
            pass
        else:
            flag_live = False
            total = 0

    obj["cache"] = total
    level = level0
    group_sum_prev = 0
    rem = total
    while True:
        if _s32(level) > helper(obj):
            return None
        acc = _u64(group_sum_prev + rem)
        if group_sum_prev == 0:
            group_sum_prev = group_sum(obj, level)
            acc = _u64(rem + group_sum_prev)
        if _s32(level) == _s32(_require(obj, "level0")) and flag_live:
            obj["cache"] = _u64(obj["cache"] + group_sum_prev)
        old_level = level
        level = _s32(level + 1)
        idx = index_leaf(obj, old_level)
        if idx < acc:
            rem = _u64(acc - idx)
            group_sum_prev = 0
            if count > _s32(level):
                g = group_sum(obj, level)
                group_sum_prev = g
                if g != 0:
                    add = double_to_unsigned_bits(_ieee_div_mul(g, acc, rem))
                    obj["cache"] = _u64(obj["cache"] + add)
        else:
            group_sum_prev = 0
            rem = 0
