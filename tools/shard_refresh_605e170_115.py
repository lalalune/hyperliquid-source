"""Model of node #115 shard refresh routine 0x605e170 (RE-001).

The routine is the shard re-selection helper of the node's
arena-style allocator: when an allocation window (the outer
Allocate 0x5f11c40 or the shard AllocateAligned 0x5f117a0, both
mapped by earlier packets) finds its selected shard locked, it
calls this routine with the allocator object and takes the
returned 64-byte shard entry as its new selection. The routine's
own FDE is 0x605e170..0x605e20d (157 bytes); it is reached by
exactly two direct calls, one in each allocation window, and by
nothing else (no tail jumps, no stored pointers, no relocations
naming it).

Pinned layout and contract (see
research/work-items/RE-001-shard-refresh-605e170-115/):

- rdi points at the allocator object. The routine reads only
  two fields: the shard array pointer at +0x48 and the shift
  dword at +0x50. It writes neither field; its only writes are
  the caller-thread's selector slot in TLS (fs:0 - 0x408, the
  same slot the allocation windows document as their cpuid
  slot) and, on the fallback path only, the per-thread seed
  word owned by the seed callee.

Pinned behavior, reproduced exactly:

- The selector comes first from the CPUID callee 0x60d5cd0
  (FDE 0x60d5cd0..0x60d5cf0, cited by contract): it returns the
  CPUID leaf-1 initial APIC id (EBX bits 31:24) as a
  non-negative int, or -1 when CPUID leaf 0 reports a maximum
  leaf of 0. A non-negative result is the selector verbatim.
- A negative result takes the fallback: the seed callee
  0x61c4080 (FDE 0x61c4080..0x61c4117, cited by contract)
  returns a pointer to a per-thread 32-bit seed word; the
  routine advances that word by one Park-Miller step (see
  park_miller_step) and uses the NEW word as the selector.
- The shard index is selector & mask, where the mask is
  (1 << (shift & 31)) - 1 computed by a 32-bit shift: the
  shift count is the field's low 5 bits, so a shift field of
  32 or more wraps the count (shift 32 gives mask 0, shift 33
  gives mask 1).
- The TLS selector slot receives index | (1 << (shift & 63)):
  the bit index uses the field's low 6 bits, twice the width
  the mask count uses, and the bit is never inside the index
  (the mask leaves it clear), so the stored value is
  index + 2**(shift & 63).
- The return value is array + index * 64, the address of the
  selected 64-byte shard entry. The routine does not inspect
  the entry (in particular it does not look at the entry's
  lock byte); locking stays with the caller.
"""

M31 = 0x7FFFFFFF
U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF


def park_miller_step(seed):
    """One step of the fallback generator, exactly as coded.

    t = seed * 16807 is formed in 64 bits from the zero-extended
    32-bit seed word; the result is (t & 2**31-1) + (t >> 31),
    with 2**31-1 subtracted once when the 32-bit sum has its
    sign bit set. This is the Park-Miller minimal-standard step
    modulo 2**31-1 for every seed the fold reaches, with one
    coded exception: a sum of exactly 2**31-1 has no sign bit,
    so seed 2**31-1 maps to 2**31-1 (a fixed point), not to 0
    as exact modular arithmetic would give. Seed 0 is also a
    fixed point.
    """
    t = (seed & U32) * 0x41A7
    s = ((t & M31) + (t >> 31)) & U32
    if s & 0x80000000:
        s = (s - M31) & U32
    return s


def index_mask(shift_dword):
    """(1 << (shift & 31)) - 1, the 32-bit shl/sub pair."""
    return ((1 << (shift_dword & 31)) - 1) & U32


def refresh(array_base, shift_dword, selector, seed):
    """Run the routine once.

    array_base: the +0x48 field (shard array pointer).
    shift_dword: the +0x50 field, read as a dword.
    selector: the CPUID callee's signed 32-bit result; a
        negative value selects the fallback path.
    seed: the current per-thread seed word (consulted and
        advanced only on the fallback path).

    Returns (entry, tls_value, seed_after): the returned shard
    entry address, the value stored into the TLS selector slot,
    and the seed word after the call (unchanged off the
    fallback path).
    """
    seed_after = seed & U32
    if selector >= 0:
        value = selector & U32
    else:
        seed_after = park_miller_step(seed_after)
        value = seed_after
    index = value & index_mask(shift_dword)
    tls_value = index | (1 << (shift_dword & 63))
    entry = (array_base + index * 64) & U64
    return entry, tls_value, seed_after
