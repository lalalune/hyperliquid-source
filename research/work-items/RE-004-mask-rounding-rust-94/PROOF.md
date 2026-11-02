# Complete raw-u64 return contract

This proof applies to the 75 bytes and decoded FDE in `static.json`, under
normal return with intact code and a valid return stack. Let `n` be raw RDI,
`C = 0xff00ff00ff00feff`, `S = 2^64-72`, and `B = 131072`.
RAX is interpreted as an unsigned word; signed source types are unknown.

The initial `cmp %rdi,%rdx` compares `C` with `n`; its unsigned `jb` reaches
the final `ret` exactly when `n > C`. RAX already contains sign-extended
immediate -72, so every rejected input returns S. This is an inclusive cutoff,
not a bitwise mask applied to the input and not a signed comparison.

For admitted inputs, the full-width `shr 8` and `add` compute
`n + floor(n/256)` modulo `2^64`. The unsigned comparison against `0x1ffff`
adds `floor((B-n)/2048)` exactly for `n < B`. The zero test is on the complete
RAX word. Loading the second sentinel into RDX does not change its flags;
the following `cmove` would select S exactly when that sum were zero.

## Small input domain

For `0 <= n < B`, write `n = 2048*q + r`, with `0 <= q <= 63` and
`0 <= r <= 2047`. Then:

```text
floor(n/256) = 8*q + floor(r/256)
floor((B-n)/2048) = 64-q-[r != 0]
V(n) = 2055*q + 64 + r + floor(r/256) - [r != 0]
```

Here `[r != 0]` is 0 or 1. The residue term has minimum 0, achieved at r=0
and r=1, and maximum 2053, achieved at r=2047. For positive r it is
`r-1+floor(r/256)`, which is nonnegative and monotone. Therefore
`64 <= V(n) <= 2055*63 + 64 + 2053 = 131582`.

The subtraction `B-n` is between 1 and 131072. Neither that subtraction nor
either addition can wrap in this domain, and the internal zero test is false.
The grouped expression is the independent small-domain oracle; it does not
copy the Rust sequence of shifts and additions. Native checks enumerate all
131,072 small inputs, separately from the symbolic proof.

## Large admitted domain and modulo arithmetic

For `B <= n <= C`, the correction is absent. The exact integer sum is
`F(n) = floor(257*n/256)`. It is strictly increasing, since increasing n by
one increases n itself and cannot decrease `floor(n/256)`. Its extrema are:

```text
F(B) = 131584
F(C) = 0xfffffffffffffffd = 2^64-3
```

Thus the maximum admitted sum fits in u64; every admitted large result is
positive. There is no modular wrap that could invalidate the zero-branch
argument. Together with the small-domain bound, this proves the conditional
move is unreachable for every input that reaches it. It is safe to omit that
conditional in the independently authored Rust value API.

The upper bound matters: merely showing that n and its shift are positive
would not rule out a modulo-`2^64` zero. Without the cutoff, the first wrap
would occur at `C+2 = 0xff00ff00ff00ff01`, because `F(C+1) = 2^64-1` and
`F(C+2) = 2^64`. Both inputs are rejected before any arithmetic in the capture.

## The sentinel is also an admitted result

Writing a large input as `n = 256*q + r`, `0 <= r <= 255`, gives
`F(n) = 257*q + r`. Divide S by 257: its remainder is 186, inside that residue
range. The unique admitted preimage is:

```text
n = 0xff00ff00ff00feba = C-69
F(n) = 0xffffffffffffffb8 = S
```

Strict monotonicity makes it the only large admitted preimage; the small
output bound excludes a small one. The zero fallback does not run for this
input. Consequently a return value equal to S does not by itself identify
whether the entry cutoff rejected the input. The implementation returns raw
bits and makes no claim that -72 means a particular error.

## Complete partition and implementation

The three domains `n > C`, `0 <= n < B`, and `B <= n <= C` partition all
`2^64` inputs. The Rust guard selects S for the first, and the two remaining
domains match their formulas exactly. Its `wrapping_add` expresses the
captured word arithmetic; the bounds above establish that wrapping is inactive
on admitted inputs. Its only subtraction is guarded by `n < B`, and its two
shift counts are constant 8 and 11. There are no panics or undefined shifts.

This is a proof of the target's returned-word relation and the Rust expression
under Rust integer semantics, not a proof of compiler correctness or original
ABI/exception/whole-program behavior. The native sample checks the new compiler
output against the separately frozen oracle; it does not execute the capture
or an instruction emulator.
