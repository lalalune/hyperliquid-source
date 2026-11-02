# Stable-memory sum and safe-slice relation

This proof concerns the exact node94 SHA-256 in `static.json`, the complete
77-byte FDE `[0x52cfe00,0x52cfe4d)` and all 22 retained instruction boundaries.
Fresh GNU and Apple LLVM disassemblies agree without byte normalization. The
8-byte alignment NOP is inside the body; three preceding and one following INT3
bytes are outside it. The next FDE starts at `0x52cfe4e`. There is no leaf call,
write, external constant table or LSDA. The complete caller FDEs and CIE records
are retained separately; caller exception behavior is not reconstructed.

## Inputs and stability premise

The entry RDI addresses an object whose base-pointer qword at offset 0x60 and
count-field dword at offset 0x68 are readable. MOV ESI,ESI at `0x52cfe04` discards
incoming RSI bits 32..63, so let `j` be that zero-extended u32 index. Multiplying
j by eight cannot overflow u64: its maximum is `8*(2^32-1)`.

The original body reloads the base pointer at `0x52cfe20` and the count field at
`0x52cfe3e` on **every iteration**, with the latter read after the element load
and sum. The fixed-input relation below requires both fields and all relevant
table values to remain stable ordinary memory throughout the execution. This
premise is not inferred from callers or from the lack of writes in this leaf.
Concurrent mutation, volatile/device memory and faults fall outside the claim.

Let B be the stable base, f the stable u32 field, and `n=2^(f mod64)`. The CL
shift masks to six bits for a 64-bit operand, so n is in `{2^k | 0<=k<=63}` and
never zero. Let `T[k]` denote the little-endian qword at B+8*k. For the safe
projection, all words in a contiguous span through the last selected element
must be valid initialized memory, with no address wrap and ordinary code/return
stack behavior. Original executions with sparse mapped words or wrapping
addresses may lie outside this slice domain even if individual loads succeed.
The slice is a decoded value view, not a recreation of the original object ABI.

## Original loop invariant and termination

At the first loop head `0x52cfe20`, RDX=0, R8=0, R9=0. After i completed
iterations and before the next head, on the stable admitted domain:

```text
RDX = i
R8 = i * 0xce40                  (modulo 2^64 outside the admitted domain)
R9 = sum(T[j + 6600*r], r=0..i-1) modulo 2^64
```

The body loads B, increments RDX, adds the old R8 to B, advances R8 by
0xce40=52,800 bytes, adds 8*j, loads a qword and adds it to R9. Since
52,800/8=6,600, that qword is exactly `T[j+6600*i]`. Reloading f then forms n.
Intel `cmp rdx,rax` (AT&T `cmp %rax,%rdx`) followed by JB returns to the head
exactly when the incremented counter is unsigned-less-than n. Thus iteration i
returns when i+1=n, and otherwise establishes the invariant for i+1.

The counter cannot overflow: n<=2^63<2^64, and comparison stops at n. There is
no zero-iteration path. For every stable count whose required memory belongs to
the admitted domain, there are exactly n loads, so termination follows even
when n is impractically large. RAX receives R9 and RET returns its raw u64 value.
The returned sum is modulo 2^64; zero is a valid sum and no error is indicated.

## Exact safe span, with no arbitrary count cap

Define the unbounded mathematical number of required words

```text
W = j + (n-1)*6600 + 1.
```

All selected positions are monotone and nonnegative; the last is W-1. For a
Rust slice on the compiled platform, require `8*W <= isize::MAX`. The immutable
slice must have at least W elements. This includes intervening unselected words;
the target only loads the selected words, while Rust requires a valid entire
slice. It also makes the decoded span nonwrapping on the relevant platform.
The actual base address and original object fields remain premises, not API
parameters checked by the value implementation.

`required_words` performs usize conversions, `(n-1)*6600`, the two additions,
byte multiplication and the isize limit check before returning Some(W). Every
term is nonnegative. If the final mathematical bound holds, all intermediate
values fit usize (and n<=W), so no checked operation can falsely reject it. If an
intermediate operation overflows or a conversion fails, the mathematical span
cannot fit this platform's valid slice bound. Consequently the preflight is
exact for that bound, not a hand-picked exponent limit. On the qualified 64-bit
host, exponent 47 can still have a representable span, while exponent 48 cannot;
the code derives this from checked arithmetic rather than encoding a cap.

`strided_sum` first checks this result and `table.len() >= W`, returning None on
failure before loading any table element. These refusals are newly chosen safe
API outcomes; they are not results of a normally returning original function.
A representable but physically absent huge span is likewise refused. A table
with extra trailing words is admitted and those extra words are not summed.

The Rust loop starts at j with remaining=n. Every load uses
`position=j+6600*i <= W-1 < table.len()`. It decrements the positive remaining
counter and advances position only if another iteration is needed. Every
advanced position is at most W-1, so usize addition cannot overflow. The counter
reaches zero after exactly n iterations without underflow. Wrapping u64 addition
preserves the original sum for arbitrary table values; no arithmetic panic or
out-of-range indexing is possible after the preflight. No unsafe code is used.

## Caller evidence and runtime-data closure

All three direct E8 candidates are aligned instructions in complete independently
decoded FDEs. `static.json` retains their full bytes, hashes, FDE/CIE/LSDA fields
and immediate argument setup:

| Caller FDE | Site | Observed immediate setup |
|---|---|---|
| `[0x52cfe60,0x52cfea2)` | `0x52cfe7e` | ESI=EBP; RDI=RBX. |
| `[0x52d01e0,0x52d0485)` | `0x52d0265` | ESI=dword[RBX]; RDI=R13. |
| `[0x52d5a00,0x52d5fe5)` | `0x52d5b03` | RBX=qword[RSP]; RDI=qword[RSP+0x28]; ESI=dword[RBX]. |

The first caller saves its entry object/index before an intervening external
call and later passes the saved registers. Those external helpers, caller
purposes and synchronization guarantees remain outside this reconstruction.
No caller is used to assume stable fields or to narrow the raw index/count
values. The direct-call scan is not a complete indirect-reference census.

The only runtime leaf data reads are the two object fields, selected qwords and
ordinary RET stack read. No data is written. All 80,300 ELF RELA records are
checked: observed types 1,6,7,8,18 are eight-byte relocations, and none overlap
protected leaf/padding/caller bytes or name the leaf entry as addend. The exact
stride-add byte pattern has one `.text` occurrence, at `0x52cfe2b`; that fact is
not a census of other possible stride idioms. Original symbols/types, table
contents and library identity remain unknown.

## Independent compact native expectations

Each input descriptor specifies j, f, actual slice length, seed and step. The
host client materializes every word of a real Vec using
`T[k]=(seed+step*k) mod2^64`, then calls the slice API. It receives no expected
result, expected span or fixture path. It does not substitute a sparse callback
or simulate target instructions. Its 500,000-word allocation guard bounds the
harness alone; it does not restrict the library's count domain.

The independently frozen oracle uses unbounded integer arithmetic and the
closed-form progression sum

```text
(n*seed + step*(n*j + 6600*n*(n-1)/2)) mod 2^64.
```

Distributing the final modulus over the individual affine words proves this
formula. It contains no indexed table-read loop or Rust checked arithmetic.
Separate mathematical inequalities determine new API refusals and expected W.
All 64 count residues, high index/field bits, exact/short/long slices and sum
wraps are covered. Large spans are checked with empty physical tables, not GiB
allocations. The largest actual table is 422,402 words (3,379,216 bytes).

Finite tests cover affine tables with admitted counts 1..64, not all tables or
all physically admissible counts. The invariant and bounds supply the general
proof. Newly authored native execution cannot establish original compiler,
Linux x86-64 ABI or rebuilt-byte identity; those remain unmeasured.
