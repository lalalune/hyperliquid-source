# Complete mask, register and global-store relation

This proof concerns only node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
complete function `[0x5521d10,0x5521d37)`. The 39-byte body has ten
instructions. Its nine trailing INT3 bytes are separate alignment padding.
The incoming instruction at `0x54b9c3f` is a direct call in the complete
957-byte caller `[0x54b9b60,0x54b9f1d)`. The caller is retained only to
qualify this edge and its argument setup; its other effects and callees
are outside the reconstruction.

## Full value and store relation

Let `x` be incoming RDI, `c` incoming RCX, `b` the common load-bias bits,
`W = 2^64`, and `S = 0x5788110`. All three inputs are unsigned 64-bit
bit patterns. Define:

```
n = x mod 64
m = W-1                    if x = W-1
    sum(2^j, 0 <= j < n)    otherwise
C = c                      if x = W-1
    x mod 2^32             otherwise
A = (b + S) mod W
```

At return, RAX equals `m` and RCX equals `C`. The single store replaces
the eight bytes at `A` with little-endian `m`. RDI is unchanged; no other
general-purpose register is written by the body. RET's stack/control
transition and the condition flags are outside the value API.

The first MOV installs all ones in full RAX. The CMP is a **64-bit**
comparison with sign-extended immediate -1. JE skips directly to the
store only for `x=W-1`; this path never executes the MOV to ECX, so RCX
retains all 64 incoming bits. In particular, inputs 255, `0xffffffff`
and `0x1ffffffff` do not take this path despite their low-byte or
low-dword resemblance to the sentinel.

On the ordinary path, MOV EAX,1 clears RAX's upper half and MOV ECX,EDI
clears RCX's upper half. SHL CL,RAX is a 64-bit shift whose effective
count is `CL & 63`. Because the least six bits are unchanged by the
ECX write, the count is exactly `x mod 64`. The count is between zero
and 63 inclusive. The shift therefore produces `2^n`; subtracting one
produces the geometric sum above, with no borrow or arithmetic overflow.
For n=0 the result is zero. For n=63 the result is `0x7fffffffffffffff`,
which is different from the sentinel result.

Both paths converge on the same instruction that stores RAX to
`[RIP+disp32]` (AT&T operands `%rax,disp(%rip)`). The next linked RIP is `0x5521d36` and its
signed displacement is `0x2663da`, giving `S`. Under a common load bias,
the computed address bits are `(b+S) mod W`. This address formation is
independent of `x`, `c` and the old global bytes. The final RET changes
neither RAX nor RCX. No store is omitted when the new qword equals its
old value.

## Source correspondence and safe domain

`apply(x,c,b,&mut [u8;8])` is a new safe value/store API, not an original
native signature. The supplied array represents exactly the target
slot's eight bytes; its Rust address has no relationship to `A`.
`Effects.store_address` reports address bits and is never dereferenced.
The enum-free API accepts every triple of u64 values and every initial
8-byte slot value. There is no undefined BSR, division, external call,
variable-length traversal or runtime global read to refuse.

The source compares the full u64 sentinel before any shift. Its ordinary
shift is bounded by `&63`, and `(1_u64 << n)-1` is between 0 and 2^63-1.
Thus overflow checks cannot panic for any admitted input. Its u32 cast
followed by u64 widening is exactly the zero extension of EDI to RCX.
The sentinel tuple preserves `entry_rcx`. The explicit wrapping addition
produces `A` for every bias bit pattern, including those whose sum crosses
2^64. The fixed-size little-endian conversion writes exactly eight bytes.
It follows that all returned fields and all final slot bytes equal the
relation for the full `2^64 * 2^64 * 2^64 * 2^64` input space.

Original-memory correspondence additionally requires normally mapped,
stable code under that common load bias, a complete writable eight-byte
slot at `A`, and valid return control. The data store must not overwrite
executed code or the return stack. Arbitrary numeric biases are admitted
by the safe projection but are not claims that all such process mappings
exist. No claim is made about MMIO, concurrent observations, faults,
physical access traces, timing, CET enforcement, original ABI, or flags.
The source reproduces final slot bytes and written GP values; the compiler
may choose a different physical store schedule.

## Static closure and data facts

The whole 91,774,280-byte target is authenticated before parsing. The
body and caller are independently locked by SHA-256; their actual FDE and
CIE bytes are retained. The checker enumerates all FDEs and requires one
exact overlapping FDE for each retained body. GNU frame output independently
confirms the extents. Complete Capstone decoding and fresh GNU listings
cover each byte; the leaf has no call and one forward branch.

The target slot belongs to writable `.data`, `[0x577a660,0x57882f0)`.
Its eight file bytes are all FF. That is a file initialization fact, not
a claim about the runtime value on entry. The function never reads the
old global, so no runtime initialization assumption is needed.
All 80,300 RELA records are scanned. No record names the entry, overlaps
the body/padding, or writes any part of this slot. Known relocation types
1,6,7,8,18 have eight-byte widths here; the overlap test also rejects
partial writers beginning before the slot. No dynamic relocation supplies
the destination: the instruction computes it directly from RIP.

Full `.text` E8/E9/EB pattern scans find only the E8 call at `0x54b9c3f`.
Its instruction boundary is checked from the caller's FDE start. The
caller loads RDI from the adjacent global `0x5788118` before calling.
This does not establish the adjacent global's meaning, a relationship
between the two qwords, or a whole-caller contract. Register-indirect
references, other encodings and arbitrary data pointers are outside this
candidate census; actual runtime reachability is unknown.

## Independent expectations and finite qualification

Before either Rust file existed, the oracle froze its own source hash,
static facts and 30,592 input/result records. It sums integer powers of two
and uses remainder arithmetic. The Rust implementation uses a bounded
machine-width shift and subtraction, and an explicit little-endian store.
The oracle does not execute or emulate captured instructions.

The corpus covers all 64 ordinary count classes across independent high
bits, 1,034 sentinel cases, 586 ordinary inputs with low32 all ones,
20,326 ordinary inputs with high32 set, 10,704 wrapping destination sums,
and 1,033 sentinel cases with nonzero preserved RCX. Initial slots vary,
including 948 already equal to their final value. Additional vectors span
every input/RCX bit, full-width boundaries, low-byte aliases and deterministic
random values. These counts describe finite fixtures, not an exhaustive
enumeration; the bit-width proof above supplies the universal relation.

Native qualification runs only newly compiled Rust on those frozen inputs,
at opt0/opt3 with repeats. Wrong native variants distinguish sentinel width,
shift-count width, mask construction, RCX preservation/extension, endianness,
store extent and the load-biased destination. Static corruption controls
exercise body, FDE/CIE, caller, initial data and unexpected relocation
writers independently of the complete-target identity check. Passing these
checks does not establish original-byte identity or whole-node equivalence.
