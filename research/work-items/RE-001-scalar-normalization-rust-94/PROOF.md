# Complete scalar-sum normalization and image-order proof

The sole semantic target is node94 linked ELF VA `[0x565eaa0,0x565ec0b)`,
363 bytes/109 instructions, bound to full target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
`static/` retains identical complete GNU/LLVM partitions, actual FDE/CIE bytes,
the full caller and boundary context. The descriptive name does not establish
an original type, numeric application, library identity or source signature.

## Admitted memory and observables

Let `M=2^64`, `H=2^63`, `L=2^256`, and `J=2^320`. Define `s(v)=v` when `v<H`,
otherwise `s(v)=v-M`. Entry RSI/RDI give source S/destination D; RDX/RCX give
scalar bit patterns x/y. The safe API receives one mutable byte image at
numeric base and these four numeric values. The nonwrapping source span
`[S,S+64)` and destination span `[D,D+32)` must fit in the image. The image's
exclusive end may equal M but not exceed it. All partial, exact and unaligned
source/destination aliases are admitted. No scalar or source-word invariant is
imposed, including no nonzero-input or canonical-sign assumption.

The image models stable ordinary readable/writable data memory. Native code,
return-control memory and caller control state must be valid and disjoint from
the accessed data. Faults, MMIO, concurrent changes, signals and instrumentation
that alter execution are excluded. The source claims all final destination
bytes and complete numeric RAX/RDX/RCX. Other registers, flags, callee-save
conventions, RET/stack effects, unwinding and the original native ABI are not
reconstructed. The leaf itself writes RBX/RBP and R8..R15; a standard extern
signature is not inferred.

Both complete spans are validated before any safe API write. Every target data
address is a fixed offset from S/D; loaded values never select an address.
Admission therefore covers every later access even when early stores change
source bytes. A failed admission leaves the entire image unchanged. This new
refusal is not native partial-write/fault behavior, which remains outside the
relation. The contiguous-image API is a deliberately explicit safe projection
rather than an assertion that arbitrary u64 addresses are mapped pointers.

## Initial stores and operand snapshots

At `0x565eaa4` and `0x565eaa7`, the target first stores x at D and y at D+8.
The next four loads at `0x565eaae..0x565eab9` read A from `[S,S+32)`.
The four loads at `0x565eb26..0x565eb32` later read B from `[S+32,S+64)`.
There are no intervening data stores between these two load groups. Both A
and B are therefore the unsigned little-endian 256-bit integers in the
**staged image**, obtained by replacing `[D,D+16)` with the two scalar words
before either input snapshot. A single 64-byte snapshot after those stores is
valid for the source implementation. An entry-image snapshot is not valid on
all admitted aliases.

No other data stores occur until the final four-word result. Both initial
stores lie within the eventual 32-byte destination, so final memory outside
`[D,D+32)` equals entry memory. The target later reloads x/y from D/D+8 before
its final stores; those locations still hold the initial scalar stores because
all intervening data operations are reads. The source can use its retained x/y
values for the returned scalars under the ordinary-memory premises.

## Exact contribution of each scalar, including negative times zero

For one input U in `[0,L)` and scalar z, the sign-mask/XOR/ADD/ADC sequence
forms magnitude `m=abs(s(z))` as u64 and a four-word value V:

- if `s(z)>=0`, `V=U` and `m=z`;
- if `s(z)<0`, `V=(-U) mod L` and `m=(-z) mod M`.

The unsigned representation handles z=H: its magnitude is H without signed
negation overflow. The four-word conditional negation discards the carry out
of its highest word. That discard is observable when U=0 and z is negative.

Four unsigned MUL/ADD/ADC rounds produce the low 256 bits of `P=V*m` and its
high word `C=floor(P/L)`. The scalar sign word is separately ANDed with m and
negated, so the fifth word is `(C-m) mod M` when z is negative, or C otherwise.
The resulting five-word residue modulo J represents

`F(U,z) = V*m - (m*L if s(z)<0 else 0)`.

For nonnegative z this equals ordinary `s(z)*U`. For negative z and U>0,
`V=L-U`, so it also equals `s(z)*U`. But for negative z and U=0, V=0 and the
contribution is **`-m*L`**, not zero. Thus a separate closed form valid for all
inputs is

`F(U,z) = s(z)*U - (abs(s(z))*L if s(z)<0 and U=0 else 0)`.

The independent oracle uses this closed form, not native conditional limb
negation. The negative-zero exception is retained intentionally rather than
repaired to conventional signed multiplication. Each individual contribution
lies in the signed 320-bit interval: for negative z, `-H*L <= F <= 0`; for
nonnegative z, `0 <= F < H*L`. Their sum may leave that interval.

The source multiplication loop maintains the standard partial-product
invariant: after i words, output words and carry encode `V_low_i*m` divided at
`M^i`. A step is `word*m+carry` in u128. Even the unrestricted bound
`(M-1)^2+(M-1)=M^2-M` fits u128. Conditional negation is complemented word plus
carry 1. These bounds exclude accidental Rust overflow on all admitted values.
The top correction uses wrapping u64 arithmetic exactly as the target's word.

## Wrapped sum and sign before the 31-bit extraction

The ADD/ADC chain at `0x565eb9f..0x565ebab` sums both five-word contributions
and discards carry beyond the fifth word. Let

`T=F(A,x)+F(B,y)`, `W=T mod J`, and
`Z=W` if `W<2^319`, otherwise `Z=W-J`.

The sign used by the target is W's bit 319, equivalently `Z<0`. It is not the
sign of the unbounded T and not the sign of the later truncated 256-bit value.
For example, x=y=H with A=B=0 gives `T=-J`, so W=0 and the target's sign is
nonnegative. Two large positive terms can conversely produce a residue whose
bit 319 is set. Both directions of signed-sum wrap are within the input domain.

The four SHRD instructions at `0x565ebb5..0x565ebc4` extract consecutive bits
31 through 286 of W. Each uses the original next word: earlier SHRD updates
only the lower word, and the next instruction reads its own still-unshifted
higher neighbor. RBP (word 4) remains unshifted until SAR by 63 at `0x565ebc9`.
Thus the extracted 256-bit integer is `Q=floor(W/2^31) mod L`, while the mask
still comes from bit 319.

Since J/2^31 is a multiple of L, `floor(Z/2^31) mod L` equals Q whether Z is
negative or nonnegative. The following XOR/ADD/ADC sequence conditionally
negates Q in 256 bits using that original sign. Because a negative Z has a
negative floor quotient, the final output integer is exactly

`R = abs(floor(Z/2^31)) mod L`.

The floor matters. For Z=-1 the target produces R=1, whereas division that
truncates toward zero would produce 0. The 256-bit truncation matters as well:
a negative Z may yield output zero after reduction modulo L while retaining
a negative sign flag. Neither an output-zero test nor bit 255 of Q can replace
W's bit 319. The Rust implementation explicitly reads `sum[4] >> 63` before
forming four cross-word shifts and conditional negation.

## Complete RAX/RDX/RCX observations

XOR RAX,RAX followed by SUB RBP,RAX at `0x565ebcd..0x565ebd0` sets RAX to
one when the sign mask is all ones and zero otherwise. Later instructions read
RAX as a carry-in value but never overwrite it. So `RAX = int(Z<0)`.

RDX and RCX were reloaded from the initial scalar stores at `0x565ebae` and
`0x565ebb1`, before final result stores overwrite that memory. The final XORs
and separate ADDs at `0x565ebfd..0x565ec06` yield

- `RDX = (-x) mod M` and `RCX = (-y) mod M` when Z<0;
- `RDX = x` and `RCX = y` otherwise.

These two ADDs are independent; carry from adjusting x does not enter the y
adjustment. In particular x=0 on a negative-sum path returns zero in RDX without
adding an extra one to RCX. Scalar MIN negates to the same bit pattern. The
source returns these three complete values without masks; its own ABI need
not place them in the original physical registers.

## Static closure and independent qualification

The full target SHA and complete 121,299-FDE/three-CIE inventory establish one
exact overlapping leaf FDE. Full `.text` E8/E9 candidate scans find 30 E8 sites
and zero E9 sites targeting this entry. All 30 sites are actual instruction
boundaries in the complete caller `[0x565df20,0x565e78b)`, 2,155 bytes and
472 instructions, independently decoded by GNU and LLVM. Caller purposes and
its other outgoing callees remain context, not reconstructed dependencies.
The scan does not exclude indirect callers or all data-reference forms.

The leaf has no calls, internal branches or RIP-relative data references.
All 80,300 RELA records are checked: none names this entry or writes either
bound body. Exact FDE/CIE bytes, 21-byte padding after each selected body and
adjacent FDE `[0x565ec20,0x565ecb2)` are retained; the adjacent body is a boundary
only. The previous subtraction discussion's numeric mention of this FDE does
not constitute an implementation or an overlap with the subtraction leaves.

The oracle was frozen before the Rust directory existed. It applies the two
initial byte stores, reads two Python whole integers, uses the independently
derived zero-corrected products, reduces the sum modulo 2^320, then computes
absolute floor quotient and register values. It does not reuse word loops,
execute instructions, model native flags or import the Rust implementation.
Exact input/expected bytes, compressed bytes and oracle file are hashed.
The input-only client sees no expected data. Native repeated builds, compiled
mutants and corruption controls qualify the new source against this relation;
the universal claim rests on the proof, not finite-case extrapolation.
No captured binary or emulator ran, and no native ABI, original-source identity,
complete caller/node behavior or rebuilt-byte equality is claimed.
