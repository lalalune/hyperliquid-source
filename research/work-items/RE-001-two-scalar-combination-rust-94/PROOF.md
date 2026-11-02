# Complete two-scalar combination and ordered-image proof

This proof covers node94 linked ELF VA `[0x565e7a0,0x565e956)`, 438 bytes and
130 instructions, under full target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The actual unique FDE, shared CIE and full GNU/LLVM instruction partition are
retained in `static/`. No original source identity or mathematical application
is assumed. In particular, the fifth input word is arbitrary; it is not assumed
to be a canonical sign limb.

## Admitted memory and observations

Let `M=2^64`, `H=2^63`, and `s(v)=v` for `v<H`, otherwise `s(v)=v-M`.
The original RDI and RSI provide destination `D` and source `S`; RDX and RCX
provide scalar bit patterns `x` and `y`. The safe API accepts one mutable byte
image at numeric `base`, with `S`, `D`, `x` and `y` supplied as `u64` values.
The image's exclusive end may equal `M`, but must not exceed it. The complete
nonwrapping source interval `[S,S+104)` and destination interval `[D,D+64)` must
fit in that image. Arbitrary unaligned and partial aliases are admitted.
All source bytes and both scalar bit patterns are unrestricted.

The image represents stable ordinary memory; destination memory is readable
and writable. Native code/control memory, stack return behavior and caller
control state must be valid and disjoint from these data accesses. Concurrent
changes, MMIO, faults, signals and instrumentation are excluded. This safe
contiguous-image model intentionally supplies stronger availability than raw
native pointers. It does not reproduce the native register calling convention:
the leaf itself writes RBX/RBP and R8..R15 without a standard callee-save wrapper.
Only all destination-byte effects and complete numeric RAX/RDX values are
claimed. Other registers, flags, RET/stack effects and exception/unwind behavior
are outside the source API contract.

The safe function checks both complete spans before its first store. Addresses
are fixed offsets from S/D; no value loaded from memory forms a later address.
Consequently early stores cannot invalidate the bounds of later loads. The
later **values** must still be read from the staged image, which the source
preserves. Any failed admission returns `Err(Unavailable)` and leaves the whole
image unchanged. That new refusal behavior is not a model of a native fault
that might occur after earlier stores. Outside the admitted domain there is no
native-equivalence claim.

## First snapshot, signed scalar minimum and fifth-word correction

At `0x565e7a4..0x565e7b7`, the target loads all five little-endian words
`a0..a4` from `[S,S+40)` before any data store. Let
`A = sum(ai*M^i, i=0..4)` and let `mx=abs(s(x))`. Because x is an arbitrary
64-bit bit pattern, `0<=mx<=H`. In particular `x=H` gives magnitude H, which is
representable as u64 even though negating signed i64::MIN is not representable
as signed i64. The Rust implementation uses unsigned wrapping negation.

SAR forms either zero or an all-one word from x's sign. XOR plus the single
carry-in converts both scalar and five-word input to:

- `mx = x` and `A'=A` when `s(x)>=0`;
- `mx = (-x) mod M` and `A'=(-A) mod M^5` when `s(x)<0`.

The five-word ADD/ADC chain at `0x565e7d9..0x565e7e8` propagates the two's
complement carry through the fifth word. This remains true for A=0, all-one
words, scalar zero and scalar minimum. Let `L=A' mod M^4` and `a4'=floor(A'/M^4)`.
The next four unsigned MUL/ADD/ADC rounds form `P=L*mx`. Their first four stores
at `0x565e7ef`, `0x565e805`, `0x565e819`, `0x565e82f` write `P mod M^4` into
`[D,D+32)`. The product carry into the fifth word is `C=floor(P/M^4)`.

The code at `0x565e820..0x565e82c` does not multiply a4' by the scalar. It forms
`K=a4' & mx`, negates K modulo M, and adds the final multiplication high half
and low-add carry. Thus RBP becomes `t=(C-K) mod M`.
For mx>0, `L<M^4` implies `C<mx`; also `0<=K<=mx`. Therefore
`-mx <= C-K <= mx-1`, which lies within `[-H,H-1]`. For mx=0, C=K=0.
The signed interpretation of t is universally the exact integer C-K; no
canonical fifth-word invariant is needed. Its later SAR is a valid signed
extension even when x is MIN and C-K is -H.

The contribution subsequently added to the second product is consequently

`F = (P mod M^4) + s(t)*M^4 = P - (a4' & mx)*M^4`.

The source retains the actual AND and wrapping word encoding. Replacing it by
a top-word multiply, testing only whether the word is nonzero, or imposing a
zero/all-one sign-limb interpretation changes admitted inputs.

## Ordered second snapshot and the 512-bit result

The first four stores finish before `0x565e833..0x565e84f` loads eight words
from `[S+40,S+104)`. Define the staged image by replacing `[D,D+32)` with
`(P mod M^4)` in little-endian byte order, leaving other entry bytes untouched.
Let B be the unsigned 512-bit integer read from `[S+40,S+104)` in that staged
image. This definition covers every byte alignment and overlap; if an early
store intersects this later span, its new bytes participate in B.

The y sign-mask/XOR/ADD/ADC sequence similarly obtains `my=abs(s(y))` and
`B'=B` when y is nonnegative, or `B'=(-B) mod M^8` when negative. The first
seven products are unsigned MUL. The eighth is signed IMUL, but its low
64 bits equal the unsigned product's low half for all input bit patterns.
The stored eight-word product is therefore `B'*my mod M^8`, which equals
`s(y)*B mod M^8`. This modular equality also holds for y=MIN, where my=H.

At `0x565e913..0x565e932`, the target copies t, sign-extends it, reloads the
first four destination words and adds the eight-word encoding of F with carry.
Those reloaded first four words still equal the early stores: intervening
operations only read memory. Source/output aliasing cannot change them by
itself. Rust may therefore use its retained `low` words for the same addition.
The entire carry chain completes before the final eight stores at
`0x565e935..0x565e950` replace `[D,D+64)`.

The complete final-memory relation is:

`destination_u512 = (s(y)*B + P - (a4' & mx)*M^4) mod M^8`.

All bytes outside the destination interval remain equal to the entry image.
The first five input words are always an entry snapshot; the next eight are
always a snapshot after the first four stores. A single initial 104-byte
snapshot would be incorrect for the admitted overlap domain.

For the Rust multiply helper, after processing i words the produced low words
and carry represent exactly the partial product divided at `M^i`. Each step
uses `word*scalar+carry` in u128. Since `word,scalar<=M-1` and `carry<=M-1`, its
maximum is `M^2-M`, below `2^128`; no u128 overflow occurs. The addition helper
uses at most two u64 words plus carry 1, also within u128. Conditional negation
uses complemented word plus carry 1. These bounds justify the safe arithmetic
for every admitted word/scalar, independently of finite tests.

## Exact raw RAX and RDX

Let the transformed B words be `b0'..b7'`. Let
`C7=floor((B' mod M^7)*my/M^7)`, the incoming carry before the final multiply,
and let `Q=s(b7')*s(my)` be the mathematical signed product performed by IMUL.
Its full low word is `q=Q mod M`; its high word is `floor(Q/M) mod M`.
The subsequent ADD to R15 contributes carry `c=floor((q+C7)/M)` and ADC adds
that carry to RDX. Therefore the leaf returns the numeric register values

`RAX=q`, and `RDX=(floor(Q/M)+c) mod M`.

RAX does **not** include C7. RDX does **not** include any carry from the later
addition of F. Neither register is modified by that later addition or the
final stores.

The Rust source computes the unsigned B-product carry `U=floor(B'*my/M^8)`.
Writing `eb=(b7'>=H)` and `em=(my>=H)`, signed multiplication expands as
`Q=b7'*my-M*(eb*my+em*b7')+eb*em*M^2`. Reducing the high word modulo M removes
the final term. Since U already includes c, the equivalent source expression
is `(U-eb*my-em*b7') mod M`. It handles both sign corrections, including my=H.
The oracle instead uses Q and C7 directly, providing a different derivation
for the claimed auxiliary-register observations.

## Static closure, independence and limits

The full target digest and all 121,299 FDEs/three CIEs are checked. The leaf has
one exact overlapping FDE, no calls, no RIP-relative data references and no
branches other than its return. Complete `.text` E8/E9 scans find seven E8
candidates and no E9 candidates targeting the entry. All seven are actual
instruction boundaries in the complete caller FDE `0x565df20..0x565e78b`
(2,155 bytes/472 instructions), bound independently by both disassemblers.
The caller's other outgoing calls are context only; its overall algorithm is
not reconstructed. Indirect calls/references are not excluded by this scan.
All 80,300 RELA records are scanned: none names this entry or writes either
bound code body. There is no leaf global-data or dynamic-helper dependency.
The caller-to-leaf call bytes are bound, not substituted by source-label claims.

`oracle.py` was frozen before the Rust directory existed. It performs whole
320/256/512-bit integer arithmetic, an explicit 32-byte image replacement, and
one mathematical second product. It does not execute native instructions,
simulate flags, import Rust logic or reuse the Rust wordwise multiplication
algorithm. The frozen corpus includes all 832 source bit bases, arbitrary fifth
words, signed minima, all overlapping byte displacements, map-boundary/refusal
cases and deterministic random images. Exact input, expected and oracle hashes
are checked. The input-only client never sees expected bytes or register values.
Finite native cases and effective mutants qualify the implementation against
this proved relation; the universal claim rests on the explicit bounds and
instruction reasoning above. No captured code or instruction emulator ran;
no target byte identity, native ABI or whole-caller/node equivalence is claimed.
