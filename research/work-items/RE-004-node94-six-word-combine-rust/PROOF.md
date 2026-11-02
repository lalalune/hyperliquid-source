# Six-word signed combination with ordered stores

This proof covers the complete 524-byte FDE `[0x565f000,0x565f20c)` of node
#94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are ELF VAs. No source function name, field modulus, GCD/Jacobi
algorithm, caller purpose or cryptographic meaning is inferred.

## Domain and projection

On entry, RSI names 96 ordinary readable bytes: two adjacent little-endian
384-bit unsigned values A and B. RDI names 48 writable bytes. RDX and RCX are
arbitrary 64-bit patterns, interpreted as two signed coefficients f and g.
The source and destination may overlap at any byte offset. The target ranges
must exist, their address formation must not wrap, and their contents must be
stable except for the writes in this function. Aliases with the function's
code, return/control/stack storage, concurrent writers, MMIO and faults are
excluded. There is no alignment requirement in the byte-image API.

`combine(image, source, destination, f, g)` admits exactly existing 96-byte
source and 48-byte destination spans. Its `MissingSpan` refusal occurs before
mutation; it is a new API policy, not an original return/fault. Successful
calls preserve the complete resulting image and the following value outputs:
R8..R13 (also the six stored words), RAX, RDX, RBX, R14 and R15. The target's
RSI is restored to its entry value; RDI and RCX are unchanged; RBP is untouched.
The function has no stack accesses except RET and no calls. Flags, timing,
physical pointer values, stack/return-address effects and native ABI are not
projected. Other registers are not inferred from a language calling convention.

## Complete body, accesses and caller evidence

The actual FDE at VA `0xfbd9ec` describes the complete 524-byte body, including
the two-byte `repz ret` at `0x565f20a`. Twenty alignment bytes follow outside
the FDE. The body has no jump, call, RIP-relative data edge or data table.
Both its bytes and actual FDE/CIE linkage are locked; GNU and Capstone agree
on complete decoding. All RELA records are checked: no naming relocation and
no relocation overlaps the body. A full `.text` E8 pattern scan has two hits,
`0x565ef7c` and `0x565ef8e`, both qualified by complete caller FDE decoding
from `[0x565eec0,0x565efe9)`. That caller is 297 bytes, not the 129-byte extent
stated for it as an excluded neighbor in an older foundation packet. The old
packet is preserved unchanged. No complete caller or indirect-xref census is
claimed here.

The memory schedule is significant:

1. `0x565f004..0x565f017` loads all six A words before any store.
2. `0x565f0bc..0x565f0cf` stores all six low words of the first product.
3. `0x565f0d3..0x565f0e6` loads all six B words from the **updated** image.
4. `0x565f188..0x565f19b` reads the first product words from the destination.
   No instruction has written those bytes since step 2, so they still equal
   the first product even if the B read overlapped them.
5. `0x565f1f3..0x565f206` stores all six final words after every arithmetic
   input has been read.

The six stores in each phase have disjoint 8-byte destinations; unaligned
source/destination overlap does not change their internal phase result. An
immutable overlay of the whole first 48-byte product is therefore equivalent
to the ordered stores before the B load. A snapshot of B taken on entry would
be wrong. The final writes overwrite all intermediate destination bytes, so
bytes outside the final 48-byte span are unchanged.

## Product identity and the negative-zero correction

Let `W=2^64`, `U=2^384` and `V=2^448`. For a 384-bit unsigned input x and a
signed coefficient c, define the signed mathematical expression

```
P(x,c) = c*x - (abs(c)*U if x=0 and c<0 else 0).
```

This extra term is established by the body, not an optional repair. For a
nonnegative coefficient, the six-by-one word multiplication computes `c*x`.
For negative c, write `m=abs(c)`, which is in `1..=2^63` even for i64::MIN.
The XOR/ADD/ADC chain computes `n=(-x) mod U`, discarding the final carry of
six-word negation. A schoolbook unsigned multiplication computes `m*n`; the
seventh word receives a correction of `-m` from `NEG R14` (first product) or
`NEG R15` (second product). Thus the seven-word value is

```
(m*n - m*U) mod V.
```

When x>0, `n=U-x` and the expression is `-m*x`. When x=0, n is zero and
the expression is **-m*U**, not zero. The carry of negating zero is lost
before the first MUL; the sign correction is still applied. This proves P
for all 384-bit inputs and all signed coefficients, including zero and MIN.
Each P lies in `[-2^447,2^447)`, but two such products need not have a signed
448-bit sum in range.

The per-word MUL/ADD/ADC recurrence is exact. If h is the carry entering a
word, `0<=h<m` (or h=0 for m=0), then `word*m+h <= W*m-1 < W^2` for m>0.
Its low word is stored and its high word is the next carry. Each ADC into the
next product high half therefore fits its intended carry recurrence; no
unaccounted overflow is required. After six words, the high word correction
is reduced modulo W, exactly giving the seventh word of P modulo V.

## Aliasing, addition and signed interpretation

Let A be the initial first value. Let I1 be the initial image with
`P(A,f) mod U` overlaid on the destination. Let B1 be the second value read
from I1. The source snapshot is then fully consumed. The ADD/ADC chain at
`0x565f188..0x565f19f` computes

```
T = (P(A,f) + P(B1,g)) mod V.
S = T                 if T < V/2,
    T - V             otherwise.
```

The final carry out of the seventh word is discarded. It must not be
interpreted as unbounded signed addition. R14's sign bit before its SAR is
the sign of S. R15 still contains the second product's seventh word; the
addition changes R14, not R15.

For example, two zero inputs with coefficients both i64::MIN give two
products `-2^447`, so their sum wraps to T=0. The final sign mask and result
are zero, while R15 remains `0x8000000000000000`. Treating the sum as an
unbounded integer would give the wrong sign and result.

## Shift, conditional negation and rounding

The six SHRD instructions at `0x565f1a2..0x565f1bb` extract bits 30..413 of
T. Their concatenated result is

```
Q = floor(S / 2^30) mod U.
```

This holds for both signs: arithmetic and logical shifts differ only in high
bits outside the retained 384-bit interval. The target then replaces R14
with zero or all ones using `SAR R14,63`, and RBX with its negation (0 or 1).
XOR of each word with that mask followed by ADD/ADC of RBX either keeps Q
or negates it modulo U. The stored result is consequently

```
R = abs(floor(S / 2^30)) mod U.
```

For negative nonmultiples of 2^30 this rounds the magnitude **up**, not down.
It is not generally `floor(abs(S)/2^30)`. For A=1, f=-1, B1=0, g=0,
S=-1 and R=1. For A=0, f=-1, B1=0, g=1, the negative-zero term gives
S=-2^384 and R=2^354; replacing P with ordinary multiplication gives zero.
The result is reduced modulo U after conditional negation; large shifted
magnitudes are not saturated or returned with extra words.

## Return value registers

The last MUL, at `0x565f17b`, acts on the top word of the transformed B1
(before multiplication carry is added) and `abs(g)`. Set

```
N = (-B1) mod U if g<0 else B1,
H = floor(N / 2^320) * abs(g).
```

RAX is `H mod W`, and RDX is `floor(H/W)`. The subsequent addition changes
R13/R15 rather than RAX/RDX, so returning the final result's low word in RAX
or its corrected high word in RDX is wrong. Other projected registers are:

| Register | Final value |
| --- | --- |
| R8..R13 | Six little-endian words of R |
| RBX | 1 if S<0, otherwise 0 |
| R14 | W-1 if S<0, otherwise 0 |
| R15 | floor((P(B1,g) mod V)/U) |

RCX keeps g's entry bits. The two LEAs add and subtract 48 from RSI, restoring
its entry value on the admitted nonwrapping range. RDI remains the destination
pointer. RBP is never written. RET and condition-code details are outside the
safe value/image API. All defined numeric outputs are tied to the same live
B1 read, not an independent entry snapshot.

## Rust and oracle independence

`frozen/ORACLE-FREEZE.json` records the oracle/source hash, full static facts,
input and expected hashes, and a timestamp while the Rust directory did not
exist. The oracle computes P with arbitrary-precision signed multiplication
plus the exceptional zero correction, uses immutable byte overlays, sums
modulo 2^448, and applies mathematical floor division/absolute value. Raw last
product registers are separately derived from the top 64-bit quotient of N.

Rust uses six-word complement/add, unsigned one-word products and carry,
a seven-word wrapping addition, cross-word shifts, and conditional six-word
negation. It loads B only after applying the intermediate stores. These
operations use new safe Rust arrays and byte slices, with no captured code,
assembly, external big-integer dependency or instruction emulator.

The span checks use checked `usize` addition before any mutation. Their
success proves every later byte index lies in the supplied slice. Six- and
seven-word array loops have fixed bounds; shifts are exactly 30, 34, 63 and
64 on appropriately wide values. Multiplication plus carry fits u128 by the
bound above; addition of two u64 words plus carry is at most `2^65-1`.
Only the documented high-word correction uses explicit wrapping subtraction.
Coefficient magnitude uses unsigned absolute value, so i64::MIN is defined.
Final carry discard and u64 shifts intentionally implement modular words.
There is no admitted panic, arithmetic UB or hidden allocation.

This proves the stated memory/value projection for every admitted image and
both full signed coefficient domains. Native fixture agreement supplies
additional qualification but is not direct target execution, machine-code
identity, ABI recovery, whole-node equivalence or a completion gate.
