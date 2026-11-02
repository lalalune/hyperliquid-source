# Complete scalar 384-to-768-bit square

Node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The selected complete FDE is linked ELF VA `[0x565b800,0x565ba10)`, 528 bytes /
160 instructions. This proof covers every six-u64 input, all 12 stored words,
and all 14 written GP values. It does not assign a source/library/cryptographic
identity or infer reduced limbs.

## Polynomial decomposition and bounds

Let B=2^64, `a0..a5` be arbitrary integers in `[0,B)`, and

```
A = sum(ai*B^i),
K = sum(ai*aj*B^(i+j), 0<=i<j<6),
D = sum(ai^2*B^(2i), 0<=i<6),
S = A^2 = 2K+D.
```

Thus `0<=S<B^12`. K is the cross-term polynomial, counted once; its digits are
`ck=floor(K/B^k) mod B`. In fact `K<B^11`. To see a convenient strict bound,
row i contributes `ai*B^i*sum(aj*B^j,j>i) < (B-1)*B^(i+6)`.
Rows 0..3 together are less than `B^10-B^6`. The last row 4 is at most
`(B-1)^2*B^9 = B^11-2B^10+B^9`; their sum is below B^11. Therefore c11=0.

Every unsigned MUL supplies its exact low/high product. To add a product to a
partial cross-term row, the target adds the current digit and an incoming carry
digit to that product. The unbounded intermediate is at most
`(B-1)^2+(B-1)+(B-1)=B^2-1`, so its high part still fits one u64. The two successive
ADC adjustments cannot silently discard an extra high word. This establishes
ordinary exact base-B row accumulation for all inputs, not only small limbs.

The target starts with products a0*aj for j=1..5 (`0x565b816..0x565b867`).
It then adds row 1's products at `0x565b888..0x565b8da`, row 2 at
`0x565b901..0x565b940`, row 3 at `0x565b967..0x565b98f`, and row 4 at
`0x565b9ba..0x565b9c7`. Stored lower output words and later rows interleave,
but row i contributes only from digit 2i+1 upward. Hence every cross digit needed
for an already emitted output pair is complete before that pair is emitted.
This is the usual triangular square decomposition, established from all target
products and their carry chains rather than an inferred source label.

## Diagonals, pair carries and apparently discarded flags

For k=0..6 define the carry entering output digit 2k by

```
q(2k) = floor((2*(K mod B^(2k)) + sum(ai^2*B^(2i), i<k)) / B^(2k)),
```

with q(0)=0. The truncated cross polynomial is below B^(2k). The diagonal prefix
is below B^(2k), since
`(B-1)^2*sum(B^(2i),i<k) < B^(2k)`.
Consequently `q(2k)` is always 0, 1 or 2. At stage k the exact two-digit update is

```
2*(c(2k)+B*c(2k+1)) + ak^2 + q(2k).
```

Its low two base-B digits are S's digits 2k,2k+1; its quotient by B^2 is
q(2k+2). The target performs this decomposition for diagonal products at
`0x565b86a`, `0x565b8dd`, `0x565b943`, `0x565b992`, `0x565b9ca`, and
`0x565b9f2`, emitting all twelve words in increasing address order.

Several target ADDs form `low(ak^2)+q(2k)` and then overwrite their flags before
using a carry. This is safe on the complete input domain: any integer square is
0 or 1 modulo 4, so its low u64 word is at most B-3. Adding at most 2 cannot
reach B. Thus no carry is lost at `0x565b8e3`, `0x565b949`, `0x565b998`,
`0x565b9d0`, or `0x565b9f5`. The target's separate doubled-cross carry and
subsequent diagonal-add carry together recover precisely the pair quotient
above. In the final pair c11=0, and S<B^12 ensures no omitted output word.

The Rust source independently accumulates the cross polynomial into a 12-word
array by adding low/high u128 products with ordinary carry propagation. It then
combines each cross pair with a diagonal using two u128 column sums. Each column
sum is at most `2*(B-1)+(B-1)+2=3B-1`, well within u128. Its low casts and high
shifts therefore implement the pair identities exactly. `add_product` is modular
base-B addition over 12 words; all genuine partial K sums are below B^11, so it
cannot lose a nonzero final carry. Input indices are fixed in 0..6 and cross
indices at most 9, making each product's two output slots valid.

## All fourteen written GP observations

Let `s0..s11` be S's base-B words. Define the partial cross polynomial

```
K2 = sum(ai*aj*B^(i+j), 0<=i<3 and i<j<6),
r = floor((a3*a4 + (floor(K2/B^7) mod B))/B).
```

The partial word is the cross digit present in R15 before row 3. The product
and that digit are added at `0x565b967..0x565b978`; r is copied into R8 and
never overwritten afterward. The sum is at most B^2-B, so r fits u64.
The final register mapping is

| Register | Exact complete value |
| --- | --- |
| RAX | s10 |
| RBX | s9 |
| RCX | s8 |
| RDX | s11 |
| RBP | (2*c10) mod B |
| RSI | a5 |
| R8 | r above |
| R9 | (a2^2 mod B)+q(4) |
| R10 | s2 |
| R11 | (a3^2 mod B)+q(6) |
| R12 | (a4^2 mod B)+q(8) |
| R13 | q(10) |
| R14 | s6 |
| R15 | s7 |

R9/R11/R12 are intermediate low-diagonal sums, not the corresponding stored
square words. They fit u64 by the modulo-4 argument. R13 is the carry entering
word 10, not the carry after the full square. RBP retains the doubled final
cross digit after its possible high bit has separately contributed to RDX.
RSI is overwritten by the final input word; it is not the returned source
pointer. RDI is never changed and is explicitly outside the written-register
projection. Every other entry value of the fourteen written registers is
replaced before its relevant use; the input's source address is used only until
its six loads finish. Flags, unchanged registers, native ABI and return/control
storage are not represented.

## Memory order and arbitrary data aliases

The six input qword loads occur at `0x565b804`, `0x565b807`, `0x565b80b`,
`0x565b80f`, `0x565b81f`, and `0x565b833`. The first output store is at
`0x565b870`. There is no later data-memory read, no call, and no stack scratch
access. Therefore a single snapshot of all 48 input bytes precedes every one
of the twelve output stores. All stores use the unchanged RDI at distinct
ascending qword offsets 0..88. The safe implementation's snapshot followed by
96 output bytes preserves every exact, partial, unaligned or cross-limb data
alias. Bytes outside that destination span remain unchanged.

`apply` represents one image `[base,base+len)` with exclusive end at most 2^64.
It requires nonwrapping readable input48 and writable destination96 spans;
byte alignment is unrestricted and a span may end exactly at the image end.
It checks both spans and checked index arithmetic before any store. Refusal
returns None with the image unchanged, an added safe-API policy rather than a
claim about native invalid-pointer results or fault ordering. Pure `square`
retains the complete six-u64 arithmetic domain independently of mapping.

Correspondence assumes ordinary stable little-endian memory and valid unchanged
code/normal return control, with output/input data disjoint from return/control
storage. MMIO, volatile reads, races, faults, native control aliases, arbitrary
wrapped address layouts, flags and timing are excluded. The target's interleaving
of arithmetic and stores is not a concurrent-observation contract here.

## Caller and variant boundaries

The complete FDE/CIE inventory validates the unique 528-byte body, four complete
caller contexts and 16 following padding bytes. Four E8 instructions at
`0x565b7c2`, `0x565ba54`, `0x565c966`, and `0x565ca26` target its entry.
Full .text E8/E9 scans into the entire selected interval find no additional
candidate; no RELA addend names it and no relocation writes bound code. The
selected body has no outgoing call, branch, RIP-relative literal/table, import
or unknown helper. Caller bodies supply boundary/entry evidence only, not their
other helper semantics or a reconstructed caller algorithm. Indirect/computed
reachability is not claimed complete.

The separately observed ADX body `[0x5658a00,0x5658c02)` also has a square-shaped
cross/diagonal calculation, but it takes output control from its custom stack
and reloads input limbs between stores. Its arbitrary-alias and raw-register
contract is different. It is not implemented, qualified or counted by this
packet, and no exhaustive square-family claim is made. The actual scalar body
has a unique exact occurrence in .text; that is not a semantic census.

## Independent oracle and finite qualification

Before Rust, the oracle computed S by one unbounded integer square, K/K2 as
whole polynomial sums, q from quotient/remainder of those sums, and output words
by base-B division. It never runs a limb ADC chain, target instruction stream,
Rust implementation or captured executable. Image expectations snapshot one
whole input integer and write its whole square to a copied image. This differs
from the source's cross-product array and paired u128 columns.

The formulas above establish the relation for all 2^384 input values and every
admitted alias. Frozen fixtures, repeated optimized/unoptimized builds and
observable compiled wrong variants qualify the implementation/comparator; finite
matching cases are not a substitute for the universal argument. There is no
captured execution, instruction emulation, assembly transplantation, original
source attribution, whole-node equivalence or component-gate completion claim.

The parent's first optimized replay of committed head
`5b7d841bf330408372669bc378efe566da618796` completed four correct runs and 28
effective mutants, then stopped at a compiler-linker disk-full error. That
interrupted run is retained under `parent-disk-failure/` and does not supply a
complete replay claim. Its failure required storage recovery and a fresh output
directory, not an arithmetic, source, oracle, fixture or validator change.
The worker subsequently completed the requested fresh-directory `python3 -O`
retry: all9,592×4 outputs,35 compiled mutants,178 static controls, five comparator
controls and two archive controls passed. Its full result and39-stream archive
are byte-identical to the first complete qualification. The separate records
under `parent-retry/` preserve this retry's provenance without reclassifying the
parent's interrupted process as complete.
