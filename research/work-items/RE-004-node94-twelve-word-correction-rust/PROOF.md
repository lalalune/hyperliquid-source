# Complete twelve-word correction family

This proof concerns node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
not a recovered source name or general modular-arithmetic specification.
The three complete FDEs are:

| API member | Half-open target interval | Bytes | Instructions |
|---|---|---:|---:|
| AddSaved | `0x5657ce0..0x5657dec` | 268 | 72 |
| SubSaved | `0x5657e00..0x5657f02` | 258 | 71 |
| SubRaw | `0x5657f20..0x5657ff1` | 209 | 57 |

The saved entries preserve six registers through stack saves/restores. The raw
entry has the subtraction data relation but exposes their final working values.
The intervening 20/30-byte and trailing 15-byte padding is bound separately.
The six-word neighbor at `0x5658000` is excluded. The family has no internal
calls, conditional branches, RIP-relative data, or entry-naming RELA records.
All 80,300 RELA records are checked for naming addends and overlapping writers;
all three complete bodies, the eight caller bodies and padding are protected.
The E8/E9/EB byte scan finds 41/61/6 E8 candidates respectively, each at a
decoded instruction boundary in one of eight complete caller FDEs (5,615 bytes,
1,354 instructions); no E9/EB candidates. This is bounded static call evidence,
not a complete indirect-reference census or a reconstruction of the callers.

## Admitted memory and observation

`apply` receives a member, one mutable byte image, its u64 base, four u64 data
addresses, and the incoming six-register tuple. The image interval may end at
2^64 but must not extend beyond it. A and B each need 96 bytes, M needs 48,
and destination D needs 96, wholly inside the image. Unaligned accesses and
arbitrary partial overlaps among these four spans are admitted. All input words
are arbitrary u64 values. There is no reduced-input, odd-modulus, nonzero, prime,
or cryptographic-domain assumption. M is simply a correction word sequence.

The original execution is assumed to have valid ordinary mapped memory with no
concurrent writes or MMIO side effects. Its return address and stack/control
storage must be valid and disjoint from the entire supplied data image. Saved
variants use their original pushes, 8-byte reservation, six loads and 56-byte
stack restoration; the supplied tuple represents the values those saves retain.
The library does not simulate its own Rust call stack as original target data.
These premises permit moving pure register calculations past accesses; they do
not permit moving reads across overlapping data stores.

All required spans are checked before mutation. `None` is a new safe-API atomic
refusal and is not a target return, exception, fault-order or accessibility
claim. A successful call describes all data-image bytes and full final RAX,
RDX, RSI, R8..R11, RBX, RBP, R12..R15. RDI and RCX are unchanged input addresses.
Flags, RIP, original RSP/stack bytes, timing, native ABI, and faulting execution
are outside the projection. Zero values in the driver's refusal register record
are protocol fields, not inferred original register values.

## Prefix stores determine live input words

Let B0=2^64, K=B0^6, and T=K^2. Words are little endian. Let A be the initial
96-byte integer, and b be B's initial low 48-byte integer. All twelve A words
and all six low B words are loaded before the first data store. Their loads are
interleaved with arithmetic but no data mutation occurs during that interval.
Thus even A/B aliasing leaves these snapshots exact.

The low output is `L=(A mod K + b) mod K` for AddSaved and
`L=(A mod K - b) mod K` for subtraction. Its six words are fixed before any
data store. Define P_j as an immutable overlay of the first j low-word stores
on the initial image. The order of word indices is **0,1,2,4,3,5** for addition
and **0,1,2,3,4,5** for subtraction. This unusual addition order is observable
under aliases; sorting it changes the actual relation.

For i=0..5, the effective high B word h_i is loaded from B+48+8i in P_(i+1).
In subtraction the effective correction word m_i is loaded from M+8i in that
same P_(i+1), before the next low-word store. In addition all m_i come from P_6.
Define `B_eff=b+K*sum(h_i*B0^i)` and `M_eff=sum(m_i*B0^i)`. These definitions
cover every alias without a fixed-point equation: each P_j uses already-known
low words. Reads remain ordinary byte-interval reads even when only part of a
qword is overlaid. For subtraction it is incorrect to sample all M words from
the original image or after all six low stores.

No source read follows a high-output store. Consequently the final image is
P_6 overlaid by the six corrected upper words at D+48..D+95. Computing those
words before issuing the high stores preserves all observations, despite the
target interleaving those stores with register additions/conditional moves.
No byte outside D..D+95 is changed.

## Addition and its two carry bits

Let `W=A+B_eff`, `c=[W>=T]`, `S=W mod T`, and `H=floor(S/K)`. Because each
operand is in [0,T), c is a bit. The twelve ADD/ADC instructions compute S and
c by radix-B0 carry propagation. Let `bH=[H<M_eff]`, also a bit. The six
SUB/SBB instructions compute `Q=(H-M_eff) mod K` and bH. SBB RDX,RDX first
sets RDX to -c modulo B0. The final SBB RDX,0 produces

`RDX=(-c-bH) mod B0`.

Its borrow flag is set exactly when c=0 and bH=1: subtracting bH from B0-1
(c=1) never borrows, while subtracting one from zero (c=0) does. All following
CMOVB instructions see that same flag; intervening MOV instructions preserve it.
The corrected upper integer U is therefore H when `!c && bH`, and Q otherwise.
In particular c=1,bH=1 yields RDX=B0-2 and selects Q. Dropping the outer carry
or treating RDX as a Boolean loses admitted behavior. This is one correction
step, not a promise that U is canonical modulo M_eff.

Let u_i and h_i' be the words of U and H. Final RAX=u_2 and RSI=u_5.
R8..R11 retain h_0'..h_3', the uncorrected high words, even when U differs.
RBX,RBP,R12,R13,R14,R15 restore the supplied entry tuple.

## Subtraction and raw working-register returns

Let `W=A-B_eff`, `bW=[W<0]`, `S=W mod T`, and `H=floor(S/K)`. Twelve
SUB/SBB operations compute S and bW. SBB RDX,RDX sets RDX=-bW modulo B0.
Each correction word is ANDed with this full-width mask, giving
`v_i=bW*m_i`. The six ADD/ADC operations give

`U=(H+bW*M_eff) mod K`.

The final carry is discarded; it is not an additional upper output word.
All M words are loaded unconditionally, including bW=0 cases. RAX=u_2,
RSI=u_5 and R8..R11=v_0..v_3. SubSaved restores the supplied six registers.
SubRaw instead leaves RBX=u_3, RBP=u_4, R12=v_4, R13=v_5, R14=u_0, R15=u_1.
The six-register difference is part of this coherent family's question.

## Rust correspondence and totality

The source uses twelve u64 words and fixed six-iteration loops. An addition
step uses u128 `a+b+carry <= 2*B0-1`, so it cannot overflow u128; the low
word and high bit are the exact ADD/ADC result. A subtraction step combines
the borrows of two `overflowing_sub` operations with OR, which is precisely
the borrow of `a-b-carry`. The same facts prove all twelve-word and correction
chains by induction over word index. Final mask arithmetic uses explicit
wrapping operations. There are no data-dependent shifts or divisions.

Span conversion and checked subtraction/addition establish each index range
before reads/writes. Array indices range over fixed sizes; output+88+8 fits
the admitted image. `base+length` is calculated in u128. The implementation
is total for every supplied slice, u64 address tuple, member and saved-register
tuple: it either refuses without a write or returns the proved observation.
These are safe Rust value semantics, not a claim to run the Linux target ABI
on the macOS qualification host.

## Independent expectations and finite qualification

The frozen oracle was authored and frozen before the new Rust directory
existed. It computes whole 384/768-bit integers, derives carries by comparison,
and evaluates immutable byte overlays for read/final-image intervals. The Rust
uses per-word carry/borrow propagation and live mutable image accesses. Thus
the oracle does not obtain expectations from Rust, compiled output, a lifted
instruction interpreter, or executing the captured image. The static evidence
binds both derivations to the complete instruction bodies.

The 19,410 frozen cases include every 768-bit A boundary and 384-bit correction
boundary with +/-1 neighbors, saved-register bits, deterministic arbitrary
words, all 289 destination offsets for five source layouts, and memory/address
limits. There are 18,783 admitted and 627 refusal cases, 6,470 total per member;
3,141 admitted aliases, 865 changed live-B observations, 975 changed live-M
observations, and all four addition carry/high-borrow combinations. Finite
qualification complements the universal argument; it is not exhaustive over
the 768-bit or address domains. Compiled controls, exact raw streams and their
scope are recorded separately. No byte equality to target machine code,
captured execution, whole-caller behavior, whole-node ABI or milestone gate
completion is claimed.
