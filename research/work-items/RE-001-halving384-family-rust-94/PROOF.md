# Complete 384-bit parity-add/halve family

Node94 target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF VAs. The three complete FDEs are core
`5656b20..5656bb9` (153 bytes), single wrapper `5656bc0..5656c2a`
(106 bytes), and repeated wrapper `5656aa0..5656b0b` (107 bytes).
Names describe recovered operations, not original source/library identity.

## Scope, memory and observations

Write B=2^64, Q=B^6. Six little-endian words encode any A,C in [0,Q).
The core receives A in R8..R13 and reads all six C words from RCX. C may be
zero, even, odd, above/below A or noncanonical. The API `step` takes snapshots
and reports the six result words plus RAX, RSI, RBX, RBP, R14 and R15: all 12
GP registers written by this core. Flags and control state are excluded.
Its numeric API does not claim a normal compiler calling convention: the target
core overwrites registers normally saved by a wrapper.

Both wrappers load A from RSI, pass C by RCX and store all six result words to
RDI only after the last core call. Single sets RCX from entry RDX and calls once.
Repeated leaves RCX unchanged and uses only the low 32 bits of entry RDX as a
count. It calls before decrementing EDX, so its exact count is

```
n = low32(raw_count), when nonzero; n = 2^32 otherwise.
```

Every u64 raw count is admitted numerically; high bits are ignored. There is
no execution budget or count refusal. DEC EDX zero-extends, so full RDX=0 at
the repeated wrapper's return. Single leaves RDX equal to its correction pointer.

The image API maps a nonwrapping numeric interval `[base,base+len)` with end at
most 2^64. Each input, correction and destination must contain 48 complete bytes.
It checks all three spans before reads/writes, including for zero/even A or C=0.
The image must contain ordinary stable readable input/correction bytes and writable
destination bytes corresponding to the target. The original PUSH/CALL/stack restore
and return accesses must be valid and disjoint from data/code. Both wrappers
push seven qwords before reading A; data aliasing those control writes is excluded.

The core performs six correction reads on every invocation: five MOV loads and
one unconditional AND memory operand. It writes no data memory. The wrappers
load A once, perform all iterations with no data stores, then store six qwords
in ascending order. Stable C can therefore be snapshotted once without changing
values. Both complete input snapshots precede the first output store, so exact,
partial and unaligned aliases among all three data spans are permitted. Sequential
output stores have disjoint destinations and produce the same final 48 bytes as
the safe API. Every other image byte is unchanged. The API's range/wrap refusal
returns None without mutation; this is a new safe-domain response, not native
fault behavior. MMIO, concurrent changes, volatile read counts, faults, flags,
stack/control effects and ABI preservation beyond the listed values are excluded.

## Exact one-step arithmetic

At `5656b24`, RSI becomes `-(R8 & 1) mod B`, selecting either all C words or
zero. ADD/ADC sums those six selected words with R8..R13. Its six low words are
s0..s5 and the final carry is e in {0,1}. `SBB R13,R13` records -e. Thus the
unbounded sum is S=A+(A mod2)C, satisfying 0<=S<=2Q-2.

Logical shifts of each low word, shifts of each next word's low bit into bit63,
and the carry-mask bit shifted into the top word combine into V=floor(S/2).
Hence 0<=V<Q; no truncation of the 385th sum bit is allowed. The six result
registers R8..R13 are exactly the six words v0..v5 of V.

The temporary words are shifted right individually before cross-word ORs.
For each i, `si>>1 = vi & (2^63-1)`, because only bit63 of vi came from the next
word or high carry. Inspection of the full instruction sequence therefore gives

```
RAX = v2 & LOW63     RSI = v5 & LOW63
RBX = v3 & LOW63     RBP = v4 & LOW63
R14 = v0 & LOW63     R15 = v1 & LOW63
(R8,R9,R10,R11,R12,R13) = (v0,v1,v2,v3,v4,v5)
```

These identities depend solely on final V, so they remain recoverable after
accelerating repeated steps. In particular RAX is neither the low result word
nor the carry mask; RSI is not a pointer or the original parity mask at return.
The Rust one-step operation uses u128 sums for six words: each total is at most
2B-1 and fits u128. Fixed shifts 1,63,64 preserve the full 385-bit result.

## All-count closed relation, including even C

For C=0, F(A)=floor(A/2), so n steps give floor(A/2^n), zero for n>=384.
For C>0 define positive odd D=C if C is odd, else C-1. When A is even both
recurrences halve A. When A is odd and C is even, floor division drops the
extra one, so both parities satisfy exactly

```
A_(j+1) = (A_j + p_j*D)/2, p_j=A_j mod2.
```

This is an arithmetic normalization, not an assertion that C is a modulus.
Zero stays zero. For positive A and D, both branches remain positive, and D is
a fixed point. C=1 and C=2 both yield D=1 and repeated ceiling division.

Expanding k steps without a limb model gives

```
2^k A_k = A_0 + D*T,  T=sum(p_j*2^j), 0<=T<2^k.
```

D is invertible modulo 2^k, so T is uniquely
`(-A_0 * inverse(D modulo 2^k)) mod 2^k`.
This is the oracle's exact small-count formula; it performs no recurrence loop.
For k>=384, A_0<Q<=2^k and T<=2^k-1 imply
`0<=A_k <= D+(A_0-D)/2^k < D+1`; hence A_k<=D. For positive A, positivity
narrows this to 1..D. Thus 384 ordinary steps suffice for every unreduced input.
Also `A_k = A_0*2^(-k) mod D`. For positive A the unique representative is in
1..D, assigning a zero residue to D, not zero. D=1 gives one; A=0 gives zero.
This proves the large-count oracle formula even for n=2^32, without a giant
2^n or billions of iterations.

## Bounded accelerated Rust

The implementation performs min(n,384) actual arithmetic steps. If no remainder
exists, that is final. If the value is zero it remains zero. A nonzero result
after 384 steps proves C>0, so constructing D cannot underflow to an invalid
zero modulus. If value=D it is fixed, which also covers D=1. Otherwise both
value and `(D+1)/2` are strictly between zero and D, and the latter is inverse2
modulo odd D. The source forms it as floor(D/2)+1, avoiding overflow at D=Q-1.

Binary exponentiation applies inverse2^(n-384). At most 32 exponent bits occur.
The modular product uses Horner evaluation of all 384 multiplier bits from high
to low: `r <- 2r + bit*a mod D`. Its modular addition inputs are below D;
the full 385-bit sum is below 2D. Exactly one subtraction suffices when the
sum is at least D. If the six-word sum overflowed Q, the wrapped subtraction
still gives `sum-D` modulo Q, and that true value is below D<Q. Otherwise the
ordinary borrow determines whether subtraction is needed. The helper ORs the
two subtraction borrows, preserving MAX-plus-incoming-borrow cases.

Every modular product therefore maintains canonical residues. The fixed D case
was already removed; nonzero residues multiplied by a unit cannot become zero.
The final zero-residue-to-D branch agrees with the positive representative
convention even though it is unnecessary for these strict canonical inputs.
Each computation is bounded independently of native iteration count. No numeric
input or raw count is refused; only safe-image address admission can refuse.
The acceleration changes timing and intermediate writes to registers, which are
excluded, while the proven final observations are identical.

## Wrapper final data registers and memory

Each wrapper restores RBX,RBP,R12,R13,R14,R15 from its own stack after writing
output. Those entry-dependent values are not fabricated by this API. RDI remains
the destination address, and RCX remains the correction address. The core does
not write RDX. The wrapper observations returned by `apply` are exactly

```
RAX=v2&LOW63, RSI=v5&LOW63, RCX=correction, RDI=destination,
R8=v0, R9=v1, R10=v2, R11=v3,
RDX=correction for Single; RDX=0 for Repeated.
```

The destination also stores v4 and v5, although the native wrappers restore
R12/R13 afterwards. No claimed register is altered by the epilogue. This full
value relation differs from the earlier four-word target's auxiliary register
layout, even though both operations share an arithmetic recurrence.

## Static and prior-work boundaries

All three selected FDEs have unique exact overlaps in the full 121,299-FDE / 3-CIE
inventory; each uses CIE 0xce1518. The wrapper→core calls at 5656ac6 and 5656be9
are the complete outgoing closure. Single has four incoming E8 sites (5646ad4,
5646af7,564ce07,564ce31) in two full caller FDEs of 354 and 1406 bytes. Repeated
has no E8/E9 candidate or naming relocation. All six sites are confirmed at
instruction starts by GNU and LLVM complete-body decoding. All selected bodies
lack RIP-relative operands and indirect calls; C is caller-provided memory.
There are no outside branches in the closure; repeated's JNE is its internal
back edge. All 80,300 RELA records are checked for entry names and code writers.

The two external callers are bound solely as complete call-site context. Their
other helper calls, constants and algorithms are not reconstructed. In particular
caller LEAs to 918940 do not impose that constant on the all-input C API. No
fixed global, table, import or unknown stub is required by these three bodies.
Indirect reachability beyond E8/E9/RELA scans is unclaimed. Alignment gaps of
21,7,22 bytes and the following 5656c40 FDE are boundary-only evidence.

Prior independently authored MIT PR #1522, commit
`c4efb12070859ebe2674208aea16cfa4d66fa8a5`, reconstructs the distinct four-word
body 565dbc0..565dc5f. Its proof/source was read as mathematical context. This
contribution independently derives six-word bounds, all three complete bodies,
all 12 core and 9 wrapper observations and arbitrary image aliases from new bytes.
Its new Horner modular multiplier and frozen whole-integer oracle are not an
instruction interpreter or copied inferred source. No existing source component
or historical evidence is modified, and no larger completion gate is claimed.
