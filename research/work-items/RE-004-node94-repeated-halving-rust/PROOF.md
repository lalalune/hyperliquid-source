# Repeated halving: all-input and all-count proof

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The exact complete FDE is `[0x565dbc0,0x565dc5f)`, 159 bytes including
its two-byte `repz ret`. One following NOP byte is alignment context only.
All addresses are original ELF VAs. No neighboring function is claimed.

## Domain, count and memory

Write `B=2^64`, `N=B^4`. Entry RSI points to four input qwords encoding
`X in [0,N)` little-endian; RCX points to four correction qwords encoding
`M in [0,N)`. Entry RDI is the 32-byte destination. Entry RDX is a raw u64
whose low32 count is used. No input is presumed reduced; M need not be odd,
nonzero, a modulus, or related to X.

The loop body is entered before the only count decrement. DEC EDX wraps
modulo `2^32`, then JNE repeats until zero. Thus the number of passes is

```
n = low32(RDX), if low32(RDX) != 0;
n = 2^32, otherwise.
```

High count bits do not participate. There is always at least one iteration.
Each DEC writes EDX and zero-extends RDX, so final full RDX is zero.

The original loads X once, reads all four M qwords on every pass, then writes
all four output words only after the last pass. The first three M words are
unconditional MOV loads; the fourth is an unconditional AND memory operand.
No stores occur inside the loop. Therefore the source can snapshot X/M before
all stores, including when their windows partially or completely overlap the
destination or one another. The image outside the destination remains intact.

This correspondence requires successful, stable ordinary-memory reads/writes
and valid address formation. Data windows must not overlap the original saved
registers, stack scratch or return-control storage: PUSH RBP/RBX precedes the
input loads, and stack restoration follows destination writes. Faults, flags,
concurrency/volatile effects, stack control and the machine ABI are excluded.
A range outside the supplied safe image or an overflowing range addition gives
`None` without mutation; this is a new API refusal, not original behavior.
Even zero X requires both readable input windows under this stated domain.

## Exact single-pass arithmetic

At loop head RBP,R9,R10,R11 contain the current four words. R8 receives
RBP, and `AND RBP,1; NEG RBP` constructs the all-ones mask precisely when
X is odd. The M loads are masked, then the ADD/ADC chain forms the full
257-bit integer

```
S = X + (X mod 2)*M.
```

The low four words are kept in R8..R11 and `SBB RAX,RAX` records the
carry out as zero/all-ones. Separate logical right shifts divide each word
by two; left shifts of the following words' low bits supply the cross-word
bits. The carry mask shifted left63 supplies the 257th-bit contribution to
the top result. The next value is exactly

```
F_M(X) = floor((X + (X mod 2)*M)/2).
```

Since `0<=S<=2N-2`, `0<=F_M(X)<=N-1`. This preserves the four-word
domain on every iteration. Retaining the add carry is essential; dividing
only the wrapped 256-bit sum would fail when S>=N.

## Odd-D normalization, including even and zero M

If M=0, the recurrence is ordinary floor division by two, so after n passes
`X_n=floor(X_0/2^n)`, zero for n>=256. If M>0 define the positive odd
integer

```
D = M when M is odd; D = M-1 when M is even.
```

For even X, both original and normalized recurrences give X/2. For odd X,
M odd makes X+M even; M even makes X+M odd, and floor division removes one.
Thus in both cases

```
X_(i+1) = (X_i + p_i*D)/2, where p_i = X_i mod 2.
```

This quotient is integral. This derived D is an arithmetic device, not an
assertion about the original correction operand's meaning. In particular M=1
and M=2 both give D=1, and the recurrence is ceiling division by two.
For M>0, zero remains zero; every positive X remains positive. D itself is a
fixed point. None of these facts assumes X<=D initially.

## Closed form and contraction

Expanding k recurrence steps gives

```
2^k X_k = X_0 + D*T_k,
T_k = sum(p_i*2^i for i=0..k-1),  0<=T_k<2^k.
```

Because D is odd, it is invertible modulo `2^k`. Hence T_k is the unique
integer in that interval satisfying

```
T_k = (-X_0 * inverse(D modulo 2^k)) mod 2^k.
```

This is the frozen oracle's closed form for k<=256; it has no iteration
loop or limb carry chain. For k>=256, X_0<N<=2^k implies

```
0 <= X_k < 1+D.
```

Thus integer X_k is at most D. Positivity gives `1<=X_k<=D` whenever
X_0>0 and M>0. In particular the first 256 ordinary passes bring every
unreduced positive input into this interval.

Also `2^k X_k = X_0 (mod D)`. For positive input, X_k is therefore the
unique representative in 1..D of

```
X_0 * 2^(-k) mod D.
```

The zero residue represents D, not zero. X_0=0 is handled separately and
stays zero. D=1 gives output one for all positive X once k>=256. For larger
odd D, inverse-of-two exists. This proves the frozen oracle's large-count
formula, including n=2^32 and all high-bit count encodings, without materializing
billions of iterations or huge `2^n` integers.

## Accelerated Rust and totality

Rust performs `min(n,256)` ordinary passes with bounded u128 limb addition
and a 257-bit shift. If no passes remain or the value is zero, that is final.
Otherwise M>0 and the current value is in 1..D. A value equal to D is fixed
and returned. This also closes D=1 before modular multiplication.

For D>1, `(D+1)/2` is inverse-of-two modulo D and lies below D. The source
forms it as `floor(D/2)+1`, avoiding a 256-bit overflow at D=N-1. Binary
exponentiation applies this inverse `n-256` more times using ordinary modular
multiplication. Each multiply uses add-and-double over at most 256 multiplier
bits. Its operands and accumulator are below D; adding any two is below 2D,
so one conditional subtraction gives the canonical residue. The helper retains
the possible 257th addition bit before choosing that subtraction. At most
32 exponent bits are processed, each with at most two modular multiplications.
All execution is bounded independently of the original billions of loop passes.

Each limb sum is at most `2B-1`, fitting u128. The borrow helper combines the
two overflowing-subtraction borrows. All bit shifts are fixed at 1,63,64 on
suitable widths; no shift reaches its type width. `checked_add(32)` validates
the image windows before loads/stores. No numeric input needs a refusal and no
unchecked Rust arithmetic overflows. This implementation uses only ordinary
new Rust code; it does not execute or interpret captured instructions.

## Independent final auxiliary-register proof

Let the final pass's full pre-shift sum be S, its four low words be s0..s3,
and its high carry be c. Let final V=floor(S/2), with words v0..v3.
The following observations depend only on V, including cases where the last
low bit of S was discarded:

- RAX is `(-c mod B)<<63`, so it is exactly v3's top bit. This follows from
  `c=1 iff S>=N iff V>=N/2`.
- RSI is `s3<<63`, so it is exactly v2's top bit, supplied from bit192 of S.
- R8 was shifted right without receiving the next word's low bit. RBP receives
  that combined low result before being restored; thus R8 is v0 with its
  highest bit cleared, not the complete stored v0.
- R9,R10,R11 are v1,v2,v3; RDX is zero after the final DEC EDX.

The reported tuple is therefore

```
(RAX,RDX,RSI,R8,R9,R10,R11)
= (v3 & 2^63, 0, v2 & 2^63, v0 mod 2^63, v1,v2,v3).
```

RDI/RCX retain the destination/correction addresses. RBX/RBP are restored;
R12..R15 are untouched. The value API does not return or fabricate those
unchanged pointer/entry-register values. Output stores use the complete v0,
not the partial R8 observation.

## Static closure

The full body, exact FDE/CIE and following NOP are rechecked against the full
target digest. Complete Capstone and independent GNU exports retain the only
back edge, every count/shift/carry operand and all loads/stores. No callee,
RIP-relative data/table operand or indirect transfer exists. Full `.text`
E8/E9/EB scans find no incoming candidate, and no one of the 80,300 RELA
records names this entry or writes its code/padding window. These absences
are not proof of unreachability or a complete whole-program xref census.
Caller constraints, source name, operand meaning and neighboring bodies remain
unknown; no node-wide ABI/build or progress gate is claimed.
