# Complete thirty-step pair and matrix transform

The target is node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The claim is the complete numeric behavior of ELF VA
`[0x565f2e0,0x565f390)`, not a caller algorithm, GCD/Jacobi symbol, source
function identity or physical ABI. All input triples of u64 entry bits in
R8, R9 and RBP are admitted, including zero, even second values and high bits.

## Closure and observations

The actual FDE at `0xfbda14` describes the complete 176-byte body, including
`repz ret` at `0x565f38e`. Sixteen alignment bytes follow separately. There
is no data-memory access, call or RIP-relative data reference. The only branch
is `JNE 0x565f301` at `0x565f370`, following a decrement from an initial count
of 30. The body always terminates after exactly thirty iterations.

Full bytes, actual FDE/CIE records and linkage, GNU/Capstone decoding and
padding are locked. All RELA records are scanned; none names or overlaps this
body. Full `.text` E8/E9/EB pattern scans find only the short tail jump at
`0x565f2d5`, instruction-qualified in the complete preparation FDE
`[0x565f220,0x565f2d9)`. That incoming helper's behavior is not reconstructed;
its nonstandard register setup does not restrict this core's full-u64 value
API. Register-indirect and other pointer paths are not a complete xref census.
The six-word product helper and following 48-step loop are outside scope.

The target writes fourteen general-purpose registers. RSI is never read or
written; RSP is used only by RET. The API returns all fourteen written values
but does not promise a Rust/native calling convention, flags, stack/return
storage, timing or fault behavior. Ordinary unchanged code and valid return
control are premises of correspondence to an actual target call.

## Exact scalar transition

Let a,b,p be the current R8,R9,RBP unsigned values. The comparison at
`0x565f30a` is unsigned. MOV and LEA preserve its flags until the conditional
swaps. The TEST at `0x565f33d` uses **the original a** saved in R10, so a
speculative swap/subtraction is wholly canceled when that original a is even.
Consequently the observable pair/accumulator step is:

| Condition on original values | New first | New second | Extra accumulator term |
| --- | --- | --- | --- |
| a even | floor(a/2) | b | 0 |
| a odd, a>=b | floor((a-b)/2) | b | 0 |
| a odd, a<b | floor((b-a)/2) | a | floor((a AND b)/2) |

All subtractions in the selected rule are larger-minus-smaller. Each resulting
first and second value is still in `0..=2^64-1`. The instruction's even-path
restoration also restores the original packed rows and original p; a candidate
swap accumulator term must not leak into that path.

After selecting the new second value B, every step additionally adds

```
q(B) = floor(((B+2) mod 2^64)/4).
```

The addition by 2 is a full-width LEA and wraps before the logical shift. This
is not unbounded `(B+2)/4`. Equivalently, with `B=4h+r`, `0<=r<4`,
`q(B)=(h+[r>=2]) mod 2^62`. This quotient/remainder identity is the oracle's
independent implementation of the increment. p is the old p plus the selected
extra term and q(B), modulo 2^64. Its complete value is observable, not just
its low parity bit. For a=0,b=2^64-1, the extra term and q(B) are zero at all
thirty steps; widening B+2 would instead add 2^62 each time and change final
p by 2^63 modulo 2^64.

## Unpacked coefficient matrix

Let M start as the 2x2 identity. A step multiplies it on the left by one of
three integer matrices, chosen using the same original a,b conditions:

```
a even:       T = [[ 1, 0], [0, 2]]
a odd, a>=b:  T = [[ 1,-1], [0, 2]]
a odd, a<b:   T = [[-1, 1], [2, 0]]
M_next = T * M.
```

The pair transition is independently `floor(T*[a,b]/2)` componentwise.
The second component is always an exact half; the first may require a floor.
For arbitrary even b, it would be incorrect to infer a single exact relation
`final_pair=M_final*initial_pair/2^30` while ignoring intermediate floors.
This proof instead preserves each scalar transition and each matrix transition
separately. It makes no gcd, coprimality, odd-modulus or parity-symbol claim.

A matrix row's sum of coefficient magnitudes is at most 2^k after k steps.
Initially it is 1. On an even step the first row stays unchanged and the
second doubles. On an odd step the first is a difference of two prior rows
(possibly after swapping), whose magnitude sum is at most 2^(k+1), and the
second is twice a prior row. Thus every coefficient after at most thirty
steps is in `[-2^30,2^30]`. Signed i64 addition, subtraction and doubling in
Rust are consequently safe. The matrix determinant's magnitude doubles each
step (each T has determinant ±2); this is consistent with the nonzero
coefficient rows, but is not a claim about caller number theory.

## Why the packed arithmetic yields those coefficients

Put K=2^31-1 and C=K+2^32*K=`0x7fffffff7fffffff`. Encode row (u,v) as

```
E(u,v) = (K+u) + 2^32*(K+v).
```

The target initializes RBX=`0x7fffffff80000000`=E(1,0),
RCX=`0x800000007fffffff`=E(0,1), and R15=C by subtracting one from RBX.
The coefficient bound proves that both biased fields remain in
`[2^30-1,3*2^30-1]`, strictly inside the unsigned 32-bit interval. Hence each
packed value uniquely represents two independent coefficients.

The target's swap exchanges the two encoded rows. Its SUB/ADD sequence
computes `E(row0)-E(row1)+C`, congruent modulo 2^64 to `E(row0-row1)`.
Its double/subtract sequence computes `2*E(row1)-C`, congruent to
`E(2*row1)`. Because every resulting biased field fits 32 bits, these modular
identities yield the exact encoded rows even when intermediate 64-bit
operations wrap. There is no unmodeled cross-field carry or borrow. This
establishes the T transitions above without treating packed subtraction as
independent 32-bit instructions or executing a captured instruction model.

The final SHR R15,32 gives K. MOV EBX,EAX and MOV ECX,EDX zero-extend the
low fields; SHR RBX,32 and SHR RCX,32 extract the high fields. Subtracting K
is then **64-bit**, giving signed coefficients represented modulo 2^64.
A negative coefficient must therefore return with high 32 bits set, not as a
zero-extended u32. Rust's bounded signed coefficient cast to u64 matches it.

## Every written value register at return

Let M30 be the matrix after thirty steps and a30,b30,p30 the final scalar
state. Let a29,b29,p29 and M29 be their values before the last iteration.
The snapshots come from the unconditional MOVs at `0x565f30d..0x565f31d`;
CMOV restoration reads them but does not change their saved values.

| Register | Result |
| --- | --- |
| RAX | M30[0][0] mod 2^64 |
| RBX | M30[0][1] mod 2^64 |
| RCX | M30[1][1] mod 2^64 |
| RDX | M30[1][0] mod 2^64 |
| RBP | p30 |
| RDI | 0, after the final 32-bit decrement |
| R8, R9 | a30, b30 |
| R10, R11 | a29, b29 |
| R12, R13 | E(M29[0]), E(M29[1]) |
| R14 | p29 |
| R15 | K |

Apart from R8, R9 and RBP, entry values of written registers are irrelevant:
they are replaced before being read. No input pointer or memory image is
required for this core. The function writes condition codes, which the safe
API explicitly does not return. RSI and normal stack/RET effects are not
reconstructed as new numeric inputs.

## Independent oracle and Rust

The oracle, full static facts, inputs and expected outputs were frozen and
hash-bound before either Rust file existed. It uses general 2x2 matrix
multiplication and componentwise floor on an integer vector. It accumulates
all p increments as an unbounded integer and reduces only when recording a
snapshot/final output. This is valid because branch choices depend only on
a,b and additions commute with reduction modulo 2^64. Its quotient/remainder
formula handles q(B)'s separate inner wrap.

Rust instead updates two signed rows directly, uses unsigned scalar
swap/subtract/shift, wraps each accumulator addition and uses wrapping B+2.
It reconstructs only the required final packed snapshots. No captured bytes,
assembly, external arithmetic library, unsafe code or instruction interpreter
implements the function. The input-only native client has no expectations.

Array indices are fixed in 0..2. All shifts use constant valid widths.
Unsigned subtraction follows a larger-first swap; coefficients fit i64 by
the row bound; biased fields fit u32 before conversion; accumulator wrapping
is explicit. The fixed 30 iterations have no early exit or counter overflow.
There is no admitted panic or undefined arithmetic. These arguments cover
all 2^192 input triples, while native fixtures provide finite qualification.
Neither proof nor native results establish original machine-code identity,
source provenance, full caller semantics or whole-node equivalence.
