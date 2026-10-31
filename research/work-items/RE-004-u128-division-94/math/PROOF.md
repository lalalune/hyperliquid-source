# Arithmetic argument for the node94 unsigned quotient

This narrows the original packet's open estimate/correction question. It gives
an all-input mathematical argument **conditional on the instruction-to-math
translation below**, with eight Z3-checked polynomial arithmetic queries. It
is not a machine-checked x86 semantics proof, an independently kernel-checked
solver proof object, native execution, source attribution or a component gate.
The Z3 executable and the existing native decoders remain trusted tools.
The value-result argument assumes valid stack/return state and ordinary
execution of the listed instructions; it does not cover arbitrary machine
state or establish memory safety.

The subject is still node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
FDE `[0x565f5a0,0x565f666)`, 198 bytes and71 instructions. Coordinates below
are ELF virtual addresses. The original GNU/LLVM listings and evaluator are
unchanged. No inferred reference source was consulted.

## Definitions and normalization

Let `M = 2^64`, `N = n_hi*M + n_lo`, `D = d_hi*M + d_lo`, with each limb
an unsigned integer in `[0,M-1]`. First suppose `d_hi > 0`. Define
`k = floor(log2(d_hi))`, `H = 2^k`, `B = 2H`,
`A = floor(D/B)`, `T = A*B`, and `delta = D-T`.

At `0x565f5a9`, BSR gives `k` in `[0,63]`. XOR with63 complements those
six bits, so the AL subtraction computes `k+1`. For `k < 63`, SHRD followed
by CMOVE selects `A`. For `k = 63`, the x86 shift count64 is masked to0,
the AL bit6 test prevents CMOVE, and R10 retains `d_hi = floor(D/M) = A`.
Only CL is read by the shifts; undefined higher bits of EAX do not enter
this arithmetic. This translation of the actual instructions is a review
obligation, not something the real-arithmetic solver verifies.

From `H <= d_hi <= 2H-1` and `0 <= d_lo <= M-1`:

```
M*H <= D <= 2*M*H-1
M/2 <= A <= M-1
T >= M*H
0 <= delta <= 2H-1
```

`normalization.smt2` checks the integer endpoint exclusions using a real
relaxation of the floor inequalities. In particular, A is an integer from
the shift; excluding `A <= M/2-1` establishes the integer lower bound.

At `0x565f5cf..0x565f5dd`, the SHLD/SHR pair forms `floor(N/2)` as the
hardware DIV numerator. Since it is below `M^2/2` and `A >= M/2`, this DIV
has a quotient below M: no quotient-overflow fault occurs. This implication
is checked in `normalized-div-safe.smt2`.

The subsequent shift by k gives the integer estimate

```
E = floor(floor(floor(N/2)/A)/H) = floor(N/T).
```

For the equality, write the successive division remainders as
`N=2*n1+r0`, `n1=A*b+r1`, `b=H*E+r2`, where
`0<=r0<=1`, `0<=r1<=A-1`, `0<=r2<=H-1`. Expansion gives
`N=T*E+R` with `R=2*A*r2+2*r1+r0`, hence `0<=R<=T-1`.
`floor-composition.smt2` checks that polynomial remainder bound.

## The estimate is at most one too large

Let `Q=floor(N/D)`. Since `0<T<=D`, `E>=Q`. The important upper bound is
strict and needs the original numerator range:

```
2H-1 <= H^2                    because (H-1)^2 >= 0
N*delta < M^2*H^2 <= T^2 <= T*D
N/T - N/D = N*delta/(T*D) < 1
```

The strict first product inequality also holds when delta is zero. It uses
`N<M^2`, `delta<=H^2`, `H>=1` and nonnegative quantities; it is not a
floating approximation. `estimate-error.smt2` checks its negation is
unsatisfiable over a real relaxation, covering every admissible integer.

Consequently `E` is either `Q` or `Q+1`. The two floor endpoint arguments
are checked in `estimate-not-below.smt2` and
`estimate-at-most-one-above.smt2`: an integer violation of the lower bound
would have `E+1<=Q`, and an integer violation of the upper bound would have
`E>=Q+2`. Neither real-relaxed constraint system is satisfiable.

The decrement and zero clamp at `0x565f5eb..0x565f5ef` therefore produce
`q0=max(E-1,0)` with `q0<=Q<=q0+1`. Both E and Q are below M because
`T>=M` and `D>=M`. This includes the zero-estimate clamp.

## Product, subtraction and final correction

`q0*D <= N < M^2`. Thus the product fits in128 bits. Also
`q0*d_hi < M`; `wide-product-safe.smt2` checks that implication. MUL's
low/high pair, IMUL's low word, and the high-word ADD at
`0x565f5f3..0x565f606` therefore form the complete product without losing
a significant high word. Signed IMUL and unsigned multiplication have the
same low64 product bits.

The SUB/SBB pair computes the nonnegative remainder `R=N-q0*D`, propagating
low-limb borrow. The next CMP/SBB sets CF exactly when `R<D`. The last
`SBB RAX,-1` returns `q0+1-CF` modulo M: q0 when R is too small, q0+1
otherwise. Since `Q` is q0 or q0+1, that is Q. A wrapping increment would
require `Q=M`, already excluded. RCX is zero and is moved into RDX, so the
high quotient limb is zero. RBX is restored by the paired PUSH/POP.

## One-limb divisor and zero divisor

For `d_hi=0` and `d_lo>0`, put `d=d_lo`. If `n_hi<d`, one64-bit DIV
computes Q directly with no overflow and a zero high quotient.

Otherwise the first DIV computes `n_hi=q_hi*d+r_hi` with `0<=r_hi<d`.
It uses32-bit DIV only when both n_hi and d fit in32 bits; otherwise it
uses64-bit DIV. Its numerator high word is zero. The second DIV computes
`r_hi*M+n_lo=q_lo*d+r_lo`. Since integers satisfy `r_hi<=d-1` and
`n_lo<=M-1`, its numerator is below d*M and its quotient fits in64 bits.
Expansion gives `N=(q_hi*M+q_lo)*d+r_lo`, so the returned pair is Q.
`limb-division.smt2` checks the expansion identity. The word bounds,
remainder bounds and mapping of the two DIV widths are explicit parts of
this mathematical/ISA argument, not a full solver encoding of the CPU.

If both divisor limbs are zero, the initial comparison always selects the
two-DIV branch, whose first DIV faults (32 or64 bits depending on n_hi).
No zero-divisor result is equated with the Rust constructor's rejection.

## Reproduce and limits

```sh
python3 research/work-items/RE-004-u128-division-94/math/verify.py \
  --output work/u128-math-fresh
```

The verifier authenticates the captured ELF as data, repeats both native
helper decodes, and checks all eight real-arithmetic queries with an existing
Z3 binary. It separately checks that every query's assumptions are
satisfiable. Three weakened-hypothesis controls remove the numerator range,
normalization lower bound or truncation remainder bound; the negated bound
then becomes satisfiable. These are mathematical controls, not claims about
executed ELF mutations. Original byte-mutation controls remain unchanged.

Finite instruction-evaluator checks cover the translation at each k boundary,
including k=63, the estimate clamp and both correction outcomes. Those checks
are not the universal arithmetic proof. Exact query/decoder/source hashes,
tool versions and raw solver output are retained by the runner. A timeout,
unknown, unexpected answer or binding mismatch is a non-pass.

The eight queries prove their stated mathematical implications assuming Z3's
correctness. The target-wide argument additionally relies on the manually
reviewed word/flag/shift translation above and ordinary x86 integer semantics;
there is no verified decoder, formal ISA model, checked solver proof object,
historical compiler/source attribution, native replay, caller reachability
proof or whole-node/gate claim. Existing Rust behavior and artifacts are
unchanged. This is more than a finite-vector estimate observation, while
the remaining machine-proof boundary stays explicit.
