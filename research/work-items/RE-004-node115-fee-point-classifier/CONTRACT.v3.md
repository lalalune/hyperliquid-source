# Node115 fee point classification: bounded static contract v3

Status: the numerical relation is specified for independent review. No source,
model, corpus, build, native execution, or source-admission decision is supplied
by this document. The whole 0x36a58d0 helper and its parallel traversal are not
closed. This is a selected value projection of one complete nested operation,
not a claim that the native function returns this new enumeration.

## Evidence and complete bodies

Target: node115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Three new complete GNU/FDE bodies were read and raw-byte audited (3,828 bytes,
787 instruction rows). No instruction was executed or evaluated.

| Complete extent, exclusive end | Bytes / rows | Raw body SHA-256 |
|---|---:|---|
| 0x3ebfdb0..0x3ec0251 | 1,185 / 242 | c6d861e3db26dba1f8efa30445c1db42d162010f89e2e33e5b83a93307b089f7 |
| 0x3876290..0x3876b72 | 2,274 / 462 | 0798c099a35ffc2ba9496455d822825a8e997b977119af5c444ba6a4bc0cfbe8 |
| 0x4524e40..0x4524fb1 | 369 / 83 | 757524c681b8370fb31aede37a22db604ac1ba162ca15b9160a58647d4707b14 |

`static-byte-audit.json` binds every decoded row to PT_LOAD bytes, the actual
FDE/CIE records, all direct/indirect calls and RIP references. Complete raw GNU
outputs and exact argv/environment/tool identities are retained. The 72 entries
in the immutable v2 manifest were rehashed successfully. Its existing outer
helper, scale traversal, release, TLS, and FMA exports remain dependency evidence;
this continuation does not claim them as newly recovered exclusive work.

## Bounded inputs and native construction

Let C be the closure pointer loaded from `[RSI+0x40]` at 0x38762a4. The numerical
inputs are five binary64 values read through pointer fields:

| Field | Value symbol | Kernel observation |
|---|---|---|
| C+0x00 | t | Pointer dereferenced for the first product, 0x38762c5/62dd |
| C+0x08 | d | Pointer dereferenced by SUBSD, 0x38762cd/62d9 |
| C+0x10 | q | Read at 0x387638b..6393, saved and reused at 0x387661b |
| C+0x20 | m | Read at 0x3876409..640d |
| C+0x28 | h | Read at 0x3876575..6582 |

C+0x18 is passed into diagnostic formatting and is not used by this numerical
relation. It is not a sixth numeric input. All prior accumulator, shared-bound,
and direction fields affect the later winner/state operation, not the four
numerical branch conditions under the noninterference premises below.

The bounded quantity n is an integer in 1..=10,000,000. The scale s is one of
these six *exact* binary64 encodings in the observed array order:

| Display | Bits |
|---:|---|
| 1 | 0x3ff0000000000000 |
| 0.2 | 0x3fc999999999999a |
| 6 | 0x4018000000000000 |
| 0.1 | 0x3fb999999999999a |
| 2 | 0x4000000000000000 |
| 40 | 0x4044000000000000 |

The 48 bytes at 0x79d4d0..0x79d500 have SHA-256
`f29ac9e2b5ea4086a55976e6dc4ac146e3dd657305cd497fa8f23bd5515934a9`.
The outer body copies them at 0x36a5c24..5c4a; 0x457cbf0 constructs a six-element
traversal. The previously audited 0x41c8750 initializes start=1, end=0x989680,
exhausted=0. 0x41cac80..0x41cad4c forms end+1-start=10,000,000 and passes offsets
[0,10,000,000). At 0x3ebfe8d..0x3ebfefa the serial arm calls this kernel with
n=base+offset and s loaded from the selected scale. This establishes the
construction, not execution of all 60,000,000 pairs: cancellation, splitting,
error selection, and runtime progress remain separate obligations.

For the proposed value projection, t,d,q,m,h may each be any binary64 bit
pattern, including signed zeros, subnormals, infinities, and NaNs. This is the
raw numerical operation's explicit value domain, not a claim that all such
values reach it from the higher validator. The v2 root derives t/h from the
last/first third-vector element or fallback, m from the first two vector
last/fallback values, d from record+0x28, q from record+0x38. Those extraction
rules and the outer minimum/FMA checks are not silently folded into this API.
No later caller fee bounds are adopted as preconditions. Quantities or scales
outside the stated bounded construction are outside this proposed contract;
any future host refusal there must be labeled host policy, not native failure.

## Floating-point and conversion premises

The relation below uses binary64 operations rounded separately to nearest,
ties to even, gradual underflow (DAZ=0, FTZ=0), and masked floating-point
exceptions. These are explicit correspondence premises, not observed native
MXCSR initialization. Neither the target nor a native runtime was executed.
Status flags, NaN payloads, exception traces, and floating-point environment
mutation are not projected outputs. All live inputs/frame contents remain valid
and unmodified while this numerical portion runs.

Write M(x,y) for one separately rounded MULSD, Sub(x,y) for one separately
rounded SUBSD, and I(k) for signed-i64-to-binary64 conversion with the same
rounding mode. I(n) is exact for this quantity domain; I(A) and I(E) need not be.
Operand order is preserved below. There is no inner FMA, no reassociation, and
no mathematical-real-number substitution for these rounded operations.

All five conversion copies implement T(x): if x is nonfinite, return 0;
otherwise truncate toward zero after saturation to the i64 range. More
explicitly, finite x<=-2^63 maps to i64::MIN, finite x>=2^63 maps to i64::MAX,
and the remaining finite x maps to its toward-zero integer. This follows from:

1. `(bits(x) & 0x7fffffffffffffff) > 0x7fefffffffffffff` bypasses to +0.
2. The finite value is clamped to [-2^63,+2^63] using the ordered comparisons
   and MINSD/MAXSD paths.
3. CVTTSD2SI converts toward zero. A later comparison with 2^63-1024 changes
   the +2^63 case to i64::MAX; CMOVNP guards the ordered result.

The exact constants are 0x459808=`0xc3e0000000000000` (-2^63),
0x459360=`0x43e0000000000000` (+2^63), and
0x458e50=`0x43dfffffffffffff` (2^63-1024). They were read from authenticated
file bytes, not inferred from labels. Crucially, at finite +2^63 the hardware
CVTTSD2SI raises invalid *before* CMOVA installs i64::MAX. Masked invalid is
therefore necessary even for finite inputs. Signaling NaNs or intermediate
invalid/overflow/underflow cases also need the stated exception premises.

The copies are A:0x387630b..637a; B:0x38763a8..63fb;
D:0x3876423..645c plus 0x387651c..654b;
E:0x387658f..6607; F:0x3876628..668f. Nonfinite conversion to zero is not a
license to ignore the preceding arithmetic or its possible exceptions.

## Complete ordered numerical relation

The following is a mathematical specification, not executable model code.
`SatSub` and `SatAdd` mean signed i64 saturating subtraction/addition;
`USatAdd` means unsigned u64 saturating addition. `AbsU` maps i64::MIN to
2^63 and otherwise gives the nonnegative magnitude in u64. Names below are
chosen source classifications, not recovered native type or enum names.

1. Compute A = T(M(M(M(Sub(1,d),t),s),I(n))).
   Then B = T(M(I(A),q)). If B<0, classify **FirstProductNegative** and stop.
2. Compute D = T(M(M(m,s),I(n))).
   Compute X = SatSub(A,B), then S = SatAdd(X,D).
   If S<0, classify **NetAndBaseNegative** and stop.
3. Compute E = T(M(M(s,h),I(n))).
   Then F = T(M(q,I(E))). If F<0, classify **SecondProductNegative** and stop.
4. Let V = unsigned(F) + unsigned(max(E,0)). This first unsigned sum cannot
   overflow: both operands are at most i64::MAX, so V<=2^64-2.
   Let U = USatAdd(V,AbsU(D)). If U>=n (unsigned comparison), classify
   **RoundedMagnitudeAtLeastQuantity**; otherwise classify **Pass**.

This covers every admitted input bit pattern under the explicit FP and
ordinary-overflow-hook premises. It does not return an answer by supplying an
unknown callback result. Every numeric operand and arithmetic operation is
visible in the complete kernel body; the overflow helper's numeric return
registers are ignored and the saturating fallback is recomputed inline.

| Priority | Deciding observation | Entry to diagnostic path | Raw candidate tag after ordinary formatting |
|---:|---|---|---:|
| 1 | B sign, 0x38763ff..6402 | 0x3876461 | 0 |
| 2 | S sign, 0x3876567..656a (or fallback 0x3876818..681b) | 0x3876821 | 1 |
| 3 | F sign, 0x3876693..6696 | 0x38766fd | 0 |
| 4 | U>=n, 0x38766ba..66c2 (or fallback 0x3876904..690c) | 0x3876912 | 1 |
| pass | U<n after all earlier checks | 0x38766c8 | No fresh tag; prior 72-byte state is copied |

The early ordering matters: D is not needed after condition1, E/F are not
needed after condition2, and condition4 is not reached after condition3.
The signed S result and the later unsigned U bound are distinct tests.
Rounding negatives toward zero differs from floor. T(nonfinite)=0 differs
from Rust's plain float-as-integer behavior for infinities and therefore
must not be lost in any later implementation proposal.

## Overflow hook boundary, not a value oracle

Signed subtraction overflow at 0x3876552 branches to 0x38767b4 and calls
slot0x64e4ea8 at 0x38767bd. On ordinary return the body recomputes A-B and
uses wrapped-sign/SF plus CMOVO to select the signed saturation endpoint.
Signed addition overflow at 0x387655e (also 0x38767e5) calls the same slot at
0x38767f7, then uses the wrapped-sign XOR i64::MIN construction and CMOVO.
Unsigned overflow at 0x38766b1 calls the slot at 0x38768f0 and recomputes the
sum, retaining u64::MAX on carry. Since n<=10,000,000, that saturated unsigned
value necessarily reaches the fourth rejection, provided the hook returns.

The slot has R_X86_64_RELATIVE addend0x4524e40. Its complete body reads
0x64fdb28, acquires/releases global state0x64fdb00, passes a 20-byte metadata
copy plus a byte argument to0x3cded00, and contains initialization, wait,
unlock, and unwind paths. The original caller supplies EDI=0 and metadata
0x646e930 (signed operations) or0x646e948 (unsigned operation). This is not
proved to be an effect-free logger, and its normal return is not guaranteed.

The conditional numerical theorem therefore requires each reached hook to
return normally, preserve callee-saved registers/live stack and input values,
and leave the chosen FP control state unchanged. These premises also exclude
unwinding, termination, deadlock, races corrupting inputs, or an inaccessible
frame. They supply *no numeric answer*. A future pure source projection may
compute saturation directly, while its documentation must retain the native
hook boundary and must not claim an equivalent effect trace or completion
when the native hook fails to return.

## What the selected projection deliberately does not establish

After a rejection branch, four calls through slot0x64df6e8→0x141e3a0 construct
diagnostics using callback pointers0x41ca900/400/580/600. Those bodies and their
allocation/string semantics are not closed here. The raw data spans displayed
in selected-data.json are opaque formatting arguments; their adjacency does
not prove the complete displayed diagnostic text. No diagnostic bytes or
allocation behavior are projected. To relate a branch classification to a
materialized native candidate additionally requires ordinary formatting return
and noninterference, but branch classification itself precedes that call.

At 0x38769e7..0x3876b22, old state, a direction flag, shared bound, atomic
compare-exchange and release requests determine whether this candidate or the
old state is returned. In particular a numeric rejection need not become the
returned candidate. The pass path copies exactly72 bytes at0x38766c8..66f5.
The native full function also has a negative-RDX failure path at0x3876b38,
a UD2 after its failure call, and unwind/drop routing. The chosen n domain
excludes the negative path; it does not prove that path's termination.

The 0x3ebfdb0 adapter can return tag2 immediately on cancellation, stop the
serial loop based on a selected rejection/shared bound, or call the unclosed
split adapter0x3b91980. Thus we do not equate root tag2 with the conjunction of
all 60,000,000 point classifications. Proving that conjunction/result/winner
relation requires the remaining scheduler and cancellation semantics. The
outer twelve comparisons additionally retain the separate v2 FMA dispatch and
FP-environment obligations. None is bypassed by this proposed pure component.

## Admission assessment and remaining gates

A complete, useful *point classification* relation is available for independent
review: five selected scalar inputs, one of six scales, one quantity, five
conversion blocks, three overflow continuations and all four rejecting branches.
It resolves a substantive part of the node115 validator rather than exposing a
single floor/saturation primitive. The natural future consumer is the existing
fee-schedule validator; integration must wait for an honest traversal contract.

Recommendation: permit independent review of this exact bounded contract, then
consider a pre-code gate only if the FP/noninterference premises and ownership
are accepted. **No source/model/corpus admission now.** Whole-helper replacement,
parallel iterator reproduction, selected diagnostic bytes/winner, native ABI,
and runtime/native-equivalence claims remain **not admitted**. Fresh ownership
is the parent's responsibility before selection/publication. This receipt adds
zero search queries; parent cumulative searches201 supersedes historical v2's200.

## EXPAND

Next useful questions are independent verification of the five conversion
copies/three saturating fallback blocks, current ownership of0x3876290 and its
point-classification scope, and whether a consumer needs precisely this bounded
value operation. Whole-helper work would additionally require the retained
0x3b91980/TLS/scheduler frontier and the outer FMA proof. No additional exports
are justified merely to exhaust the cap: three bodies/3,828 bytes were enough
to expose the numeric kernel and its explicit opaque effect boundary.
