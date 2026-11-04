# Node #115 fee point classifier

This independently authored MIT component reconstructs the ordered numerical
classification of one supplied fee-calculation point. The library is
dependency-free, `no_std`, and forbids unsafe code. Its sole supported toolchain
for this contribution is the repository-pinned Rust 1.95.0; it is not a full
node implementation or a native-equivalence claim.

The target is Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The complete selected native kernel is `0x3876290..0x3876b72`. The reviewed
adapter `0x3ebfdb0..0x3ec0251` and overflow hook `0x4524e40..0x4524fb1` establish
construction and effect boundaries. Four previously audited construction
bodies are credited context, not new exclusive coverage. The native input is
never linked, loaded, executed, or used by the library or driver.

`classify(Point)` accepts quantity `1..=10,000,000`, one of the six exact
`SCALE_BITS`, and five supplied binary64 bit patterns `t`, `d`, `q`, `m`, `h`.
Those five fields accept every bit pattern, including subnormals, signed zeros,
infinities and NaNs. This value domain does not assert that every combination
is admitted by the higher validator. Quantity and scale refusals are a chosen
safe host policy, checked in that order, and are separate from classification.

Each floating-point operation is separate binary64 arithmetic. `T` maps all
nonfinite values to zero; otherwise it truncates toward zero with saturation
to `i64`. In the notation of the reviewed contract, the operation is:

1. Compute `A = T((((1-d)*t)*scale)*I(quantity))`, then `B = T(I(A)*q)`.
   A negative `B` selects `FirstProductNegative`.
2. Compute `D = T((m*scale)*I(quantity))`, then
   `S = saturating_add(saturating_sub(A,B),D)`.
   A negative `S` selects `NetAndBaseNegative`.
3. Compute `E = T((scale*h)*I(quantity))`, then `F = T(q*I(E))`.
   A negative `F` selects `SecondProductNegative`.
4. Compute the unsigned `V = F + max(E,0)`, then saturating unsigned
   `U = V + unsigned_abs(D)`. `U >= quantity` selects
   `RoundedMagnitudeAtLeastQuantity`; otherwise the result is `Pass`.

`I` is integer-to-binary64 rounding, including possible rounding of `A` and
`E`. Products retain the displayed order; the two signed saturations are
separate. `V` cannot overflow because both summands are at most `i64::MAX`.
Later stages are not computed after an earlier classification. These five
names are chosen observations, not a recovered native enum or ABI.

Correspondence is conditional on round-to-nearest, ties-to-even, masked
floating-point exceptions, and gradual underflow (DAZ=0, FTZ=0), with stable
valid inputs/frame contents. The component does not inspect or set FP control
state. It relies on the ordinary Rust binary64 operations and finite cast
semantics; compilation must preserve separate operations rather than enable
reassociation or contraction. FP flags and NaN payloads are not outputs.

Each reached native overflow hook must return normally and preserve live
inputs, stack/register values and FP controls. The source computes the proved
saturating value directly; it does not reproduce the hook's locks, diagnostics,
initialization, waiting, exceptions or effect trace. A finite `+2^63` native
conversion raises invalid before repair, so masked invalid remains a premise.
Plain Rust casts alone would map infinities differently; the explicit
nonfinite-to-zero gate is essential.

The result precedes formatting and the later shared-bound/CAS winner selection.
It says nothing about diagnostic bytes, financial units, returned native state,
cancellation, traversal of all points, the outer FMA checks, or native hook
completion. These remain separate obligations before whole-validator integration.

## Input-only driver

The standard-library binary `fee-point-driver` reads stdin only, with no
arguments, expected-output file, artifact access or network operation. Each
record has exactly these eight ASCII TSV fields:

`case_id`, `quantity`, `scale_bits`, `t_bits`, `d_bits`, `q_bits`, `m_bits`, `h_bits`.

IDs are unique nonempty `[A-Za-z0-9_-]+`. Quantity is canonical unsigned decimal
in the admitted range, without a sign or leading zero. Every bit field is
exactly 16 lowercase hexadecimal digits, with no prefix. Input must have a
final LF, contain 1 through 8,192 records, and be at most 2 MiB. CRLF, blank
rows, unsupported scales, duplicate IDs, extra fields and malformed encodings
are refused. These transport limits are host policy, not native parsing claims.

For admitted input it emits `case_id TAB ClassName LF` in input order. It buffers
the complete response until every record has been validated, so malformed
input emits no stdout; errors produce stderr and exit code 2. An output I/O
failure after writing starts can leave partial output. The library itself
performs no allocation or I/O.

Actual offline, locked Cargo metadata validated the one-package graph. Debug
and release each matched all 5,900 pre-source frozen expectations; ten compiled
semantic variants were detected in both profiles, and 26 release-driver
transport controls passed. The Linux x86-64 library-only build passed without
execution. See the [evidence packet](../../research/work-items/RE-004-node115-fee-point-classifier/README.md)
for exact receipts, preserved failures, reproduction commands and the unchanged
conditional native boundaries. These results do not establish full-node or
native runtime equivalence.
