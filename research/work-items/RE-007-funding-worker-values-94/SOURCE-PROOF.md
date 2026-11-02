# Supplied-state Rust implementation argument

This document is a later, separate phase. `STATIC-FREEZE.json` and
`pre-rust/PRE-RUST-FREEZE.json` preserve the native proof, contract, independent
oracle and all expectations from before this source existed. The coordinator
passed the pre-source gate before authoring this component. This source proof
does not alter that evidence or claim a build result before compilation.

## Exact integer implementation of the selected floating relation

`funding_amount` implements only the two roundings and subsequent classification
in `PROOF.md`, under its native correspondence premises. The Rust library uses
no host floating-point arithmetic, unsafe code, foreign calls or instruction
evaluation. The independent pre-source oracle instead uses exact `Fraction`
values and a binary search over adjacent representable binary64 magnitudes.

For a nonnegative integer significand `m` and power `p`, `rounded_bits` rounds
`m * 2^p` to binary64, nearest with ties to even. Zero returns the supplied sign
bit. Otherwise let `t = floor(log2(m)) + p` and `q = max(t - 52, -1074)`.
`2^q` is the spacing at this value, with the fixed subnormal spacing respected.
If `s = q-p` is positive, quotient/remainder division by `2^s` identifies the
lower neighbor and the exact halfway case. Incrementing precisely above halfway
or at halfway with an odd quotient chooses nearest-even. If `s>128`, a `u128`
magnitude is strictly below halfway, so zero is correct. For `s==128`, exactly
`2^127` ties with zero and rounds to zero; larger magnitudes round to one.
If `s<=0`, left shift is exact and at most 52 bits: the spacing definition gives
`s >= bit_length(m)-53`. Therefore the result uses at most 53 bits, or a
54th-bit carry which is exactly a power of two and normalizes without losing a
nonzero bit. A nonzero result below exponent -1022 retains the fixed `2^-1074`
quantum; the first normal value and a subnormal rounding up into it are encoded
correctly. A rounded exponent above 1023 becomes infinity. At the top finite
binade, the exact overflow midpoint increments the odd last finite significand
to the even carried value, giving infinity. No saturation to maximum finite is
substituted for that rounding.

The first call supplies the unsigned magnitude of an `i64`, including `2^63`
for `i64::MIN`, with power zero. `finite_parts` represents a normal raw binary64
as its 53-bit significand times `2^(encoded_exponent-1075)` and a subnormal as
its fraction times `2^-1074`. The finite integer conversion is then multiplied
by the finite raw rate: the exact product of the two significands is strictly
less than `2^106`, and all powers and shifts fit the `i32` arithmetic used here.
The second `rounded_bits` call therefore rounds the exact product of the first
rounded integer and raw rate, not the unrounded integer product. Signed zero is
retained internally by XOR of signs; integer zero has positive sign.

A nonfinite input rate always leads to a nonfinite native multiply (including
zero times infinity) and the native nonfinite guard returns amount zero. The
Rust shortcut has the same amount, with the untouched raw rate separately
retained in the row. A finite-rate multiplication that rounds to infinity also
returns zero. For a finite result, magnitude bits are monotonically ordered;
comparison with `0x43e0000000000000` classifies magnitude at least `2^63`.
Positive values in that class clamp to `i64::MAX`; negative values produce the
minimum-amount refusal. Below this boundary, shifting the finite significand
toward the integer point truncates toward zero and cannot exceed `i64::MAX`.
No shift reaches 128 in that conversion: very small values take the explicit
zero branch. Applying the sign is then safe. This preserves the distinction
between nonfinite amount zero and a finite value clamped to `i64::MIN`.

This is an abstract bit-value correspondence, not a claim about actual caller
MXCSR state. The native theorem still requires `(MXCSR & 0xffc0)==0x1f80`,
including nearest-even, DAZ/FTZ disabled and masked exceptions, plus preservation
across its returning helpers. Signaling NaN exception flags and NaN result
payloads are not API outputs. The original rate payload is an API output and is
copied bit for bit, including signaling NaNs and signed values.

## State and ordered request relation

`funding_worker` takes immutable explicit input state. Eligibility precedes all
position checks. A `BTreeMap<u64, Position>` supplies the strictly ascending
unsigned traversal established for valid native trees in `PROOF.md`; it does
not assert native tree shape, allocation behavior or pointer layout.

For each position, missing rates and either signed zero skip before metadata
indexing. The full unsigned asset modulo 10000 selects metadata. Bounds refusal
precedes the zero-size skip, which precedes negative-metadata and checked-product
refusals. The amount computation and minimum-amount refusal precede the raw
first-four-time-bytes zero gate. These match the frozen guard order. No calendar
or public funding policy is inferred from the time bytes.

Only tag exactly equal to the full `u32` value one selects the local balance;
all other tags select the shared balance. `checked_sub` or `checked_add` detects
the exact signed overflow condition before the corresponding saturating value
is assigned. Each detected overflow appends its request first. The three
accumulators are processed in their fixed coordinate order, and positions stay
in unsigned key order. This is an ordered value trace of diagnostic requests,
not execution or guaranteed delivery of native diagnostic helpers. Asset
attribution and field identifiers are value-level audit coordinates, not claims
of extra native call arguments.

The successful row has all 72 bytes defined by `pre-rust/PROTOCOL.md`: asset,
negative amount, original size, unmodified raw rate, signed product, address and
raw time. Negation is safe because the refused amount is the only value whose
negation would overflow. Summary saturation folds rows in their established
order. Its request records follow every position request, matching the native
post-traversal pass. Comparing unsigned product magnitudes with strict `>`
preserves the first maximum, including magnitude `2^63`; size is not used for
this comparison. The zero-row summary has sum zero and no candidate.

Native correspondence remains conditional on the static proof's valid finite
tree/count/alias premises and exact normal-return allocator, copy and frame
contracts. Rust collections must also have sufficient finite successful
storage. A Rust refusal is safe supplied-state validation; it does not reproduce
native panic behavior, prior side effects on native failure, allocation failure,
or rollback. The immutable input is preserved by the API and is not evidence
that native failure rolls back. Full settlement, scheduler coverage and economic
units remain outside scope.

## Source, driver and qualification boundary

The real crate has five files: manifest, Cargo-generated lock, README, library
and eight integration tests. There are no dependencies, build scripts, proc
macros, network clients, FFI or unsafe blocks. `LOCK-GENERATION.json` records the
actual offline lock generation in a fresh audited copy; that step did not compile
Rust. `SOURCE-FREEZE.json` pins the real files and the separate input-only driver
and build harness before compilation.

`driver.rs` accepts no arguments or expected-file paths. It reads only framed
stdin, bounds counts by remaining payload bytes, rejects duplicate/out-of-order
map keys and duplicate IDs, requires complete consumption of each input payload,
calls the real library, and serializes the returned values. It does not inspect
case IDs to select behavior. An invalid frame exits two; prior complete frames
may already have been emitted, so parser failure is not an output rollback
contract. Empty input is a valid empty stream.

`build.py` admits all chronological freezes, actual source bytes, the five-file
graph, the real dependency-free lock, and all 97 pinned toolchain `bin`/`lib`
payload files before compilation. It uses a fresh canonical direct child of
`/tmp`, a fresh `CARGO_HOME`, an allowlisted environment, no inherited Cargo
flags/config, and absent canonical ancestor Cargo configuration. Both component
copies have an identical relative layout and explicit canonical path remapping.
Cargo metadata must report exactly the library and integration-test target with
no dependencies. Source copies, harness identities, toolchain payloads and
selected linker/SDK bytes are checked again after the run.

Qualification invokes the real offline locked crate in debug and release, its
eight integration tests, Clippy, and a driver linked to the actual resulting
rlib. Whole raw output is compared with the 10,945 frozen input/output frames,
including frame identity/order/length. A second fresh directory rebuilds both
profiles from the same source. Raw rlib and client identities are reported as
observed, with no masks or normalization and no promise of universal toolchain
reproducibility. Host OS/dyld and the whole SDK are not hermetically pinned.

Eight comparator corruptions and six malformed-client inputs plus valid empty
input qualify framing. Sixteen explicitly recorded source mutations test signed
zero, full tag, modulo, raw time/rate, product maximum and first ties, the two
nonfinite paths, ties-even and initial integer rounding, summary saturation,
request order, negative metadata, guard order and finite minimum refusal. Each
must actually compile, execute successfully, emit all cases, and disagree with
the frozen outputs; compile failure or an abort is not a killed value mutant.
Every invoked command's stdout/stderr is retained as content-addressed gzip.
These are authored Rust value executions only, never captured native execution.
