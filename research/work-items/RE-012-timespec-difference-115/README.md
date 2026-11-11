# RE-012: reconstruct node #115 complete normalized two-input timespec difference

Target Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Foundation utility under
RE-012 startup/helper scope. New Rust/scripts/docs independently authored MIT.
No unlicensed inferred source, copied original machine code or captured execution.

## Gap and full bounded result

The previous time-producer contribution implements nonnegative clock reads
against a zero origin; it retains this helper only as context. That leaves the
complete normalized **two-input** operation unimplemented: negative timestamps,
reverse direction, same-second nanos ordering, borrowing, and differences whose
seconds magnitude exceeds i64MAX. This contribution implements that whole
primitive in real no_std Rust, reusing licensed `core::time::Duration`.
It does not republish zero-origin behavior as a new discovery.

The existing std census identifies the198-byte FDE
`0x5c84210..0x5c842d6` as the shared Unix Timespec::sub_timespec routine. Its
existing target/source bodies differ in raw bytes; this PR neither reruns nor
extends compiled-window equality claims. The new logical kernel is independently
authored and allocates no new private-node byte credit. Standard-library
provenance and use of core Duration are explicit, rather than an invented
private implementation or Cargo dependency. All gates/counts remain unchanged.

## Complete static evidence and selected real consumer

`scope.json`/`records.json` bind the full subtraction FDE198 bytes, one real
nonzero-origin consumer `0x14fbc70..0x14fbd5f`239 bytes, and clock wrapper
`0x5c842e0..0x5c843a9`201 bytes: total638 bytes/169 Capstone instructions.
Primary function and contexts are labelled separately. Full FDE/CIE records,
original instruction bytes, actual calls/branches and relative/dynamic
relocation writers are retained; GNU readelf independently checks extents.
Ten real instruction/data anchors reject individual corruptions below artifact
hash checking, plus wrong/truncated capture controls. No operands or bytes are
masked, and no whole-ELF caller census is claimed.

The selected consumer passes clock id1 to the real clock wrapper, copies its
other timestamp from object+0x38/+0x40, and calls this subtraction at
`0x14fbcae`. It reads the returned duration magnitude as a u128 nanosecond
quantity and clamps a nonzero direction tag to zero before its selected atomic
store attempt. These are actual nonzero-origin data and result-reader
observations; the caller's other atomic/wake/reference behavior is not
implemented or counted as newly closed.

Initial collection failed strict LLVM instruction-row equality: LLVM prints
five `lock` prefixes as standalone f0 rows while GNU/Capstone include the prefix
in the following instruction. The packet-local collector was the active static
qualification blocker. Its only correction joins an f0 row with its immediately
contiguous next row, then requires exact address and byte equality to the
Capstone partition. Sites are recorded in
`llvm_standalone_lock_prefixes_joined`: 0x14fbce1, 0x14fbcf7, 0x14fbd14,
0x14fbd26, 0x14fbd42. Original raw LLVM exports are retained unchanged.
This is disassembler presentation joining, not opcode replacement, a byte mask,
a global-tooling change or a compiled match. Original failure stderr is retained
under ignored work. Final native qualification passes with that explicit label.

## Observed ordering, arithmetic and direction

The helper compares signed seconds. On equal seconds it compares nanoseconds
unsigned. For self>=other, it computes a nonnegative duration. Without a nanos
borrow, the seconds magnitude is the full unsigned representation of the
signed-second difference, and nanos are subtracted directly. With a borrow,
seconds decrease by one and nanos become self_ns+1e9-other_ns. This cannot be
implemented using a checked i64 subtraction: e.g. i64MAX minus i64MIN has
u64MAX seconds magnitude.

For self<other, it recursively computes the reverse duration then XORs the first
sixteen result bytes with the actual mask at `0x453aa0`:
`01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00`.
Only the result direction tag flips; the magnitude does not become negative.
Normal positive output stores tag0, seconds at+8 and nanos at+16; negative
has tag1. Rust represents this logically with Result<Duration,Duration>, not
as a recovered native enum ABI. Equality returns positive zero, not Err zero.

The native additional-normalization/overflow edge is retained. For canonical
inputs ns<1e9 it is unreachable: after an ordered borrow the seconds differ
by at least one and adjusted nanos lie in[1,1e9-1]; without borrow they lie
in[0,1e9-1]. Across the entire i64 timestamp range, maximum nanosecond distance
is `(u64MAX*1e9)+(1e9-1)`, exactly the normalized core Duration range.
`derive.py` checks that whole-domain bound and the actual XOR mask. These are
mathematical proofs, not a captured-code instruction evaluator. Raw-invalid
nanosecond representations can reach other paths and remain outside this API.

## Independent Rust and frozen qualification

Private Timestamp fields enforce the selected normalized input domain. Safe
constructor refusal is wrapper behavior, not a claim about native invalid-input
panic payloads. Rust orders the logical fields, uses core i64::abs_diff to avoid
signed overflow, and performs explicit nanos borrowing. It has no clock, TLS,
allocation or external callback. Its manifest/lockfile has no external packages
or build hooks; core Duration is a real compiler-provided licensed dependency.

Before the new Rust directory existed, oracle.py and freeze.json fixed43,425
rows. Python arbitrary-precision arithmetic subtracts whole signed nanosecond
values, then takes sign and divmod of absolute magnitude. That independent
relation differs from Rust's lexicographic borrow algorithm. Cases cover i64
extremes, cross-zero spans, reverse/equal timestamps, all selected nanos-boundary
cross products, a dense near-zero set,25,000 deterministically seeded synthetic
pairs and explicit safe-domain refusals. The seed is solely offline fixture
selection; no target RNG, runtime data or OS state is read.

Actual opt-level0 and3 compiled Rust both match every row. Seven separately
compiled mutants exit normally and are detected: equality direction, positive
result tag, negative result tag, clamping unsigned seconds to i64MAX, omitted
seconds borrow, incorrect borrow base, and refusal of valid999999999 nanos.
The last control covers the safe wrapper; the first six cover the whole result
and arithmetic relation. First witnesses and source/probe/output hashes are
in qualification.json. This is independent mathematical qualification, not
captured differential execution or native ABI equivalence.

Host Cargo build, Linux/amd64 release rlib, Clippy all-targets with denied
warnings and rustfmt pass. From repository root after sourcing
`work/environment/new-three-env.sh`:

```sh
python3 -B research/work-items/RE-012-timespec-difference-115/verify.py
python3 -B research/work-items/RE-012-timespec-difference-115/derive.py
python3 -B research/work-items/RE-012-timespec-difference-115/qualify.py --out work/timespec-difference-replay --rustc "$RUSTUP_HOME/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc"
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-timespec-difference/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-timespec-difference/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --check --manifest-path src/node115-timespec-difference/Cargo.toml
```

Python3.14.5, Capstone5.0.7, GNU2.45, LLVM23.1.4, Rust1.95.0. Only newly
compiled own host Rust executes; Linux emits an rlib. No captured binary,
clock service, OS/TLS call, node networking, emulator or instruction evaluator
runs. Original caller operations, clock errors, raw-invalid timestamps, native
panic/layout and whole-node integration remain open. Next: reuse this normalized
full-range relation in a verified elapsed-time caller while independently
recovering that caller's concurrency and failure behavior.
