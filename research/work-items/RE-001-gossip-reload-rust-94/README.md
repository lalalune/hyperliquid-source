# RE-001: Rust for node94 gossip-reload selected gates

Target node94 SHA256:
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Base e5c9b6436876b2a4a39daef813171f9879317699.
Component: node-runtime/gossip configuration; bounded predicates only.

## Established contract and missing implementation

Credit merged#1091 and unchanged RE-001-gossip-reload-gates-94. Its producer
binds the native predicates and surrounding ordering but supplies no Rust.
This adds a standalone no_std implementation of both related gates in one
family, without implementing a clock, filesystem, parser or reload API.

The full owning FDE is0x4741210..0x4741694, SHA256
33eff4f0458c535e2cdd4cf397957e21c0a64d9165182c50b5e5cb807dffb29b.
Original ELF VAs, full disassembly/FDE/CIE and body bindings remain in the
credited packet. native-records.json regenerates exactly from the authenticated
whole capture; original disassembly and negative results are preserved.

At0x4741320 the first metadata dword is compared signed, the next two unsigned,
lexicographically, with strict newness. Fields are raw words; no calendar schema,
original object ABI, library ownership/version or live-state reachability is
inferred. This may include upstream time-comparison behavior; it is not credited
as reconstructed first-party bytes or an upstream library source match.

The throttle's TEST/Jcc at0x4741253 bypasses the float predicate for previous
first dword zero. Otherwise the UCOMISD/JBE relation at0x47412bf releases for
less/equal/unordered, so the gate opens only for ordered strict greater.
Helper values and threshold are explicit inputs under normal opaque-helper
return assumptions. Their time units and helper implementations remain open.
These are two selected gates separated by unclosed file/metadata helpers;
the source does not claim that either true result completes a reload.

## Freeze, real builds and controls

Freezea0416b02 and18smoke rows precede production Rust. The actual bounded
instruction decoders plus independent signed-tuple/IEEE equations generate
17133 distinct inputs:16649metadata pairs (15625boundary pairs plus1024public
deterministic pairs) and484throttle combinations. The latter cover four raw
previous dwords and eleven helper/threshold bit patterns each, including signed
zero, subnormals, infinities and quiet NaNs of both signs/payloads.

Comparison assumes ordinary nontrapping, denormal-preserving IEEE value
semantics. Signalling NaNs, exception/status flags and global MXCSR/FPCR recovery
are excluded. The tests enforce that included NaN words have the quiet bit.
Float arguments use exact bit words, not decimal serialization/normalization.

Real pinned rustc1.94.1 opt0/opt3 libraries and separately linked input-only
clients each match all17133 results. Compiled smoke passes. Four compiled
mutants change first-word signedness, metadata strictness, throttle strictness
and zero bypass:8000/125/30/376 mismatches, and all fail actual compiled smoke
assertions with exit101. Same-basename opt3 own rlibs are raw-identical, without
normalization. This is host arm64 macOS reproducibility, not x86-64 byte equality.

Eleven focused tests pass in72.037wall seconds under serial10%active-time duty,
including the existing actual opcode/operand/helper-relocation corruption tests.
Pinned rustfmt, Clippy library/test and fresh catalogue-check pass. The OS denied
setpriority, so nice19 is not claimed. No parallel worker or copied checkout
is used. Explicit shared input/import/reproduction checks reuse completed#1831
results only after confirming unchanged dependency paths against the same base.
That narrow reuse is not a new-code or whole-suite PASS.

## Reproduce

From repository root with authenticated inputs and actual pinned1.94.1 tools:

    python3 tools/gossip_reload_rust.py --rustc "$RUSTC" --output /new/output
    python3 -m unittest tests.test_gossip_reload_rust tests.test_gossip_reload_gates -v
    "$RUSTFMT" --check --edition 2021 src/node94-gossip-reload-gates/lib.rs src/node94-gossip-reload-gates/input_only_driver.rs
    "$CLIPPY" --edition=2021 --crate-type lib src/node94-gossip-reload-gates/lib.rs --emit=metadata -o /new/lib.rmeta -D warnings
    "$CLIPPY" --edition=2021 --test src/node94-gossip-reload-gates/lib.rs --emit=metadata -o /new/test.rmeta -D warnings
    make doctor verify test catalogue-check reproduce

Output directories must be new. Frozen full-corpus hashes are checked before
the compiler; long corpora/products regenerate outside Git. build-result.json
records compiler/source/output identities and exact commands with private
path spellings replaced by$REPO/$OUTPUT/$RUSTC only. No code operand is masked.

The component runner is needed to link Rust clients to the native corpus and
run compiled mutations; the earlier producer offers only Python evidence.
No shared tooling rewrite, fabricated Cargo graph/dependencies, native capture,
Unicorn, real file probe, signing or network operation is introduced.

## Limits and next question

Only selected value/branch outcomes are reconstructed. Callback effects, actual
clock units, parser grammar, payload replacement, mutex/concurrency semantics,
original ABI/ownership/unwind and full function behavior remain unclosed.
No catalogue, byte-credit or full component gate change. Full make test awaits
upstream CI and no pending/queued result is a completed full-suite PASS.
Next close the metadata/parser callees and cached-state update boundary before
building a complete source-based reload procedure.
