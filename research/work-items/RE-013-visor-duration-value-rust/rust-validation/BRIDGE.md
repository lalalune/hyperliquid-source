# Source and build phase boundary

The coordinator admitted pre-code freeze
`b3bbc7257864d14a4315599352c7d70b7616646a49d6c996186abedd57430857` only after
independent complete native/manual review, raw binding and all59,159 expected
values. The pre-code gate receipt is a private session artifact, not a rewritten
pre-code chronology. The61 entries plus original freeze remain immutable.

`src/visor-duration-value` is the actual new standalone dependency-free Cargo
component. Its API is `convert_bits(u64) -> DurationValue`, with private seconds
and nanoseconds and read accessors. `SOURCE-PROOF.md` proves all source integer
widths, casts, classification and rounding against the frozen value contract.
Names, safe layout and host protocol are new. There are no dependency crates,
feature gates, build hooks, unsafe code, host FP operations, clock/process/filesystem
effects or captured executable calls in the library. The8 authored tests cover
classification, tiny inputs, integral values, both exact tie parities, carry,
the2^64 discontinuity, adjacent product-overflow encodings and canonical remainders.

`input_client.rs` reads only stdin, accepts exactly the frozen16-hex-ID/16-hex-word
framing and calls the real linked library once per input. IDs affect only echo
and duplicate rejection. Its source includes no expected values, provenance,
case labels, oracle imports or table of fixture answers. It buffers all output
until every row is valid, so a malformed suffix cannot emit a successful prefix.
Any command argument is rejected. This is a new host protocol, not a native error
ABI. The build/comparison harness alone opens the frozen expected stream.

`build.py` reuses MIT orchestration from the earlier readiness-value harness
(its exact path/hash is in the docstring), without readiness semantics or source
dependencies. It admits the immutable pre-code phase, exact actual source/test/
client/harness graph, real Cargo manifest and generated lock. It checks every
installed bin/lib toolchain payload and symlink before and after qualification.
Fresh canonical /tmp builds use a fresh Cargo home, explicit offline/locked
commands and allowlisted environment. Lexical and canonical ancestor Cargo
configs must be absent, and ancestor manifests must not supply a workspace.
Actual Cargo metadata must report precisely the one library and one integration
test in the copied component. No fake root workspace or substitute crate is built.

The later authorized run will build debug/release in two distinct clean roots,
run8 tests per profile, compare all59,159 values and retain every raw stdout/stderr.
It will also compile20 deliberately wrong library variants in both profiles;
each must emit its own complete differing value stream. These target sign/tiny/
significand classification, fractional and integer scale, truncation/tie parity/
carry, ordinary microsecond rounding, early/late fallback, nonfinite saturation,
fallback units, adjacent overflow and an integer implementation of premature
53-significand-bit rounding. Mutants are authored source, never modified captured
instructions. Their outcomes are unknown until actual compilation and comparison.

Ten comparator corruptions must fail exact stream equality. Thirteen malformed
stdin cases and one extra-argument case must exit2 without stdout; empty stdin
must succeed with empty stdout. Build commands, status, raw streams, source copies,
toolchain/config admission, actual artifacts and both-profile differences are
retained. Path prefixes are logical only in command metadata; output/compiled
bytes are not masked. Debug Mach-O may retain object paths despite compiler
remapping; any byte difference is reported without assigning an unproved cause.

Preparation permits actual offline lock generation, Cargo metadata/version and
rustfmt only. No library/client compilation is authorized until the separate
coordinator source/build review admits the frozen files. Later receipts must
state what actually passed or failed. Toolchain payload pinning and selected
linker/SDK inputs do not make the host OS, dyld or complete SDK hermetic, nor do
host value matches establish original ABI/compiler/machine-byte equivalence.
