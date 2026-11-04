# RE-012: Node115 CLI registration path

- Component: node-runtime.
- Sole target: node115, Linux x86-64; SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Source/base: 8fd8db680ec4bfef40996e5616bce3d5156d0b86.
- Reference: MIT Clap d51ae89656fda527ef1bccf53fca0ad78ecb8c29, src/app/parser.rs; structural comparison only.
- Status: exact byte/call/data-write observations; inferred Rust labels; unresolved transitive ownership, action/type chains and exact vendored version.
- Included: 0x1638840 registration entry plus eleven bounded reference/group/lowering/insertion/drop helpers, exact ranges in spec.json.
- Excluded: prior common-producer coverage, full CLI grammar/defaults, arbitrary alias inputs, captured execution, stable Rust layouts and full component completion.

## Reproduce

README.md gives exact root-relative commands. The target remains data. No target executable is spawned. The author-side native commands use GNU binutils 2.47, -d -Mintel --insn-width=16, and each exact start/end range. Capstone binding 5.0.7/core 5.0.1280 independently decoded every exported byte; original raw outputs are retained.

## Evidence

spec.json binds 21 typed operand observations, 23 actual callsites, three unique RELATIVE writers and twelve FDEs. records.json is re-derived from the target, including CIE/FDE identities and bounded LSDA tables. independent-instructions.json and the twelve original GNU files retain the full 6,165-byte / 1,311-instruction denominator, without normalization masks.

The previous producer's fourteen calls establish the actual registration binding but do not count as new coverage. README.md separates the new writes and inferred branch names from unknown helper contracts. Complete action/type chains, arbitrary callee unwinding and runtime caller completeness are not established.

## Implementation and comparison

No Rust implementation, Cargo.lock, two-build comparison or equivalent node is claimed. The independently authored standard-library collector uses existing ELF/FDE readers and rejects changed target identity, typed opcodes/operands, call displacements, RELATIVE writers, FDE ranges and malformed bounded LSDA fields. Internal corruption tests bypass only the outer identity hash so that a hash failure cannot hide missing operand guards.

The replay verifier has a closed, contained, no-symlink file inventory and source digests. It re-derives records, compares the full independent byte stream and native rows, and qualifies exception boundaries against decoded instructions. Original native byte corruption and missing-row controls test that comparator.

## Results and limitations

validation.json records focused observed runs and exact source/input identities. It is not a whole-suite or hosted-CI pass. Native Windows GPG import and six original test patterns were observed failing at the same base; final-head mandatory commands remain separately reported. A failed-leftover-child author probe remains failed even though it wrote raw observations; later successful focused extraction does not relabel it.

No component gate or implementation-progress byte total changes. A research inventory count may increase only through the official catalogue generator. Next: recover the reference-lowering and positional insertion ownership contracts before Rust reconstruction.
