# Pre-code validation status

Before new Rust, the author ran the task-local static verifier with its explicitly temporary `--pre-freeze-check` mode. It passed 83 negative controls and two byte-identical native/fixture regeneration trees: 32 full FDEs, 14,506 bytes, 3,560 instructions and 1,141 mathematical cases. Independent review then caught semantic case names in the proposed client ID column. [PRE-CODE-REVISION.json](PRE-CODE-REVISION.json) records their replacement with opaque IDs before the freeze; every input frame, expected length, preimage and digest stayed unchanged. Temporary pre-freeze mode refuses to run once the immutable receipt exists.

The retained `PRE-RUST-FREEZE.json` binds 81 derivation, protocol, source-plan, scope, obligation, dependency, native-record, provider and expectation files before implementation. Subsequent ordinary and optimized-Python checks both passed all 83 controls and two fresh regeneration trees. Their complete result JSONs were byte-identical, SHA-256 `f0401a40acdc5f31668618fbe31521831e036bd75f58021ecb0444505ffe87df`; one copy is retained as [validation/static.json](validation/static.json), with both command exits and explicit local-output-path normalization in [validation/runs.json](validation/runs.json). The final manifest is an integrity inventory, not a signature or proof of chronology by itself.

Only Python arithmetic, reviewed ELF/DWARF parsing and native GNU/LLVM disassembly of data snapshots ran. No captured machine code or instruction evaluator ran. There was no broad repository test invocation, Rust implementation build or production/network operation in this phase. The 64 below-identity instruction controls prove rejection of changed evidence; they do not evaluate changed native behavior. The all-year certificate proves finite integer identities under the manually established arithmetic relation, not an instruction-level equivalence theorem.

Independent proof/corpus review subsequently passed and authorized source work.
The later source freeze and actual authored-source checks are recorded separately
in [rust-validation/VALIDATION.md](rust-validation/VALIDATION.md). They use the
real baseline Cargo graph, pinned toolchain, input-only client, both profiles and
compiling source mutants. The pre-code receipt remains unchanged; no later
source result is restamped as pre-code or claimed as native dynamic equivalence.
