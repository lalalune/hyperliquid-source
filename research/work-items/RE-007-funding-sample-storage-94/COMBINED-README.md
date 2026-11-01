# RE-007: funding record storage proof and Rust value reconstruction

This contribution connects the node 94 sample producer's returned records to
the host's keyed sample/fallback updates, closes the complete selected
missing-key insertion paths, and implements the resulting **active-value
transition** in an independent dependency-free Rust component.

For one explicitly supplied ordered record stream, full unsigned tag 2 stops
before an update. Every other even tag appends the unchanged u64 payload to
the key's sample vector, creating an empty vector when absent. Odd tags insert
or replace a fallback value only when the selected dex byte is exactly 3;
the last selected fallback for a key wins. Initial unrelated entries, sample
order, empty-vector presence, unsigned key values and all payload bits survive.

The native theorem ends at host record-loop exit `0x222b480`, under the explicit
valid-tree/vector, allocation, copy, ABI and memory-frame premises in
[PROOF.md](PROOF.md). The Rust component represents active map values; it does
not reconstruct native node layout, capacities, pointers, allocator behavior,
exceptions, scheduling, outer min-length pairing, later reporting/cleanup or
economic meaning. Rust allocation must succeed for the stated value result.
No captured node execution or native ABI/byte-equivalence claim is made.

## Review path and chronological freezes

1. [Static proof](PROOF.md) and [static validation](VALIDATION.md): all 19 selected
   FDEs, including producer/host/bridges, complete sample/fallback insertions and
   growth adapters. The original [README.md](README.md), `FINAL-FREEZE.json` and
   `MANIFEST.sha256` are the unchanged **historical static phase**.
2. [Pre-source contract](pre-rust/CONTRACT.md),
   [source plan](pre-rust/SOURCE-PLAN.md), [oracle](pre-rust/oracle.py) and
   [pre-source freeze](pre-rust/PRE-RUST-FREEZE.json): expectations were frozen
   while the Rust component and driver were absent. The coordinator independently
   regenerated them and checked every state before authorizing source.
3. [Actual source freeze](rust-validation/SOURCE-FREEZE.json): the five real
   component files, actual Cargo-generated lockfile and input-only harness were
   frozen before the first Rust compilation. Its `source_compilation_has_run`
   field describes that historical instant, not the completed state below.
4. [Actual command results](rust-validation/receipts/results.json),
   [raw command streams](rust-validation/receipts/commands.json) and
   [receipt rehash/recount](rust-validation/AUTHOR-RECEIPT-AUDIT.json).
5. `COMBINED-MANIFEST.json` binds this author snapshot of packet and component;
   `COMBINED-FREEZE.json` records its identity. Later independent review receipts
   may be appended separately without rewriting these historical freezes.

Implementation: [src/lib.rs](../../../src/node94-funding-record-storage/src/lib.rs),
[manifest](../../../src/node94-funding-record-storage/Cargo.toml) and
[focused tests](../../../src/node94-funding-record-storage/tests/returned_records.rs).
There is no root-workspace edit, external/path dependency, build script, network
operation or copied reference implementation.

## Why the Rust operation implements this value contract

The native-to-value abstraction in the pre-source contract discards inactive
slots, capacities and addresses while retaining every active key/vector element
and fallback word. The complete native insertion induction establishes that an
absent sample key gains an empty vector and other active associations survive,
including full-node splits and root growth. The original selected leaf handle
then identifies the appended vector. That closure supports the chosen map API;
it is not assumed from a familiar B-tree helper name.

For the Rust loop, use the invariant that both maps equal the contract's result
for the already-processed prefix. Full tag2 breaks before any mutation. In the
even arm, `entry(key).or_default().push(payload)` preserves the previous sequence
and appends exactly one raw word. In the odd arm, exact byte3 admits
`insert(key,payload)`, replacing or creating only that fallback association.
The remaining arm preserves both maps. Ordered slice iteration and induction
over its finite prefix establish the specified result for every representable
input on successful allocation. No numeric conversion, tag truncation or
payload arithmetic occurs. This is a conditional active-value relation, not a
claim about native allocation/failure or the whole host's final state.

## Observed validation

| Evidence | Observed result |
| --- | --- |
| Complete native scope | 19 FDEs; 13,772 bytes; 3,208 GNU/LLVM-agreed rows |
| Native structural/metadata census | 717 blocks; 607 transfers; 73 LSDA call-site rows |
| Static controls | 883 passed, including 17 actual operand-mutated dual-native decodes |
| Static regeneration | Two exact collections, normal and `-O`, distinct seeds/timezones |
| Pre-source corpus | 8,144 cases / 85,263 input records; 20 explicit hand expectations |
| Actual crate tests | Eight focused tests passed in each debug/release profile |
| Actual format/Clippy | Two clean-source format checks and relevant all-targets Clippy passed |
| Input-only compiled outputs | 8,144/8,144 exact states in debug and release, in both clean directories |
| Actual wrong-source controls | Ten release-compiled mutants, all distinguished |
| Comparator controls | Eight missing/extra/changed/reordered/duplicate/format corruptions rejected |
| Raw receipts | 59 commands, all exit 0; 118 stdout/stderr references rehashed; 43 unique streams |

The wrong-source mismatch counts are, in recorded order:

| Compiled wrong behavior | Mismatching cases |
| --- | ---: |
| Never stop | 1,491 |
| Stop on low byte 2 | 1,176 |
| Process tag2 before stopping | 1,491 |
| Treat only tag1 as fallback | 195 |
| Admit every nonzero dex byte | 2,869 |
| Keep first fallback | 1,749 |
| Replace samples instead of append | 4,010 |
| Drop absent sample keys | 4,514 |
| Clear initial state | 8,110 |
| Clear each payload's low bit | 6,284 |

The independent prefix/filter/group oracle was frozen before source; the
compiled library uses a sequential loop. The driver reads only inputs and
writes every resulting map entry. Expected bytes are read by the external
comparator. All four clean observed streams have SHA-256
`2bf1ffb9ef4702af7cff3642165263a0761437527719f7c1b796c765031a10b6`.
The corpus supplements the manual proof; it is not an exhaustive native-state
execution or evidence for opaque allocator/scheduler behavior.

## Rebuild identity and its limit

The harness uses resolved canonical build paths for Cargo ancestor-config
audits and compiler remapping. Both clean directories produced byte-identical
rlibs in debug and release, and byte-identical release drivers, without masks.
**Debug driver bytes differed and retained their canonical build-path prefix.**
The same full value output matched in both directories. No normalization,
rerun to force equality, or raw debug-driver reproducibility claim is made.

Toolchain bin/lib files were pinned before compilation and checked unchanged
afterward; selected linker/SDK files and the exact environment are recorded.
The build used installed Rust 1.94.1 on `aarch64-apple-darwin`. The host OS/dyld
and entire SDK are not hermetic, and this is not the captured Linux compiler or
build identity. Raw rlib equality here concerns two builds of this authored
component, not equality to any node94 machine-code body.

## Reproduction and remaining scope

See [rust-validation/README.md](rust-validation/README.md) for the pinned,
offline/locked build command. Supply source-freeze SHA-256
`e745b6a6cdaba1b4b98ea64fe95dee0baddb9b8b4f185cb468db49965796be5b`.
The original static verifier and independent corpus generator remain separately
reproducible. Complete stdout/stderr streams are retained as real gzip bytes;
there is no expected-file substitution for observed output.

The explicit unresolved boundary is still the scheduler's input-to-returned-list
completeness/order and native allocator/copy/frame implementations, followed by
opaque post-loop effects. No full component gate, coverage denominator,
repository-wide suite, hosted CI or funding-payment claim is introduced.
Prior premium, distribution, bucket, config, metadata-clone and related generic
insertion work is credited in the unchanged static proof/intake.
