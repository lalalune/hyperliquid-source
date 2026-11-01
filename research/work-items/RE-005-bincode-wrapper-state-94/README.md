# RE-005: integer wrapper charge, cursor and caller composition

The direct Readers do not reproduce the complete u32/u64 slice wrappers.
The wrappers charge a fixed 4/8 before decoding, retain a non-overflow limit
failure's increment, and select length-dependent error/cursor behavior. In
particular, a rejected fast marker remains unread while the Reader consumes it.

This contribution extends the real dependency-free `src/bincode-varint` crate
with independently authored safe `SliceDecoder` and `SliceError` value APIs.
Existing Reader, encoder and fast-only APIs retain their behavior. The exact
conditional contract and one existing request caller's state composition are in
[PROOF.md](PROOF.md); actual results are in [VALIDATION.md](VALIDATION.md).
Only new Rust runs. No captured instruction execution or emulation is used.

- Task/component: RE-005 / serialization, bounded integer-wrapper family.
- Target: node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; relevant source and
  prior packets are unchanged from the initially inspected `abac38ba`.
- All addresses are linked ELF VAs. Actual FDE ranges, PT_LOAD file mappings,
  full native byte partitions, three RELATIVE bindings and four tables are bound.
- Partial progress only. No acceptance gate, original Rust ABI, whole request
  wire schema, network behavior or target machine-code identity is claimed.

## New scope and prior credit

The [slow-width packet](../RE-005-bincode-slow-widths/README.md) already records
the u32 wrapper, both Readers, width thresholds and differing u64 error codes.
The [Reader Rust packet](../RE-005-bincode-reader-rust-94/README.md) implements
the Reader value/cursor relation. The [gossip route packet](../RE-001-gossip-enum-routes-94/README.md)
already establishes the selected request's calls and short-circuit checks.
The [original varint packet](../RE-005-bincode-varint/README.md) establishes
the u64 fast success path. Those findings and exports are reused context.

The additional result is the complete wrapper charge/error/cursor transition
and its safe implementation, with the selected caller's composed state effects.
No inferred unlicensed implementation was copied. New code/prose are MIT;
native exports retain the captured artifact's upstream rights.

| Role | Actual FDE | Bytes / instruction rows |
| --- | --- | ---: |
| u32 wrapper | `0x466bc10..0x466bd03` | 243 / 73 |
| u64 wrapper | `0x466bd10..0x466bdf5` | 229 / 69 |
| u32 Reader | `0x466d850..0x466d975` | 293 / 88 |
| u64 Reader | `0x466d980..0x466dabc` | 316 / 95 |
| Error builder | `0x466dac0..0x466dace` | 14 / 5 |
| Request context | `0x438b5c0..0x438b6d7` | 279 / 76 |
| Export/comparison denominator | Six complete FDE bodies | 1,374 / 406 |

Every selected byte and instruction boundary agrees between GNU and LLVM,
without normalization. This is two decoders of one target, not independent
semantic implementations or a count of newly recovered bytes. All 15 calls
resolve within this family under the recorded relocation bindings.

## Frozen expectations and actual controls

`PRE-RUST-FREEZE.json` records the prior component source hash, absent wrapper
APIs and the hashes of 4,726 input/expected rows before implementation. The
corpus covers all 256 tags, both width thresholds, short payloads, non-minimal
values, suffixes, mode bypass, overflow/limit equality and failures, and the
request's successive calls. It contains 1,681 u32, 1,681 u64 and 1,364 composition
cases. The production adapter receives input rows only; expected rows are
read by the comparison runner and assertions, never by the library/driver.

`evidence.py` authenticates the complete input before native parsing and uses
one private chmod0400 snapshot shared by both decoders. Full snapshot bytes
are checked after exports. `observed/records.json` is compact metadata;
complete instructions remain in the native text files. Static parsers are
reused at their recorded hashes, with no shared-tool modification.

`verify.py` regenerates all fourteen evidence files twice, checks the frozen
fixtures and exercises below-identity body/table/relocation/FDE/data controls.
Five changed native operands also change independently calculated scalar
expectations. These are corruption and mathematical sensitivity controls,
not instruction emulation. `build.py` compiles four behavioral mutants;
each must compile, disagree with the frozen corpus and fail compiled assertions.

## Reproduce

From repository root, with the pinned artifacts and installed native tools:

```sh
python3 -B research/work-items/RE-005-bincode-wrapper-state-94/verify.py
python3 -O -B research/work-items/RE-005-bincode-wrapper-state-94/verify.py
python3 -B research/work-items/RE-005-bincode-wrapper-state-94/build.py --rustc /path/to/rust-1.94.1/bin/rustc --output /new/wrapper-build --controls
cargo test --offline --locked --manifest-path src/bincode-varint/Cargo.toml
cargo test --offline --locked --release --manifest-path src/bincode-varint/Cargo.toml
cargo clippy --offline --locked --manifest-path src/bincode-varint/Cargo.toml --all-targets -- -D warnings
```

Use `collect.py --output /new/wrapper-native` for a fresh fourteen-file native
export. Destinations must be new; existing output is preserved. The collector
records GNU/LLVM/readelf versions and explicit Intel-syntax/start-stop options.
`collect.py` and `verify.py` accept `--gnu`, `--llvm` and `--readelf` overrides;
their defaults are the recorded macOS host paths. The original `evidence.py`
and its pre-Rust freeze hash are preserved. Exact textual reproduction requires
the recorded provider versions/output conventions; a different provider may
export the same bytes but fail the retained-text equality check. The Rust toolchain is the
repository research pin, not recovered original compiler provenance.

## Limits and next question

Only active fields are represented; copied inactive bytes, original enum/state
layout, destructor ownership and source configuration types remain unknown.
The comparison adapter's request operation is a selected call composition,
not a public request decoder. Values/suffixes are qualified under valid-input,
ordinary-call and disjoint-memory premises. Own host Rust output agreement and
repeatable host rlibs are not target machine-code equality; target raw-equal /
normalized-only / unmatched compiled counts remain unmeasured.

No broad `make test`, captured interpreter, original process, live network,
signing or chain action is part of this packet. The coordinating contribution
reports applicable root static gates separately. A next bounded question is
which constructors supply mode/limit/charge and which valid source modes they
admit. The excluded Reader at `0x466dad0` and gossip response helpers remain
separate work; no progress gate advances.
