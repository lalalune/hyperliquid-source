# Node #115 portfolio split entry composition

Backlog HL115-047. Target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
ELF virtual addresses; original static disassembly only. No captured execution,
emulation, copied unlicensed inferred source or complete-component claim.

## Gap and prior attempts

Merged #2154 identifies the simulation path's split handoff. #3374 recovers
`0x3f10c10`'s sign, scaling and overflow behavior but leaves its entry helpers
opaque. This contribution closes the value/entry policy at those helper
boundaries and supplies an owned unique-key composition. It credits the existing
arithmetic rather than claiming another reconstruction of it.

## Contract

The negative map starts empty; the positive map is a supplied seed whose ownership
is transferred to the output. The input is a valid map with unique unsigned64
keys, not an arbitrary list of duplicated wire entries. For each input:

* Zero does nothing.
* Negative magnitude uses the previously established saturating absolute value.
  `0x3cde300` inserts it if absent. On a match its `0x3cde66b..0x3cde676` path
  loads the old value, overwrites with the new value and returns the old value.
  It does not add magnitudes. The split caller ignores this return value.
* Positive quantities are multiplied by 100 with overflow checked before entry
  lookup. Overflow leaves the seed unchanged and does not create a vacancy.
  `0x3cd0da0` distinguishes occupied/vacant entries without changing an occupied
  value. `0x3f14f20` returns the occupied cell, or initializes a vacant cell to
  zero. The caller then adds the scaled quantity with unsigned saturation.

The entry results are bound through both flat and tree arms. Flat values are at
16-byte row+8. Tree values are at node+0x60+8*index. Positive default zero is
passed explicitly to `0x4546250` / `0x370f210`, with their key/value stores
retained. Negative new values reach `0x454b590` / `0x370a180`; the occupied tree
and flat paths converge on the same replacement store. The native tree split,
allocation, balancing, representation conversion and iteration internals remain
premises of valid logical map operation, not newly reconstructed algorithms.

A key already in the positive seed accumulates instead of being replaced. A
negative input key does not remove a same-key seed entry: the key may occur in
both output maps. Zero input also preserves any seed value. These are useful
composition distinctions missing from a scalar sign classifier.

Repeated invocation of the negative helper replaces the previous magnitude.
However, repeated negative keys are not reachable from a well-formed unique-key
input traversal into a freshly empty negative map. The source intentionally
accepts a `BTreeMap` rather than attributing an invented duplicate-wire policy to
the target. The helper policy is tested separately, and the positive seed case
provides a reachable occupied-key integration witness.

## Validation

`src/node115-portfolio-split-entries` performs actual owned-map insertion,
replacement and accumulation. Five tests cover distinct occupied policies,
overflow before entry creation, retained seed keys, zero, `i64::MIN`, and whole
split composition. An independent u128 oracle checks 54 product/seed boundary
pairs, including multiplication refusal and addition saturation. Native data
layouts and pointer identity are not the layout of Rust's BTreeMap.

```
python3 research/work-items/RE-007-node115-portfolio-split-entries/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-portfolio-split-entries/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-portfolio-split-entries/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-portfolio-split-entries/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-portfolio-split-entries/Cargo.toml --all-targets -- -D warnings
```

Use Python with Capstone 5.0.7. The verifier authenticates the whole target,
FDEs and nine selected windows, then checks 1,095 facts over 1,088 instructions.
Nineteen deliberately corrupted instructions/call edges must fail the semantic
checks even when blanket window hashes are bypassed after authenticating the
original. These are static checks, not executed target comparisons. Repository
check results and precise environment commands are recorded in the PR.

The full simulation, economic meaning of the key/quantities, nonzero-mode
transformations, diagnostic behavior, physical collection mutation and unwind
cleanup remain open. This closes entry/value composition only, with gates false.
