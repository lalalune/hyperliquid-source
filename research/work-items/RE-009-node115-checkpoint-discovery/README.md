# Discover a completed local checkpoint at an exact requested height

`src/node115-checkpoint-discovery` implements the read-only selection result for an already-formatted local checkpoint directory. Earlier packets established several adjoining contracts. A fixture can now use real directory entries and markers to obtain the selected canonical path. For example, a marker under `+0042` alone cannot select height 42. When the canonical directory `42` also exists with a qualifying marker, both spellings yield rows for that same canonical path.

**Target and scope.** Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`. Addresses are ELF virtual addresses. This is independently authored Rust with the existing directory admission crate as a local dependency.

| Stage | Selected node evidence |
| --- | --- |
| Obtain directory names | The outer-directory predicate at `0x25d3f95` resolves to `0x1500a60`. On the accepted branch, `0x25d3fb1` calls the directory-only listing `0x1501290`. A listing failure can reach the same no-match sentinel. See [startup admission](../RE-012-node115-startup-directory-admission/README.md). |
| Canonicalize heights | The producer at `0x25d410d` takes an empty suffix. Its collector parses the numeric component as unsigned decimal, admitting a leading plus. Formatting emits the numeric value in decimal, losing the original spelling. The outer routine reverses the returned path rows. See [canonical height paths](../RE-017-node115-restore-canonical-heights/README.md) and [selected sort contracts](../RE-009-node115-checkpoint-numeric-sort-33-63/README.md). |
| Check both marker forms | The primary marker is `CHECKPOINT_COMPLETE`. If its regular-file check fails, selector 2 builds `CHECKPOINT_COMPLETE_EvmState` under the same canonical path. The verifier resolves the typed string and checks the regular-file mode test. See [marker paths](../RE-017-node115-restore-marker-paths/README.md). |
| Return an exact match | The requested key is saved at `0x25d3f31`, reloaded at `0x25d4962`, and compared to each admitted row at `0x25d49cf`. An eligible first match carries its path and height. Scan exhaustion reaches the sentinel. See [exact-match handoff](../RE-017-restore-checkpoint-exact-match-115/README.md). |

The adapter accepts the checkpoint directory itself. `candidates` exposes the ordered rows and any directory-open error. `find_checkpoint` returns the first exact match, collapsing the ordinary missing/listing-failure cases to `None`. It uses Rust's unsigned sort for the logical order. Direct evidence covers small vectors and the published 33–511 composition under its cited contracts. For larger lists, order equivalence depends on the remaining native sort contract. Distinct directory spellings can generate duplicate equal-height rows. Their canonical paths are identical in an unchanged filesystem.

The equivalence scope is ordinary, stable Unix directories and regular files, successful allocations, normally returning helpers and the selected control-flow edges. The adapter leaves the filesystem alone. Native treatment of rejected entries after collection, diagnostic ownership, allocation and metadata races, symlinks, snapshot-content decoding, fallback after decode failure, and replay validation are separate questions.

## Reproduce

Run from the repository root. The Python verifier needs only the standard library and existing in-tree ELF readers.

```sh
python3 research/work-items/RE-009-node115-checkpoint-discovery/verify.py
cargo test --offline --locked --manifest-path src/node115-checkpoint-discovery/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-checkpoint-discovery/Cargo.toml
cargo clippy --offline --locked --all-targets --manifest-path src/node115-checkpoint-discovery/Cargo.toml -- -D warnings
```

The verifier authenticates six complete FDEs and 33 selected instruction starts, resolves five indirect calls, rejects a shifted slot at each call, and checks decimal and marker data. The focused tests build real directory trees for alias spellings, skipped invalid components and overflowing values, both marker types, marker directories, a missing exact height, and a shuffled collection of 73 checkpoints. No captured code runs. The instruction witnesses were decoded from owning FDE starts using GNU objdump.
