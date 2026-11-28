# Honor context mode when recording the offline successor root

The integrated ABCI replay fixture treated a matching root cadence as sufficient for recording a candidate root. The native slow selector checks context mode on both the fixed-height and ordinary interval paths. Mode 2 returns before computing or retaining a raw root. The reconstructed engine now accepts the supplied context mode, preserving its default behavior for existing callers.

Block finalization reaches `0x5a07ec0` from `0x5a05fc9`. The standard 10,000 cadence branch reaches `0x5a07f25` and compares the mode before reaching the remaining gate. The inactive-freeze path compares the same dword at `0x5a07f42`. Mode 2 takes the empty return at `0x5a07f2e`, bypassing the root call at `0x5a07fce` and later history insertion at `0x5a07fe5`. [PR #7323](https://github.com/lalalune/hyperliquid-source/pull/7323) modeled the selector as a standalone preflight. This change applies the mode check in the integrated Rust replay path.

The normal controls cross a 10,000-height boundary and a custom interval with identical synthetic replay inputs and candidate digests. In mode 2 both blocks still advance height and round, and the root selector and history remain untouched. Other parts of the node's context-mode behavior, invalid freeze states, and real raw-root parity are outside this fixture.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-integrated-root-mode/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test root_context_mode
```

The [offline log](offline-log.txt) records the selected native span checks and Rust results. The binary is read as ELF data.
