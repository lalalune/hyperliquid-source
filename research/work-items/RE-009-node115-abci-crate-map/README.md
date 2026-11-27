# RE-009: node #115 complete `abci` module diagnostic map and integrated engine crate

- Component ID: `abci` (`l1/src/abci/*` — 4/4 observed diagnostic source paths)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes)
- Method: static ELF/Location/FDE/instruction verification over the pinned #115 binary. No target execution.

## All 4 `l1/src/abci/*.rs` files mapped in node #115

| Source file | #115 `Location` count | Key enclosing FDEs | Binary-backed semantics integrated into `src/node115-abci` |
| --- | --- | --- | --- |
| `l1/src/abci/abci_hash.rs` | 2 (`L28:37`) | `0x2bb37c0`, `0x548d8c0`, `0x548dad0` | 59-slot state-root reduction tree MessagePack preimage encoder (`RE-017-abci-root-tree-115`) + root-selector `.bss` cell (`0x160bee0` / `0x5cadd50` -> `0x6500098`). |
| `l1/src/abci/engine.rs` | 22 (`L168..175`, `L262`, `L316`, `L332`, `L339`, `L431`, `L514`, `L557`) | `0x2d23610`, `0x5a04e40`, `0x5a06600`, `0x2d25620`, `0x5a07ec0`, `0x4d98c40`, `0x38c40f0`, `0x3d5dca0` | Single-owner block application (`ctx + 0x450`), `H -> H+1` saturating height advance (`0x54838d3..0x54838e5`), sink-before-comparison (`ctx + 0x280` -> `ctx + 0x400`), post-comparison local root cadence (`% 10_000 == 0` / hardfork / `% periodic_cadence`), and EVM checkpoint maintenance (`prune_lowest_evm_checkpoints` keep = `100` at `0x4d98d51`, daily `tar` with `TAR_COMPLETE` marker). |
| `l1/src/abci/hash_signature_tracker.rs` | 8 (`L107`, `L123`, `L174`, `L184`) | `0x27604d0..0x27610ac`, `0x5afadd0..0x5afb3a3` | Running unsigned max watermark (`tracker + 0x80`), seal marker (`tracker + 0x90`), saturating prune cutoff `height - 50_000` (`0xc350`), pending cutoff `1_000` (`0x3e8`), vote admission (`node115-digest-vote-admission`), two-gate support transition (`node115-digest-support-gate`), drain handoff (`node115-digest-reference-handoff`), and JSON quorum line (`node115-quorum-line`). |
| `l1/src/abci/state.rs` | 25 (`L76..82`, `L102`, `L113`, `L123`, `L151`, `L161`, `L193..195`, `L201`, `L340`, `L460`) | `0x3c12800`, `0x3c13520`, `0x26a2c80`, `0x26a2810`, `0x22ed1f0`, `0x229b760`, `0x22ec9b0` | Checkpoint restore validation (`[S+0x28] == requested`), loader tag `1` (`0x3c1353b`), freeze-height invariant `freeze_height >= current_height` (`L201`), and action success code `0x1a2` (`0x22ec9c9`). |

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-abci-crate-map/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_abci_crate_map_115
(cd research/work-items/RE-009-node115-abci-crate-map && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/storage-abci \
  cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
```

## Limits

- Live exchange action semantics beyond `0xdd` digest votes, ECDSA recovery behind slot `0x64e0ad8`, concrete BLAKE3/SIMD digest implementation equivalence, and full component acceptance gates remain open.
