# RE-009: Node #115 Complete `abci` (`l1/src/abci/*.rs`) 41-FDE Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `abci` (`l1/src/abci/*.rs`, Stream B / `RE-009`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** `l1/src/abci/*.rs` `Location` struct (**57/57**) across **every** observed source file (**4/4**: `abci_hash.rs`, `engine.rs`, `hash_signature_tracker.rs`, `state.rs`) and **every** `.text` FDE referencing them (**41/41 unique FDEs = 89,230 bytes**), closing the final four unaudited `state.rs` routines (`state.rs:102:40`, `state.rs:113:9`, `state.rs:161:83`, `state.rs:193:56`/`195:17`/`195:64`, and `state.rs:340:21`) plus all slow/duplicate monomorphizations.

## Final 4 `l1/src/abci/state.rs` Routines Closed Here

1. **State restore / loader unwrap & handoff (`state.rs:102:40`, `state.rs:113:9`)** — `0x564a680` (`101 B`), `0x2ae41e0` (`11,142 B`), `0x2cde430` (`10,657 B`):
   - `0x2ae4f04` / `0x564a685` pass `state.rs:102:40` (`0x64767d8`) into `0x422e410`; `0x564a691` tests `Result` discriminant `al & 1` and panics via `called \`Result::unwrap()\` on an \`Err\` value` (`0x92a732`, len `0x2b`).
   - `0x2ae4f2d` / `0x2cdf029` pass `state.rs:113:9` (`0x64767c0`) into `0x422ed40` on the restored state pointer.
2. **State serialization buffer & wall-clock elapsed logging (`state.rs:161:83` and `state.rs:193:56`, `195:17`, `195:64`)** — `0x4e4b860` (`960 B`) and `0x26a2810`/`0x4e4af80`/`0x4e4b3f0` (`3 × 1,134 B`):
   - Both paths initialize a serialization buffer capacity of **`0x1000400` (`16 MiB + 1 KiB = 16,778,240` B)** (`0x26a2881`: `mov dword ptr [rsp+0x18], 0x1000400`; `0x4e4b8c1`: `mov dword ptr [rsp+0x8], 0x1000400`).
   - Both measure wall-clock elapsed duration in seconds by dividing nanoseconds by `1_000_000_000.0` (`0x26a2979`, `.rodata 0x458d50`), guarding against `f64::INFINITY` (`0x26a2985`, `.rodata 0x459010`), and logging `"serialized abci state"` (`0x26a2a21`, `.rodata 0x5f41ee` / `0x91875b`) via the structured `WARN >>> ... [height: ...] @ [elapsed: ...]` formatter (`0x43df63`).
3. **Zipped batch action/result length-equality guard (`state.rs:340:21`)** — `0x229b760` (`302 B`) and `0x5618890`/`0x5618990` (`2 × 246 B`):
   - Enforces exact `assert_eq!(left.len(), right.len())` (`0x56188bb`: `cmp rsi, rcx; jne 0x561893b -> core::panicking::assert_failed` with `Location` `0x642d368`/`0x64aa260`) before computing `min(lhs, rhs)` (`cmovae`/`cmovb`) and delegating to `0x2ccda40`/`0x564bc00`.

## Complete `abci` Acceptance Inventory

- **Mapped**: 4/4 `l1/src/abci/*.rs` files, 57/57 `Location` structs, 41/41 unique FDEs (`89,230 B`) verified against `work/index/node-115-fde.tsv` and raw ELF bytes.
- **Built & Behavior**: Integrated `src/node115-abci` (`#![forbid(unsafe_code)]`, 0 external deps, pure-`std` + `node115-abci-blake3` + `node115-abci-checkpoint-replay-fixture` + digest micro-crates) implements checkpoint restore, `STATE_SERIALIZE_BUF_CAPACITY` / elapsed-seconds logging helper, `zip_exact_slices` guard, `AbciCheckpointBundle` atomic on-disk persistence, BLAKE3 state-root reduction tree, big-endian `u16` `LtHash`/`LtHashes`, `HashSignatureTracker` quorum/seal/prune, 6 ordered `apply_block` guards, 7-stage `apply_block_pipeline`, EVM checkpoint maintenance/straggler filter, and daily tar archiver.
- **Compiled-Byte Identity (honest inventory)**: **55** non-overlapping, 100% relocation-qualified `abci` `.text` FDEs (`6,824 B`) live-rebuilt under `rustc 1.95.0` across `RE-009-node115-storage-abci-byte-matches` (`36w / 1,017 B`) and `RE-009-node115-storage-abci-debug-byte-matches` (`19w / 5,807 B`).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-abci-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_abci_closure_115 -v
(cd research/work-items/RE-009-node115-abci-closure && sha256sum -c MANIFEST.sha256)
```
