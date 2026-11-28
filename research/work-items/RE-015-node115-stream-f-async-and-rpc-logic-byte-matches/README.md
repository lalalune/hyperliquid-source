# RE-015: Node #115 Stream F (`evm-rpc` + `info-api`) Async & RPC Pure First-Party Logic Byte Matches

## Target & Provenance

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Compiler & flags**: `rustc 1.95.0 (59807616e 2026-04-14)`, `--edition=2021 --crate-type=bin --crate-name=stream_f_async_rpc -C opt-level=3 -C overflow-checks=yes -C relocation-model=pie -C codegen-units=1 --emit=obj`
- **Source hygiene**: `#![forbid(unsafe_code)]`, `0` external crates.io dependencies, `0` `core::`/`alloc::`/`std::` windows attributed to first-party, `0` overlaps with `research/byte-windows.json` or any sibling work-item packet (checked across both `start`/`end` and `start_va`/`end_va`).

## Summary (38 Strictly Disjoint First-Party Business-Logic FDEs = 7,090 B)

| Component | Windows | Total Bytes | Raw-Equal Bytes | Raw-Equal % | `.data.rel.ro` `Location` Anchor(s) |
| --- | ---: | ---: | ---: | ---: | --- |
| `evm-rpc` | `1` | `94 B` | `83 B` | `88.30%` | `0x642dc48` (`evm_rpc/src/evm_store.rs:452:61`) |
| `info-api` | `37` | `6,996 B` | `6,143 B` | `87.81%` | `0x6442df8` (`info_server/src/abci_state_info_handler.rs:81:12`), `0x6442de0` (`:82:16`) |
| **Total** | **`38`** | **`7,090 B`** | **`6,226 B`** | **`87.81%`** | **3/3 verified, 0 non-reloc diffs, 38/38 relocation-qualified** |

### Breakdown

1. **`evm-rpc` (`1` FDE / `94 B`)**:
   - `0x232df90..0x232dfee` (`94 B`, `83/94` raw-equal, 0 non-reloc diffs): `evm_rpc/src/evm_store.rs:452` `resolve_block_number(&EvmStore, &Option<BlockId>, u64) -> Option<u64>`, resolving `Some(BlockId::Hash { block_hash, .. })` via `#[track_caller]` hash-index lookup at `self + 0x28`, `Some(BlockId::Number(BlockNumberOrTag))` via 6-arm jump table (`Latest|Finalized|Safe => Some(latest)`, `Earliest => Some(0)`, `Pending => None`, `Number(n) => Some(n)`), and `None => Some(latest)`.
2. **`info-api` (`37` FDEs / `6,996 B`)**:
   - `37` monomorphized `info_server/src/abci_state_info_handler.rs:81-82` `async fn` `Future::poll` state machines (`0x29781a0..0x297acb9`) spanning 14 distinct `(argument_layout, response_layout)` instantiations (`121 B`, `144 B ×2`, `146 B`, `148 B ×5`, `150 B ×5`, `158 B`, `160 B`, `177 B ×6`, `185 B`, `191 B`, `193 B ×2`, `247 B`, `249 B ×6`, `267 B ×4`), each loading `self.inner` -> `&inner.meta` (`+0x10`) + `&inner.lock` (`+0x140`), constructing `LocalMeta::Ctx(ctx)` (`tag = 0`), invoking the `#[track_caller]` ABCI-state closure executor with `flag = false` and `Location` `0x6442de0` (`:82:16`), and transitioning the Future state byte (`0 -> 1`, unwind `-> 2`, panic-on-resumed via `0x6442df8` `:81:12`).

## Companion `constants` (`global_constants`) Whole-Scope `identity` Readiness Audit

- **Offline registry check**: local `~/.cargo/registry/{cache,src}` contains only `memchr-2.8.3` (no `2.7.x`) and `serde_json-1.0.{120,140,154}` (no `1.0.145..1.0.149`), confirming that the 2 residual third-party `serde_json` CGU FDEs (`0x1775ee0` `102 B` + `0x1776c20` `71 B` = `173 B`) cannot be closed offline without patching crates.io packages.
- **Full-scope `global_constants` inventory**:
  - In-CGU first-party functions: **`12/12` (`12,753/12,753 B = 100.00%`)** matched (`e1528748a`).
  - Total CGU `0x1772f80..0x1778ad7`: **`38/40` (`22,877/23,050 B = 99.25%`)** matched (`e1528748a`).
  - `.data.rel.ro` `Location`s: **`5/5`** (`4` in-CGU across 3 matched FDEs + `1` cross-CGU `0x6411208` `aws_name.rs:213:29` `unimplemented!()` inlined into external caller `0x2e11b00..0x2e13c3a` `8,506 B`).
  - CGU RIP-relative data references: `103` unique `.rodata` VAs (`0x43351a..0x482120`, incl. `0x4671d0` f64 table & 79 `AwsName` literals), `23` unique `.data.rel.ro` VAs (`0x6410ce8..0x64c24e0`), `4` `.got` VAs, and `STATIC_CONFIG` `LazyLock` at `0x64f06c0`.
  - Per `docs/SCOPE.md`, `constants` `identity` remains honestly `false` until whole-ELF / cross-CGU / unmodified `z_vendor/serde_json` + `memchr 2.7.x` closure is achieved.

## Verification Commands

```bash
cd research/work-items/RE-015-node115-stream-f-async-and-rpc-logic-byte-matches && sha256sum -c MANIFEST.sha256
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-015-node115-stream-f-async-and-rpc-logic-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_f_async_and_rpc_logic_byte_matches_115 -v
```
