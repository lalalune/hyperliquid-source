# RE-007: Node #115 Complete `dex-registry` (`l1/src/dex_registry/*`) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `dex-registry` (`l1/dex_registry/*` — Stream E2 / `RE-007`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `dex-registry` source file (**3/3**: `l1/src/dex_registry/clearinghouses.rs`, `l1/src/dex_registry/dex_registry.rs`, `l1/src/dex_registry/perp_dex.rs`), **every** `.data.rel.ro` `Location` struct (**5/5**), **every** `.text` FDE referencing those `Location` structs (**373/373 unique FDEs = 1,177,785 bytes**, spanning the standalone `PerpDexes::get`/`get_mut` (`0x4201750`, `0x42017d0`), `Clearinghouses::get`/`get_mut` (`0x2753a70`, `0x446b3f0`), zipped cross-DEX scans (`0x2c774c0`, `0x560f890`, `0x2cf9fd0`, `0x2cfa1e0`), and all inlined `l1` callers), and **20 disjoint HIP-3/DexRegistry business & codec FDEs** (`14,248 bytes`, **393 unique FDEs / 1,192,033 bytes** combined).

## Verified `dex-registry` Routines & Data Layouts

1. **Checked `Pdi` Indexing & Zipped Registry Scans (`l1/src/dex_registry/{perp_dex,clearinghouses,dex_registry}.rs`)**:
   - `PerpDexes::get` (`0x4201750`, `perp_dex.rs:29`) & `PerpDexes::get_mut` (`0x42017d0`, `perp_dex.rs:34`): bounds check `cmp 0x10(%rdi), %rsi` (`0x4201755`, `0x42017d5`) with `PerpDex` stride `0x200` (`shl $0x9, %rbx` at `0x420175e`).
   - `Clearinghouses::get` (`0x2753a70`, `clearinghouses.rs:11`) & `Clearinghouses::get_mut` (`0x446b3f0`, `clearinghouses.rs:17`): bounds check on `Vec<Clearinghouse>` with `Clearinghouse` stride `0x510` (`add $0x510, %r15` at `0x2c775a3`).
   - `DexRegistry` zipped `(perp_dexes, clearinghouses)` scan (`0x2c774c0`, `0x560f890`, `dex_registry.rs:37`): verifies parallel length equality (`cmp 0x10(%r15), %rbx` at `0x2c774dc`) and scans slots in `Pdi` order.
2. **Main / HIP-3 State Envelope, Limits, Schema & Disabled-State Codecs**:
   - Exact `DexKind` (`"Main"` -> `0x0009`, `"Hip3"` -> `0x0109`) visitors (`0x2b94d80`, `0x4440220`, `0x5469f10`).
   - Dynamic-arity `DexMetadata` envelope encoder (`0x2bc2700`: 4-field `Main` or 3..=6-field `Hip3` with optional `hip3_backstop_liquidator_state`, `ss`, `df`).
   - `Hip3Limits` 6-field codec (`0x2bc1190`), `Hip3Schema` 7-field codec (`0x2bc17c0`), `Hip3State` 5-field codec (`0x2bc0900`), and `Hip3DisabledRecord` (`0x2bc06a0`, `src/node115-hip3-disabled-record` + `src/node115-hip3-disabled-state-codec`).
3. **23-Variant `Hip3DeployAction` & Sub-Deployer Authorization / `disableDex` Transition**:
   - All 23 `Hip3DeployAction` tags (`0..=7` `{"hip3Star": ...}` via `0x2bc6150`, `8..=22` string variants via `0x2bc7610`), `sub_deployers` sequence/element writers (`0x2ce6f90`, `0x2205280`, `0x22927f0`, `0x2299050`, `0x2eabb50`).
   - Selector-scoped sub-deployer permission membership (`0x469e170`, `0x35bf6c0`, `0x4552d70`, selector `0x13` = `DisableDex`) and `DexRegistry::set_disabled_state` (`DisabledState::UserDisabled` / `ValidatorDisabled`) in `src/dex-registry/src/registry.rs`.

## Complete `dex-registry` Acceptance Inventory

- **Mapped**: 3/3 `dex-registry` source files, 5/5 `Location` structs, 373/373 Location-referencing FDEs (`1,177,785 B`) + 20/20 disjoint business/codec FDEs (`14,248 B`) = **393 unique FDEs (`1,192,033 B`)** verified against `work/index/node-115-fde.tsv` and raw ELF bytes.
- **Built & Behavior**: Integrated `src/dex-registry` (`#![forbid(unsafe_code)]`, 0 external deps, wired into `src/exchange` and `src/hl-node`) combines both registered `dex-registry` micro-crates (`node115-hip3-disabled-state-codec`, `node115-hip3-disabled-record`) with full `DexRegistry<C>`, `PerpDexSlot`, `DexMetadata`, `Hip3Limits`, `Hip3Schema`, `Hip3State`, `Hip3DeployAction`, `SubDeployers`, and `set_disabled_state` implementations and behavioral tests.
- **Compiled-Byte Identity (honest status)**: `identity` remains `false`; compiled-byte proofs currently cover `RE-007-node115-stream-e2-byte-matches` (`dex-registry` visitor FDEs).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-node115-dex-registry-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_dex_registry_closure_115 -v
(cd research/work-items/RE-007-node115-dex-registry-closure && sha256sum -c MANIFEST.sha256)
```
