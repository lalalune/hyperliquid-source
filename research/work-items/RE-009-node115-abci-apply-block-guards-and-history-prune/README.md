# RE-009: Node #115 `AbciEngine::apply_block` Pre-Execution Guards, History `split_off` Cutoff, & `BlockReader` Entry Points

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Work item**: `RE-009` (`abci` + `storage`)
- **Methodology**: Static ELF/`.text`/`.rodata` analysis only; no captured binary execution.

## Binary-Proven Facts

1. **`l1/src/abci/engine.rs` `apply_block` (`0x5a04e40..0x5a065f8`) 6 ordered pre-execution guards (`0x5a04ec3..0x5a04f59`)**
   1. **Hardfork / freeze guard (`0x5a04ec3..0x5a04ee4`)**: loads `Option<u64>` hardfork height from `[S + 0x10e8]` (tag `1` = `Some`) and `[S + 0x10f0]` (`hf_h`), compares against `S.height` (`[S + 0x28]`): `hf_h < S.height` traps (`0x5a062d4`); `hf_h == S.height` panics with `"assertion failed: !self.state.is_frozen()"` (`0x93a65e` via `0x5a06235`).
   2. **Round monotonicity (`0x5a04eea..0x5a04eed`)**: `round <= parent_round` panics with `"assertion failed: round > parent_round"` (`0x93a61b` via `0x5a0621d`).
   3. **Parent round equality (`0x5a04ef3..0x5a04eff`)**: `[S + 0x30] != parent_round` panics (`0x5a0624a`).
   4. **Parent timestamp equality (`0x5a04f05..0x5a04f23`)**: 128-bit `[S + 0x18..+0x28] != (block.parent_time_hi, block.parent_time_lo)` panics (`0x5a0626d`).
   5. **Action-count equality (`0x5a04f29..0x5a04f4c`)**: header action count `!=` payload action count panics (`0x5a06290`).
   6. **Feature-version gate (`0x5a04f52..0x5a04f59`)**: `byte [S + 0xb9a] != 3` panics with `"assertion failed: features_ok"` (`0x93a641` via `0x5a062b6`).

2. **`ctx + 0x400` local raw-root history pruning before `end_root_selector` (`0x5a05ea1..0x5a05fc9`)**
   - When `[ctx + 0x10] != 0`, computes `cutoff = [ctx + 0x18].saturating_add(1)` (`inc rax; mov rcx, -1; cmovne rcx, rax` at `0x5a05ead..0x5a05ebc`), calls `BTreeMap::split_off(&cutoff)` (`0x4de5ad0` at `0x5a05ee3`) on `ctx + 0x400`, frees entries `< cutoff`, and installs the survivor map before calling `0x5a07ec0` (`end_root_selector`, logging `"computed abci digest at height="` `0x44c994`).

3. **`db/src/block_reader.rs` method entry points**
   - `0x2a191e0..0x2a195a7`: `BlockReader::block` (`0x2a19258` -> `.rodata 0x43f132`).
   - `0x2a0acc0..0x2a0b327`: `BlockReader::range_query_inclusive` (`0x2a0aeeb` -> `.rodata 0x449de1`).

## Reproducibility

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-abci-apply-block-guards-and-history-prune/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_abci_apply_block_guards_115
```
