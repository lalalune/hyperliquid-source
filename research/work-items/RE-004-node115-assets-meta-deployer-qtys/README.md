# RE-004: Node #115 `perp_meta`, `spot_meta` Deployer Fee Share, and `qtys` Clamped `f64` Scaling

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `assets` (`l1/src/perp_meta.rs`, `l1/src/spot_meta.rs`, `l1/src/qtys/mod.rs`)
- **Implementation**: `src/node115-assets/src/{meta,qtys,lib}.rs`

## Scope and Method

This packet binds 13 complete, FDE-bounded `.text` functions (`1,883 B` total), 9 `.data.rel.ro` relocated panic `Location` records, 3 `.rodata` deployer-fee error strings, the `.rodata` `POW10_F64` table at `0x91b7c0`, and 3 IEEE-754 clamp constants directly to node #115 and mirrors their exact control flow and boundary conditions in `src/node115-assets`.

## Directly Observed Binary Evidence

### 1. `l1/src/perp_meta.rs` (`0x3d19800`, `0x50bea90`, `0x50beb30`)
- **`0x3d19800..0x3d19868` (104 B)**: Splits `asset` by `10_000` (`0x346dc5d63886594b >> 11`), checks `pdi == self.pdi` and `local < self.universe.len()` (panic `l1/src/perp_meta.rs:163:38` at `0x64768a8`), reads `sz_decimals` at `universe[local] + 0x1d` (stride `0x20`), enforces `sz_decimals <= 6` (panic `l1/src/perp_meta.rs:287:28` at `0x6478258`), and returns `6 - sz_decimals`.
- **`0x50bea90..0x50beb2f` (159 B)**: Same `pdi`/bounds/`sz_decimals < 7` checks, returning `(raw_px as f64) / POW10_F64[6 - sz_decimals]` via `.rodata` `0x91b7c0`.
- **`0x50beb30..0x50bebba` (138 B)**: Short-circuits `raw_sz == 0 -> 0.0` (`test rdi, rdi; je`) before metadata lookup; otherwise divides `(raw_sz as f64)` by `POW10_F64[sz_decimals]` at `0x91b7c0`.

### 2. `l1/src/spot_meta.rs` Lookups & Decimal Scaling (`0x50be9e0`, `0x3c47660`, `0x3c47ae0`, `0x3c49df0`, `0x3d1a2c0`, `0x3c49360`, `0x3c4b280`, `0x3c4b1a0`)
- **`0x50be9e0..0x50bea85` (165 B)**: Single-price spot conversion `raw_px as f64 / POW10_F64[quote.wei_decimals - base.sz_decimals]`, panicking at `spot_meta.rs:590:25`, `119:33`, or `1055:9`.
- **`0x3c47660..0x3c4769a` (58 B)**: Reads `token_infos[token]` (stride `0x158`) `spots` slice (`+0x58` ptr, `+0x60` len) and returns `Option<Spot>` (`Some(spots[0])` if non-empty).
- **`0x3c47ae0..0x3c47b59` (121 B)**: Scans `token_infos[base].spots` for a `spot_infos[spot]` (stride `0x20`) whose quote token (`+0x08`) equals `quote_token`.
- **`0x3c49df0..0x3c49e6a` (122 B)**: Specialized USDC (`Token(0)`) spot predicate (`cmp qword ptr [r9 + r10 + 8], 0`).
- **`0x3d1a2c0..0x3d1a314` (84 B)**: Resolves `spot_infos[spot]` (`+0x08`) into `token_infos[quote]` name slice (`+0x38` ptr, `+0x40` len).
- **`0x3c49360..0x3c49433` (211 B)**: Computes `10u64.checked_pow(tokens[0].wei_decimals - tokens[base].sz_decimals)` via unrolled binary exponentiation (`10`, `10^2`, `10^4`, `10^8`, `10^16`), panicking on underflow (`1055:9`) or pow overflow (`1074:69`).
- **`0x3c4b280..0x3c4b30c` (140 B)**: Computes `TokenSpec::wei_per_sz = 10u64.checked_pow(wei_decimals - sz_decimals)` (panic `1206:57`).
- **`0x3c4b1a0..0x3c4b274` (212 B)**: Computes `raw_sz.checked_mul(token.wei_per_sz())` (`mul rcx; setno sil`).

### 3. `l1/src/spot_meta.rs` Deployer Trading Fee Share (`0x2c58880..0x2c58947`, 199 B)
- Bounds-checks `token_idx < token_infos.len()` (panic `l1/src/spot_meta.rs:125:37` at `0x64768f0`).
- Rejects `new_share_e5 > 100_000` (`0x186a0`) with `Err(0xee)` pointing to `.rodata` `0x7bc1d5` (`"deployer trading fee share cannot be more than 100%"`, 51 B).
- Reads `old_share = token_infos[token_idx] + 0x118`.
- **Legacy Mainnet rule** (`token_idx <= 195` (`0xc3`) and `byte [rsi + 0xb9a] == 3`):
  - If `old_share == 0`, allows setting `new_share_e5`.
  - Else if `old_share <= new_share_e5`, rejects with `.rodata` `0x7bc3ac` (`"deployer trading fee share cannot increase"`, 42 B).
  - Else if `new_share_e5 == 0`, rejects with `.rodata` `0x7bc389` (`"cannot reset legacy token fee share"`, 35 B).
  - Else writes `new_share_e5` and returns `Ok(0x1a2)`.
- **Non-legacy / non-Mainnet**: requires `new_share_e5 < old_share`, else rejects with `.rodata` `0x7bc3ac`.

### 4. `l1/src/qtys/mod.rs` Clamped `f64` Scaling (`0x46a6aa0..0x46a6b4a`, 170 B)
- Checks `raw >= 0` (`test rdi, rdi; js`), panicking at `l1/src/qtys/mod.rs:847:1` (`0x6493638`) on negative inputs.
- Multiplies `(raw as f64) * factor`; non-finite products (`|x| > f64::MAX`) map to `0.0`.
- Clamps finite values to `[-2^63, 2^63]` (`0x459808`, `0x459360`), converts via `cvttsd2si`, saturates values `> 0x43dfffffffffffff` (`0x458e50`) to `i64::MAX`, and clamps `NaN` or `<= 0` to `0`.

## Inferences and Open Scope

- Field names (`sz_decimals`, `wei_decimals`, `deployer_trading_fee_share`, `MAINNET_CHAIN_TAG = 3`) are inferred from `.rodata` error strings, sibling `RE-004` evidence, and instruction semantics; full `TokenInfo` (`0x158` B) serialization layout beyond the verified offsets remains out of scope for this packet.
- This packet extends `assets` behavioral coverage and does not by itself claim the full `identity` gate.
