# RE-004: Node #115 `FeeSchedule` Protocol Solvency Floor (`0x36a58d0`), Rate Bounds (`0x36a1c20`), and Volume Gates (`0x2c2cb40`, `0x2c59480`)

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `fees` (`l1/src/fees/fees.rs`, `l1/src/raw_vlm.rs`, `l1/src/scaled_vlm.rs`)
- **Implementation**: `src/node115-fees/src/{solvency,tiers,lib}.rs`

## Scope and Method

This packet binds 8 complete node #115 `.text` FDEs (`9,568 B` total), 11 `.rodata` IEEE-754 `f64` constants, and the 6-entry `.rodata` protocol fee scale table at `0x79d4d0..0x79d500` directly to `artifacts/node/115/hl-node`, and wires the recovered solvency floor and volume gates into `src/node115-fees`.

## Directly Observed Binary Evidence

### 1. `FeeSchedule` Validator (`0x36a1c20..0x36a31ff`, 5,599 B) & Chain Iterator (`0x36e1b90..0x36e1bff`, 111 B)
- Calls `0x36e1b10` (`fee-window-scan`, `l1/src/fees/fees.rs:259:57`) at `0x36a283a` for descending monotonicity.
- Enforces staking-tier bounds `5.0` (`0x4593d0`) and `0.5` (`0x459490`) at `0x36a2a0d..0x36a2a23`, and discount/proportion bounds `[0.0, 1.0]` (`0x4592b0`) at `0x36a2a47..0x36a2d8b`.
- Enforces taker rate bounds (`0x36a2ef3..0x36a2f56`): `0.0 <= r <= 0.001` (`0x459af0`), and if `r > 0.0` then `r >= 0.0001` (`0x459b50`).
- Enforces maker rate bounds (`0x36a2ff1..0x36a3059`, iterating via `0x36e1b90`): `|r| <= 0.001` (`0x459af0` with sign mask `0x450180`), and if `r > 0.0` then `r >= 0.0001` (`0x459b50`).
- Invokes `0x36a58d0` twice (`0x36a2e1c` & `0x36a2eba`) — once for perp and once for spot.

### 2. Protocol Net-Fee Solvency Floor (`0x36a58d0..0x36a5d40`, 1,136 B) & Bridge (`0x457cbf0..0x457ccac`, 188 B)
- Computes:
  - `min_add = min(vip_adds.last().unwrap_or(base_add), mm_adds.last().unwrap_or(base_add))`
  - `min_cross = vip_crosses.last().unwrap_or(base_cross)`
  - `after_stake = min_cross * (1.0 - max_staking_discount)`
  - `net_cross_referral = after_stake * (1.0 - referral_discount) * (1.0 - referrer_keep)`
  - `net_cross_trial = after_stake * (1.0 - trial_discount)`
- Verifies `net_cross.mul_add(scale, min_add * scale) >= 5e-6` (`0x459388`) for **both** referral and trial paths across all **6 protocol fee scale multipliers** `[1.0, 0.2, 6.0, 0.1, 2.0, 40.0]` stored contiguously at `.rodata 0x79d4d0..0x79d500` (and referenced individually at `0x4592b0`, `0x4592d8`, `0x458e08`, `0x4593e0`, `0x458eb0`, `0x4597a8`).

### 3. Volume-Gated Action Thresholds (`0x2c2cb40..0x2c2cf4a`, 1,034 B; `0x2c59480..0x2c5995b`, 1,243 B; `0x294bcd0`, 163 B; `0x29dfea0`, 94 B)
- **`0x2c2cb40`**: calls `0x2a8ae60` (`raw_vlm` fold), compares against `0x5f5e100` (`100_000_000`, returning `Err(0x11d, raw_vlm as f64 / 100.0)` when below), checks `+5` days lookahead (`0x2c2cc6d`), and caps at `10` per UTC day (`cmp [rax], 9` at `0x2c2ce90`).
- **`0x2c59480`** (with helpers `0x294bcd0` & `0x29dfea0`): folds `0x2a8ae60` across master + subaccounts with `qtys/impl_ntl.rs:682` saturating addition and compares against `0x77359400` (`2_000_000_000` -> `Err(0x119)` when `<=`).

## Inferences and Open Scope

- Semantic labels (`trial_discount`, `PROTOCOL_FEE_SCALES` regime meanings) are inferred from caller offsets and sibling `RE-004` evidence; `0x3ddba40` (downstream of `0x457cbf0`) remains outside this packet's scope.
- This packet extends `fees` behavioral coverage and does not by itself claim the full `identity` gate.
