# RE/Vaults: Vault Distribution Settlement & Equity Accounting (node #94)

- Component ID: RE/Vaults (`l1/src/vault/mod.rs`, `l1/vault/*`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91774280 bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference lead `references/can1357-hl/l1/vault/mod.rs`
  (unlicensed reference lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status:
  - Observation for byte-level disassembly of 3 FDEs totaling 12,528 bytes:
    - `0x3956320..0x3957bc0` (6,304 B): `apply_distribution`
    - `0x39582c0..0x3958b60` (2,208 B): `verify_equity_distribution`
    - `0x395bdd0..0x395cd80` (4,016 B): `ledger_transition_and_close`
  - Observation for exact static source panic locations in `.data.rel.ro`:
    - `0x570d9a0`: `vault/mod.rs:520:50` (in `0x3956320`)
    - `0x570d9b8`: `vault/mod.rs:528:50` (in `0x3956320`)
    - `0x570d9d0`: `vault/mod.rs:529:79` (in `0x3956320`)
    - `0x570da00`: `vault/mod.rs:626:71` (in `0x39582c0`)
    - `0x570da18`: `vault/mod.rs:621:93` (in `0x39582c0`)
    - `0x570da48`: `vault/mod.rs:742:58` (in `0x395bdd0`)
    - `0x570d858`: `qtys/mod.rs:843:1` (in `0x395bdd0`)
  - Inference for high-level Rust struct models (`VaultEquityRecord`, `VaultState`, `DistributionReceipt`), accounting traits (`VaultLedger`), and rounding formulas.
  - Unresolved items are listed under Results and Limitations.
- Scope included and excluded:
  - Included:
    - Three FDE extents:
      - `0x3956320..0x3957bc0` (6,304 B; file offset `0x3955320..0x3956bc0`).
      - `0x39582c0..0x3958b60` (2,208 B; file offset `0x39572c0..0x3957b60`).
      - `0x395bdd0..0x395cd80` (4,016 B; file offset `0x395add0..0x395bd80`).
    - Numeric bounds and constants:
      - `RAW_NTL_SCALE = 1_000_000` (6 decimal raw notional units).
      - `MIN_LEADER_EQUITY_NTL = 100_000_000` (100.0 notional floor).
      - `MIN_DISTRIBUTION_NTL = 10_000_000` (10.0 notional minimum).
      - `MIN_TOTAL_FRACTION_DENOMINATOR = 1.0e-15`.
      - `MIN_PARTICIPANT_EQUITY_USD = 1.0e-7`.
      - `LEADER_FRACTION = 0.05` (5% leader profit share / allocation constraint).
      - `LEADER_MIN_EQUITY_DIVISOR = 19.0`.
    - Seven mapped panic records in `.data.rel.ro`:
      - 6 in `/home/ubuntu/hl/code_Mainnet/l1/src/vault/mod.rs` (lines 520, 528, 529, 621, 626, 742).
      - 1 in `/home/ubuntu/hl/code_Mainnet/l1/src/qtys/mod.rs` (line 843).
  - Excluded:
    - Zero execution of captured binary (static disassembly and offline structural verification only).
    - No live vault balance mutations or network consensus execution.
    - Node #115 and visor targets excluded.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64 / Windows, Python 3.12+, GNU objdump 2.42+.
The binary is only read offline; nothing is executed.

```sh
# Verify authentic node #94 input digest
python3 -c "import hashlib; assert hashlib.sha256(open('artifacts/node/94/hl-node','rb').read()).hexdigest() == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'"

# Verify packet integrity against sha256 manifest
(cd research/work-items/vault-distribution-94 && sha256sum -c MANIFEST.sha256)

# Optional human cross-check: disassemble the 3 FDE extents
objdump -d -M intel --start-address=0x3956320 --stop-address=0x3957bc0 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x39582c0 --stop-address=0x3958b60 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x395bdd0 --stop-address=0x395cd80 artifacts/node/94/hl-node
```

## Evidence

Coordinates are ELF virtual addresses (VA). `.rodata` VA equals file offset; `.text` VA = file offset + 0x1000;
`.data.rel.ro` VA = file offset + 0x2000.

### 1. Observed Binary Facts (Ground Truth)

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| --- | --- | --- | ---: | --- |
| `VaultState::apply_distribution` | `0x3956320..0x3957bc0` | `0x3955320..0x3956bc0` | 6,304 B | `e906051d49107997465295b776373949df11fe697a958971fb161f2c40b6cc4e` |
| `VaultState::verify_equity_distribution` | `0x39582c0..0x3958b60` | `0x39572c0..0x3957b60` | 2,208 B | `f00a04dbeeb78350b5ddcf6d8d656fb2e89d6f1da17ac841121995bc6d1f6a81` |
| `VaultState::ledger_transition_and_close` | `0x395bdd0..0x395cd80` | `0x395add0..0x395bd80` | 4,016 B | `6ae643627e0d2ac717138cc0438e829f02e65999cdfaaf2e893156f85622bd47` |

#### A. Distribution Math & Profit Splitting
- Iterates over equity records stored in an ordered tree (BTreeMap at vault state offset `+0x38`).
- Computes gross participant equity `gross = trunc(share * total)`.
- Principal is protected: `principal = min(deposited_ntl, gross)`. Profit is `max(0, gross - principal)`.
- Fee deduction for non-leaders: `fee = trunc(profit * fee_fraction)`.
- Participant net credit: `net = trunc(share * amount) - fee`.
- Unallocated residual (`amount - sum(distributed)`) is credited to the vault leader address.
- If total vault equity drops to 0, sets vault state flag `closed = true` (`0x395bdd0`).

#### B. Mapped Source Panic Records
- `0x570d9a0`: `vault/mod.rs:520:50` (bounds check on participant credit calculation).
- `0x570d9b8`: `vault/mod.rs:528:50` (underflow / overflow check on ledger credit).
- `0x570d9d0`: `vault/mod.rs:529:79` (leader fee credit bounds).
- `0x570da00`: `vault/mod.rs:626:71` (equity verification delta check).
- `0x570da18`: `vault/mod.rs:621:93` (participant equity floor guard).
- `0x570da48`: `vault/mod.rs:742:58` (residual settlement check).
- `0x570d858`: `qtys/mod.rs:843:1` (quantity saturation guard).

---

### 2. Inferred Role Models (Separated from Binary Proof)

The following role models are inferred based on search leads from `references/can1357-hl/l1/vault/mod.rs`:
- Type layouts:
  - `VaultEquityRecord`: `share: f64`, `deposited_ntl: u64`, `net_ntl: i64`, `last_update_id: UpdateId`.
  - `DistributionReceipt`: `participant_deltas: BTreeMap<Address, RawNtl>`.
- Mode selector:
  - Leader excess mode (`requested_ntl >= MIN_DISTRIBUTION_NTL`, capped by `leader_excess_withdrawable_ntl`).
  - Pro-rata liquidation / withdrawable distribution mode.

## Implementation and comparison

Not yet implemented in clean-room Rust.
An independent clean-room Rust implementation must:
1. Enforce exact participant pro-rata distribution with fee haircuts on profit only.
2. Direct all unallocated dust / rounding residuals to the leader account.
3. Handle closed-vault state transitions when remaining equity reaches zero.
4. Be independently authored under MIT license without copying from unlicensed reference repositories.
5. No runtime or binary equivalence claim is made.

## Results and limitations

- Metrics (explicit denominators):
  - FDE extents validated: 3/3 (12,528 B total).
  - Panic source records mapped: 7/7 (6 in `vault/mod.rs` + 1 in `qtys/mod.rs`).
- Limitations & Inferences:
  - Deposit and withdrawal paths outside these 3 FDEs are excluded.
  - Multi-vault child aggregation logic is evaluated separately.
  - Node #115 and visor differences are not evaluated.
- No progress gate is requested.

Next question: How does `apply_vault_withdraw` calculate the fee settlement when withdrawing partial principal?
