# RE-007-node115-spot-clearinghouse-accounting

## Scope
Binary-backed reconstruction of the core `l1/src/spot_clearinghouse` state machine in Linux x86-64 `hl-node` #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`), implemented in pure-std `#![forbid(unsafe_code)]` Rust in `src/clearinghouse/src/spot_clearinghouse.rs` with zero external crates.io dependencies.

## Observed Binary Evidence (Node #115)

### 1. Anchored FDEs (9 FDEs, 12,360 B total)
| FDE | Start VA | End VA | Size (B) | Role |
|---:|---|---|---:|---|
| `#66488` | `0x3bf5120` | `0x3bf5fb3` | 3,731 | `validate_genesis_supply_and_hyperliquidity` (`100M` lots min, `1%` Hyperliquidity min exempting `"HYPE"`, `no_hyperliquidity` zero check, `[0xff; 20]` system address, exact max supply) |
| `#66499` | `0x3bfa400` | `0x3bfa80f` | 1,039 | `validate_token_genesis_update` (`<= 1000` blacklist batch limit `0x3e8`, mutual exclusion with balance updates, blacklist conflict check) |
| `#66500` | `0x3bfa810` | `0x3bfa90d` | 253 | `validate_token_before_genesis` (token bounds `0xfa`, USDC `token == 0` rejection, `token_to_max_supply` duplicate check `0xf9`) |
| `#66501` | `0x3bfa910` | `0x3bfac09` | 761 | `SpotBalance::apply_delta` (`l1/src/spot_clearinghouse/types.rs:159:50`: checked total debit, saturating hold debit, saturating total credit, proportional `entry_ntl` with `0x028f5c28f5c28f5c` guard) |
| `#66504` | `0x3bfb650` | `0x3bfbeee` | 2,206 | `distribute_to_existing_token_holders` (`existing_token_max_supply * 1e-6` dust threshold `0x459130`, `max_clawback_frac = 0.01` `0x458e48`) |
| `#66510` | `0x3bfd020` | `0x3bfd340` | 800 | `SpotClearinghouse::fmt` (`Debug` struct layout map: `meta +0x10`, `user_states +0x370`, `daily_exchange_scaled_and_raw_vlms +0x4d0`, `token_to_genesis +0x4f0`, `token_to_max_supply +0x510`, `token_fees_collected +0x530`, `evm_transfer_escrows +0x5b0`, `spot_dusting_opted_out_users +0x5c8`) |
| `#66512` | `0x3bfd3c0` | `0x3bfdb3c` | 1,916 | `reconcile_pro_rata_distribution` (sort holders, non-zero total check, pro-rata pass via `0x3d5e540`, deficit top-up to index 0, `max_clawback_frac` excess trim, final checked-sum invariant `0x433b5c`) |
| `#69259` | `0x3d5e540` | `0x3d5e817` | 727 | `compute_pro_rata_allocations` (`l1/src/spot_clearinghouse/spot_clearinghouse.rs:959:98`: `0.0 <= ratio <= 1.01` `0x4590b8`, `min_alloc_wei` filter, checked running-total overflow error `0x444ed0`) |
| `#69050` | `0x3d4e560` | `0x3d4e8ff` | 927 | `SpotFillDeltaAccumulator::record_fill` (`l1/src/spot_clearinghouse/cl_trait.rs:940,995,1003,1015,1023,1031`: 128-bit scaled base/quote credit/debit + primary/secondary/builder fee accumulation) |

### 2. Observed Constants & Error Literals
- Hyperliquidity address at `.rodata 0x7baea9`: `[0xff; 20]` (20 bytes of `0xff`).
- `"HYPE"` 4-byte little-endian check at `0x3bf56da`: `cmpl $0x45505948, (%rax)` exempting `"HYPE"` from the 1% Hyperliquidity minimum.
- `100_000_000` lots minimum (`0x5f5e100`) at `0x3bf5188`.
- `1000` blacklist update batch limit (`0x3e8`) at `0x3bfa429`.
- `entry_ntl` proportional scale ceiling (`0x028f5c28f5c28f5c` = `u64::MAX / 100`) at `0x3bfaab3`.
- IEEE-754 `f64` constants in `.rodata`: `1e-6` (`0x459130`), `0.01` (`0x458e48`), `1.01` (`0x4590b8`), `+inf` (`0x459010`), `2^63` (`0x459360`), `2^64` (`0x459090`), `next_down(2^64)` (`0x458d58`).
- Error literals in `.rodata 0x7baebd..0x7bb199`, `0x444ed0`, `0x433b5c`, `0x4424b7` (all pinned with exact VAs and byte lengths in `evidence.json`).
- Panic `Location` structs in `.data.rel.ro`: `0x6479c20` (`spot_clearinghouse.rs:959:98`), `0x6476690` (`types.rs:159:50`), and `0x6479c50..0x6479cc8` (`cl_trait.rs:940,995,1003,1015,1023,1031`).

## Inferences & Open Unknowns
- **Inference**: In `#66512` (`0x3bfd3c0`), `0x3bfda1f` calls a slice sort on `(Address, Wei)` elements; we model deterministic descending-balance tie-broken-by-address ordering so index 0 receives any rounding shortfall.
- **Open Unknowns**:
  - Full `l1/src/spot_clearinghouse/impl_outcome.rs` (`0x3bf2be0`, 6,222 B) outcome settlement / fallback outcome validation and `spot_dusting` sweep (`0x46ef710`) remain for subsequent slices.
  - Byte-for-byte identity compilation of `SpotClearinghouse` methods is not claimed by this behavioral packet.

## Verification
- `sha256sum -c MANIFEST.sha256`
- `PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-007-node115-spot-clearinghouse-accounting`
- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_spot_clearinghouse_accounting_115 -v`
- `CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=/home/shaw/Work/hyperliquid-source/work/target/risk-exchange cargo +1.95.0 test --offline --locked --manifest-path src/clearinghouse/Cargo.toml` (debug & `--release`) and `clippy --all-targets -- -D warnings`.
