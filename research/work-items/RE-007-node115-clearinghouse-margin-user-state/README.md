# RE-007: node #115 clearinghouse margin tables, position margin summary, user available margin, and spot existing-token balances

- Component ID: `risk` (`RE-007`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: **observation** for all 7 FDE ranges, `.rodata` float/string constants, 5-arm jump table `0x7cf4cc`, instruction anchors, and 10 relocated panic `Location` records; **inference** for reconstructed Rust API names (`MarginTable`, `MarginTableStore`, `MarginRequirement`, `position_margin_summary`, `available_margin_isolated`, `compute_existing_token_balances`) implemented in `src/clearinghouse/src/margin_user_state.rs`.
- Remaining unknowns: full cross-margin account fold callee `0x3beb980` internals beyond the `PositionRiskRecord` fold (`0x3bebd70`), and dynamic initialization body of the built-in `< 50` static margin table array at `0x64fb8f0`.

## Evidence (node #115 static observations)

| Function VA (size) | Observed #115 behavior & anchors |
| --- | --- |
| `0x38b4e20..0x38b4f7a` (346 B) | `MarginTable::first_tier`: dual-rep BTree/ring container lookup; panics at `l1/src/clearinghouse/margin_table.rs:139:57` (`0x646e380`) if empty. |
| `0x38b54b0..0x38b55f3` (323 B) | `MarginTable::maintenance_margin`: highest tier with `lower_bound <= ntl` (panics at `margin_table.rs:145:105`, `0x646e368`); computes `(ntl / (2 * max_leverage)).saturating_sub(maintenance_deduction)` (`0x38b5596`: `addl %esi, %esi`), saturating to `0` on borrow with `l1/src/qtys/impl_ntl.rs:26:1` alert (`0x646e398`). |
| `0x38b5300..0x38b54a9` (425 B) | `MarginTable::backstop_margin`: exact integer `2/3` maintenance formula `((2 * ntl) - (4 * max_leverage * maintenance_deduction)) / (6 * max_leverage)` (`0x38b53f0`: `leal (,%rcx,4), %eax`; `0x38b541c`: `addl %ecx, %ecx; leaq (%rcx,%rcx,2), %rcx`), saturating `2 * ntl` and subtraction with `impl_ntl.rs:26:1` alerts. |
| `0x3c43150..0x3c432f4` (420 B) | `MarginTableStore::get`: `cmpl $0x32, %edx` (`0x3c4315d`) dispatches `id < 50` to static built-in leverage tables at `0x64fb8f0 + id * 32` and `id >= 50` to the custom BTree/ring map at `+0x30`. |
| `0x448b800..0x448b967` (359 B) | `Position::margin_summary`: checks `mark_px >= 0` and `mark_px.checked_mul(szi)` (`l1/src/clearinghouse/position.rs:204:57`, `0x648be00`), dispatches 5-arm jump table `0x7cf4cc` (`0=Zero`, `1=Initial`, `2=Maintenance`, `3=Backstop`, `4=InitialCapped`), and splits Cross (`tag=0`) vs Isolated (`tag=1`, `account_value = raw_usd.saturating_add(ntli)` with `impl_ntl.rs:70:1`, `margin_used = account_value.max(0)`). |
| `0x3beb700..0x3beb972` (626 B) | `UserState::available_margin`: isolated mode (`mode == 1`) indexes `oracle_pxs[asset % 10_000]` (`0x3beb8b1`: magic `0x346dc5d63886594b >> 11`; `oracle.rs:433:18`, `0x6476558`), calls `0x448b800`, asserts isolated output (`user_state.rs:89:60`, `0x6476570`), rejects negative margin (`qtys/mod.rs:847:1`, `0x6476588`), and returns `account_value.saturating_sub(margin_used)` (`impl_ntl.rs:70:1`, `0x64765a0`). |
| `0x3d5e540..0x3d5e817` (727 B) | `SpotClearinghouse::compute_existing_token_balances`: asserts `0.0 <= ratio <= 1.01` (`0x4590b8` = `1.01_f64`; `spot_clearinghouse.rs:959:98`, `0x6479c20`), maps `+inf -> 0`, saturates to `u64::MAX`, filters `< min_balance`, and on `total_wei` `u64` overflow emits tag `0x109` (`0x3d5e772`) with `"error while computing existing token balances total_wei={} marginal_wei={}"` (`0x444ed0`). |

## Reproduce

```sh
python3 tools/artifacts.py verify
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_clearinghouse_margin_user_state_115
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-007-node115-clearinghouse-margin-user-state
(cd research/work-items/RE-007-node115-clearinghouse-margin-user-state && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/clearinghouse/Cargo.toml
```
