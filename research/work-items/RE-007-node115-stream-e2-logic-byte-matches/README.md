# RE-007: Node #115 Stream E2 Non-Visitor Business-Logic First-Party Compiled-Byte FDE Matches

## Target Binary
- **Path**: `artifacts/node/115/hl-node` (Linux x86-64 ELF)
- **SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Compiler**: `rustc +1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes` (`#![forbid(unsafe_code)]`, 0 external deps)

## Direct Observations (Binary-Backed)
`lib.rs` live-compiles **16 strictly disjoint non-visitor business-logic `.text` FDEs (4,645 B total, 0 non-relocation mismatches = 100.00% relocation-qualified)** across 4 Stream E2 components, with zero overlap against `research/byte-windows.json` (Wave 3) and all sibling `*-byte-matches*` / `constants-gate-closure` packets:

| Component | Windows | Bytes | Business-Logic FDEs |
|---|---:|---:|---|
| `exchange` | 8 | 2,545 B | `BoleReserve::utilization_bps` (`0x36a08b0`, 312 B, pure `u128` ceil/floor/magic-div), `BoleReserve::utilization_f64` (`0x36a09f0`, 309 B), 18-variant compact state/ADL/PM JSON `visit_str` (`0x286d0c0`/`0x4682fd0`, 480 B × 2), `UserAbstraction` 11-alias JSON `visit_str` (`0x23c5330`/`0x3bdd050`, 285 B × 2), `BoleReserve` 9-field compact JSON `visit_str` (`0x288f7f0`/`0x4699090`, 197 B × 2) |
| `action-wire` | 2 | 1,174 B | `OrderKind` 22-alias JSON `visit_str` (`0x25d03a0`/`0x4450a20`, 587 B × 2: `limit`, `market`, ..., `closeForVaultWithdrawal`, `spotDustConversion`, `borrowLendLiquidation`, `twapSlice`, `trailingStopMarket`) |
| `l1-shared` | 3 | 574 B | `NodeRole` 4-variant JSON `visit_str` (`0x1543ce0`/`0x57c3c90`, 234 B × 2) & `NodeRole::fmt` `Display` (`0x1553730`, 106 B) |
| `risk` | 3 | 352 B | 9-tag compact Clearinghouse/Bole JSON `visit_str` (`0x2886380`/`0x4693600`, 137 B × 2) & `OracleKind::fmt` `Display` (`0x3d66320`, 78 B: `Spot`, `Mark`, `ExternalPerp`) |

## Verification
- `PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-node115-stream-e2-logic-byte-matches/verify.py --self-test`
- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_e2_logic_byte_matches_115 -v`
- `(cd research/work-items/RE-007-node115-stream-e2-logic-byte-matches && sha256sum -c MANIFEST.sha256)`

## Scope & Unknowns
- Relocation-normalized FDE identity only covers the 16 non-visitor Stream E2 functions above (4,645 B); larger stateful `BoleReserve::accrue_interest`, `Clearinghouse`, and `Exchange` handlers remain behavior-tested in `src/exchange` and `src/clearinghouse` without full relocation-normalized byte identity.
