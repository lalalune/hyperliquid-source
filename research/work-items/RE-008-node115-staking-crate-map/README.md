# RE-008: Node #115 Staking Source Map & Validator Registration / Profile / Commission / Unregister Lifecycle

## Scope & Target

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`)
- **SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `staking` (`RE-008`)
- **Integrated Rust crate**: `src/node115-staking` (`src/validator_lifecycle.rs`)
- **Static analysis only**: No captured binary execution; all strings, `.rela.dyn` pointers, `.data.rel.ro` `core::panic::Location` records, and `.text` instructions are read statically.

## Direct Binary Observations

### 1. Staking / Validator Source-Path & `Location` Inventory

All 4 observed staking-related diagnostic source files in node #115 `.rodata`, all 12 `.data.rel.ro` `Location` records pointing to them via `R_X86_64_RELATIVE` relocations, and all referencing `.text` FDEs are verified live by `verify.py`:

- `l1/src/c_staking/jailing.rs` (2 Locations: lines 38, 199; 2 FDEs)
- `l1/src/staking.rs` (4 Locations: lines 185, 239, 243, 325; 3 FDEs)
- `l1/src/exchange/stake_requirement.rs` (4 Locations: lines 5, 64; 7 FDEs)
- `l1/src/action/vote_global.rs` (2 Locations: line 1504; 3 FDEs)

### 2. Validator Lifecycle & Profile Validation FDEs

| Function | FDE Extent | Size | Verified Semantics |
| --- | --- | --- | --- |
| `c_validator_action_handler` | `0x2c77640..0x2c77ba5` | 1,381 B | Dispatches 3-arm `CValidatorAction` (arm `2` rejected with `0x92`; allowlist check when `[exchange+0x10e4] == 0` -> `0x98`). For `Register`: rejects `chain == Local` (`0x92`), rejects `initial_wei >= 0xccccccccccccccc` (`0x154`), if `initial_wei != 0 \|\| min_self != 0` rejects `disable_delegations` (`0x10c`), missing native token (`0x10a`), `initial_wei < min_self` (`0x145`), and balance `< initial_wei` (`0x10b`); invokes slot `0x64e7f10 -> 0x3c3d480`. |
| `c_staking_validator_lifecycle` | `0x3c3d480..0x3c3f412` | 8,082 B | Slot `0x64e7f10`. Enforces max 1,000 registered validators (`[rsi+0xe8] <= 0x3e7`, else `0x96`), unregister zero-delegation guard (`[rbx+0x20] == 0`, else `0x144`), unknown validator (`0x95`), per-validator signer/IP cooldown (`0x135`), and global signer/IP cooldown (`0x136`). |
| `c_staking_validate_profile` | `0x3c3a700..0x3c3adf5` | 1,781 B | Checks private-IP exemption set and delegates profile validation to slot `0x64e9650 -> 0x469b540`. |
| `validator_profile_validate` | `0x469b540..0x469b725` | 485 B | Slot `0x64e9650`. Enforces global IPv4 (`0x12f` unless exempt: rejects `0/8`, `10/8`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24` except `.9`/`.10`, `192.0.2/24`, `192.168/16`, `198.51.100/24`, `203.0.113/24`, `255.255.255.255`), `1 <= name.len() <= 50` (`0x130`), `1 <= description.len() <= 1000` (`0x131`), and commission `0..=10_000` bps (`0x2710`) with increase cap `<= 100` bps (`< 0x65`, 1%) (`0x132`). |
| `register_active_validator` | `0x4225b80..0x4225c74` | 244 B | Inserts new active validator into `[state+0x10]`, rejecting duplicates with `0x97` (`Validator already registered`). |

## Inferences & Remaining Unknowns

- **Inferences**:
  - The IPv4 check in `0x469b540..0x469b6e8` corresponds to standard RFC 6890 non-global IPv4 exclusions (including the `192.0.0.9`/`192.0.0.10` PCP/Traversal exceptions).
- **Unknowns (explicitly not claimed)**:
  - Unstaking withdrawal queue creation and 7-day completion drain (`[state+0x268]` writers) remain outside this packet.
  - Epoch reward distribution and commission payout arithmetic remain outside this packet.

## Reproduction

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-staking-crate-map/verify.py
(cd research/work-items/RE-008-node115-staking-crate-map && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node115_staking_crate_map -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/node115-staking/Cargo.toml
```
