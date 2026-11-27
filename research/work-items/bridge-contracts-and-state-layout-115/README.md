# `bridge`: Node #115 Canonical Arbitrum Contract Registry & `Bridge2` State Layout / Balance Guard

- **Component ID**: `bridge` (Stream F, `RE-011` / `RE-015`)
- **Target Artifact**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, 105,896,032 bytes)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Crate Extended**: `src/bridge/` (`src/bridge/src/contracts.rs`, `src/bridge/src/state.rs`, zero `Cargo.toml`/`Cargo.lock` changes)
- **Claim Status**: All ELF virtual addresses, `.rodata` contract address strings, `.data.rel.ro` panic `Location` records, `.eh_frame` FDE extents, and x86-64 instruction bytes are **static observations** from the authenticated node #115 ELF (never executed). No acceptance gate is modified by this packet.

## Observations

### 1. Canonical Arbitrum Contract Registry (`0x154d390..0x154e96a`)

The 5,594-byte registry initializer at `0x154d390..0x154e96a` embeds four Arbitrum contract keys and checksummed 20-byte addresses directly from `.rodata` `0x466e9f..0x466f7b`, and falls back to `{}/contract_addresses/{}.json` (`.rodata` `0x432654` referenced at `0x154db44`) for non-embedded chains (`Sandbox` / `Local`):

| Registry Key | Key `.rodata` VA | Address `.rodata` VA | Embedded Address |
|---|---:|---:|---|
| `Usdc2Mainnet` | `0x466e9f` | `0x466eab` | `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` |
| `Bridge2Mainnet` | `0x466ed5` | `0x466ee3` | `0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7` |
| `Bridge2Testnet` | `0x466f0d` | `0x466f1b` | `0x08cfc1B6b2dCF36A1480b99353A354AA8AC56f89` |
| `Usdc2Testnet` | `0x466f45` | `0x466f51` | `0x1baAbB04529D43a73232B713C0FE471f7c7334d5` |

### 2. All 6 `l1/src/bridge2.rs` Panic `Location`s, 15-Field Schema & Balance Underflow Guard

All 6 `.data.rel.ro` `R_X86_64_RELATIVE` panic `Location` records referencing `l1/src/bridge2.rs` (`0x43e33a`) resolve to 5 FDEs:

| `Location` VA | Line:Col | Referencing FDE | Size |
|---:|---:|---|---:|
| `0x648c418` | `145:95` | `0x44d83f0..0x44d8583` | 403 B |
| `0x648c430` | `147:68` | `0x44d83f0..0x44d8583` | 403 B |
| `0x648c3d0` | `177:40` | `0x44d7b10..0x44d7f07` | 1,015 B |
| `0x648c3e8` | `178:45` | `0x44d7b10..0x44d7f07` | 1,015 B |
| `0x648c400` | `385:43` | `0x44d7f10..0x44d83e2` | 1,234 B |
| `0x64bc8a8` | `477:60` | `0x5afedf0..0x5aff7bd` & `0x5aff7c0..0x5b0018d` | 2,509 B each |

- `0x44d83f0..0x44d8583` registers the withdrawal request in `[rbx + 0x80]` via `0x3689150`, checks Ok tag `0x1a2` (`0x44d8448`), subtracts withdrawal amount `r14` from `Bridge2::bal` (`[rbx + 0x1c8]` at `0x44d8454..0x44d8464`), and on borrow (`jb 0x44d8511`) panics with `"bridge2 withdrawal balance bug"` (`.rodata` `0x7d30e2`, len 30).
- Complete 15-field `struct Bridge2` schema string block sits contiguously at `.rodata` `0x7d09dd..0x7d0a99` (plus `dvpd` at `0x459f80` and `last_pruned_deposit_block_number`), with deposit-ring stride `0x68` (104 B) at `0x44d7d4b`.

## Reproduce

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/bridge/Cargo.toml
CARGO_BUILD_JOBS=4 cargo clippy --offline --locked --manifest-path src/bridge/Cargo.toml --all-targets -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bridge_contracts_and_state_115 tests.test_bridge_crate_115 -v
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/bridge-contracts-and-state-layout-115
```
