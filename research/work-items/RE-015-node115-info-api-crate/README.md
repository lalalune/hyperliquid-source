# RE-015: Node #115 `info_server` (`info-api`) 55-Variant Schema & Integrated Crate

- **Component ID**: `info-api` (Stream F, `RE-015`)
- **Target Artifact**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, 105,896,032 bytes)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Crate**: `src/info-api/` (`#![forbid(unsafe_code)]`, 0 external crates.io dependencies)
- **Claim Status**: All ELF virtual addresses, `.rodata` byte spans, `.data.rel.ro` `R_X86_64_RELATIVE` tables, `.eh_frame` FDE bounds, jump-table entries, and immediate map-entry counts are **static observations** from the authenticated node #115 ELF (never executed). Type/enum identifiers and module groupings in `src/info-api/` are clean-room MIT reconstructions grounded in those observations. No acceptance gate is modified by this packet.

## Observations

### 1. Complete `info_server/src/*.rs` Inventory (7 Source Paths, 43 Panic `Location`s)

All 7 `info_server/src/*.rs` strings observed in `.rodata` and all 43 `R_X86_64_RELATIVE` panic `Location` records referencing them in `.data.rel.ro`:

| Source Path | `.rodata` VA | Panic `Location` Count | Anchored FDEs |
|---|---:|---:|---|
| `info_server/src/abci_state_info_handler.rs` | `0x432b83` | 33 | `0x2968470`, `0x2968810`, `0x2968b40`, `0x2968e70`, `0x29698d0`, `0x2a6a7e0`, ... |
| `info_server/src/f_types/position.rs` | `0x44acf9` | 2 | `0x2c7fd80..0x2c80666`, `0x514d080..0x514d953` |
| `info_server/src/handle_request.rs` | `0x449e6a` | 3 | `0x2e3ed10..0x2e414d3` (lines 30, 49, 120) |
| `info_server/src/handler.rs` | `0x431acb` | 1 | `0x2e3ed10..0x2e414d3` (line 41) |
| `info_server/src/router.rs` | `0x431ab1` | 1 | `0x2e3ed10..0x2e414d3` (line 45) |
| `info_server/src/save_l4_snapshots.rs` | `0x4318ae` | 2 | `0x273bb10..0x273bd19`, `0x273bd20..0x273bf29`, `0x22b6490` (+3 sibling monomorphizations) |
| `info_server/src/user_ip.rs` | `0x43ae5b` | 1 | `0x2e3ed10..0x2e414d3` (line 28) |

### 2. Complete 55-Variant `InfoRequest` Wire Schema (`0x643a9e0`, `0x2744200`, `0x273bf30`)

- **Variant Table**: `.data.rel.ro` `0x643a9e0..0x643ad50` holds 55 `(ptr, len)` string slices referenced by the serde variant matcher at `0x2744200..0x2744bfa` (`lea r8, [0x643a9e0]; mov ecx, 0x37`).
- **Serializer & Field Schema**: `0x273bf30..0x273ebc0` (11,408 B) dispatches all 55 discriminants (`0..=54`) through jump table `0x5f45d0`, serializing each variant as an internally-tagged JSON map with tag key `"type"` (`0x45a144`), exact `serialize_map` entry count in `edx` (`1..=4`), and exact field names (including snake_case `only_use_db` on `settledOutcome` and `settledQuestion`, `ignorePortfolioMargin` on `spotClearinghouseState`, `includeDebugDetails` on `spotMeta`, and `request`/`outPath`/`includeHeightInOutput` on `fileSnapshot`).
- **`FileSnapshotRequest` Sub-Enum**: `.data.rel.ro` `0x643ad50..0x643ad70` holds 2 variants (`referrerStates` at `0x5f65b2`, `l4Snapshots` at `0x5f65c0`), followed by `"variant index 0 <= i < 2"` at `0x643ad70`, matched by `0x2744c00..0x2744d62`. Adjacent `.rodata` at `0x5f65cb` holds `includeUsers` and `includeTriggerOrders`.

### 3. HTTP Handler, Timing, Future-State & Snapshot-Guard Invariants

- **Endpoint & Labels**: `/info` (`0x605aec`), `Web /info` (`0x605af1`), `handle_request_rate_limiter` (`0x644408`), `not from localhost: ` (`0x4359a1`).
- **Handler Pipeline (`0x2e3ed10..0x2e414d3`)**: Materializes HTTP `200` (`0x2e40830`) and `500` (`0x2e3fdeb`, `0x2e4082b`); times synchronous request dispatch (`0x2ecf9d0`) + response conversion (`0x273bf30`) with `CLOCK_MONOTONIC`, mapping negative or `+inf` durations to `0.0`; retains a dormant `0.014`s (`0x3f8cac083126e979`) inner future gated by `bpl == 0` (`RE-008-info-request-timing-115`, `RE-008-info-user-ip-future-115`).
- **Future & Snapshot-Guard Invariants**: Integrates the `0x2979780` resume-state byte (`0`/`1`/`2`), `0x29698d0` conditional second-query first-stage tag rules (`0..=4`), and `0x2a52620`/`0x2a3ceb0` `S+0x6a8` atomic reader-count guard (`+16`/`-16`, disallowed bit 3, `-16` limit, wake mask `(old & !13) == 18`).

### 4. Integrated Crate (`src/info-api/`)

Joins `node115-json-string-scanner`, `node115-json-error-position`, `node115-replica-response-json`, `node115-risk-candidate-scan`, `global-constants`, and the `node115-position-integer` integer-prefix logic into a single cohesive `#![forbid(unsafe_code)]`, zero-external-dep crate.

## Inferences & Remaining Unknowns

- **Inferred**: Mapping of `InfoRequest` field value Rust types (beyond wire field names and map entry counts) and full ABCI snapshot response JSON payloads for all 55 queries.
- **Unresolved**: Full per-variant ABCI state read & JSON response serializers inside `abci_state_info_handler.rs` and Axum server/router wiring (`node/src/node.rs:225`).

## Reproduce

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/info-api/Cargo.toml
CARGO_BUILD_JOBS=4 cargo clippy --offline --locked --manifest-path src/info-api/Cargo.toml --all-targets -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_info_api_crate_115 -v
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-015-node115-info-api-crate
```

## Perpetual position display values

The public `info_api::position::project_position_values` converts raw post-lookup size,
mark and entry words into four binary64 fields of a position row, before decimal-string
formatting. On the ordinary return path the signed size is divided by the asset's size
scale; the magnitude of the signed mark product and signed PnL both use 1,000,000.
The optional entry price first discards the integer division remainder, then divides by
10 to the power six minus the asset's size decimals. A flat position yields no row, and
a nonzero position with a zero entry word has zero PnL and no entry price.

| Output offset | Value | Producer evidence |
| --- | --- | --- |
| +0, +8 | Optional entry price tag and payload | 0x2c800a2..0x2c800df; 0x2c803e5..0x2c803fd |
| +0x48 | Signed size | input +0x10 at 0x2c7fd94; 0x2c80366..0x2c80387; packed division/store at 0x2c80480 |
| +0x50 | Absolute position value | signed multiply at 0x2c7ff1a; absolute value at 0x2c800df; saved on both division-width paths at 0x2c80105 and 0x2c80199; unsigned conversion and packing at 0x2c8041e..0x2c8044d |
| +0x58 | Unrealized PnL | signed subtraction at 0x2c7ff56, zero-entry alternative at 0x2c7ff95; conversion at 0x2c80397 and scalar division/store at 0x2c80459 and 0x2c80489 |

Both indexed tables and the upper packed lane / scalar micro-dollar divisors are
checked directly against the ELF by `test_position_display_loads_scales_and_output_lanes`.
The retained full instruction export is in
[`RE-001-node115-position-response-entry-quotient`](../RE-001-node115-position-response-entry-quotient/README.md).
The field names are an interpretation of the units and dataflow. The Rust integration
test independently recreates the four quantities in the published ETH example from
Hyperliquid's [perpetual account summary](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint/perpetuals).

The caller supplies a selected asset row with 0–6 size decimals. Account lookup,
risk calculations, other fields and the public HTTP handler remain outside this projection.
