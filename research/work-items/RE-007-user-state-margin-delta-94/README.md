# RE-007: UserState Margin Aggregation and Delta Calculation (node #94)

- Component ID: RE-007 (Risk / Clearinghouse / UserState margin; `l1/clearinghouse/*`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91,774,280 bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference lead `references/can1357-hl/l1/clearinghouse/user_state.rs`
  (unlicensed reference lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status:
  - Observation for byte-level disassembly of FDE 1 (`0x37d7360..0x37d77d8`) and FDE 2 (`0x37d77e0..0x37d79e0`),
    BTreeMap position traversal call sites, arithmetic saturation sequences, rodata panic strings, and source location records in `.data.rel.ro`.
  - Inference for high-level struct field names (`UserState`, `AggregateMarginSummary`, `PositionRecord`)
    and full clearinghouse account management state.
  - Unresolved items are listed under Results and Limitations.
- Scope included and excluded:
  - Included:
    - FDE 1 extent: `0x37d7360..0x37d77d8` (1,144 bytes; file offset `0x37d6360..0x37d67d8`).
    - FDE 2 extent: `0x37d77e0..0x37d79e0` (512 bytes; file offset `0x37d67e0..0x37d69e0`).
    - Rodata strings:
      - `0x59c1f2`: `called \`Result::unwrap()\` on an \`Err\` value`
      - `0x59b52a`: `internal error: entered unreachable code`
    - Four static source location records in `.data.rel.ro`:
      - `0x56f3a48`: line 87, column 60 -> `/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/user_state.rs` (VA `0x1f7c8c`).
      - `0x56f3a30`: line 197, column 18 -> `/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/oracle/oracle.rs` (VA `0x1f685d`).
      - `0x56f3a60`: line 843, column 1 -> `/home/ubuntu/hl/code_Mainnet/l1/src/qtys/mod.rs` (VA `0x1e65a2`).
      - `0x56f3a78`: line 62, column 1 -> `/home/ubuntu/hl/code_Mainnet/l1/src/qtys/impl_ntl.rs` (VA `0x1e0394`).
  - Excluded:
    - Zero execution of captured binary (static disassembly and offline arithmetic verification only).
    - No live network or live node execution.
    - No claim on full liquidation engine or cross-margin position state solver.
    - Node #115 and visor targets excluded.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64 / Windows, Python 3.12+, GNU objdump 2.42+.
The binary is only read offline; nothing is executed.

```sh
# Verify authentic node #94 input digest
python3 -c "import hashlib; assert hashlib.sha256(open('artifacts/node/94/hl-node','rb').read()).hexdigest() == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'"

# Verify packet integrity against sha256 manifest
sha256sum -c research/work-items/RE-007-user-state-margin-delta-94/MANIFEST.sha256

# Optional human cross-check: disassemble the two FDE extents
objdump -d -M intel --start-address=0x37d7360 --stop-address=0x37d77d8 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x37d77e0 --stop-address=0x37d79e0 artifacts/node/94/hl-node
```

## Evidence

Coordinates are ELF virtual addresses (VA). `.rodata` VA equals file offset; `.text` VA = file offset + 0x1000;
`.data.rel.ro` VA = file offset + 0x2000.

### 1. Observed Binary Facts (Ground Truth)

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| --- | --- | --- | ---: | --- |
| `aggregate_position_margin_summary` | `0x37d7360..0x37d77d8` | `0x37d6360..0x37d67d8` | 1,144 B | `bd411fb7d53621828e36bb7577ca7f61d5fca0aeade4478ed1a2057dbc505e49` |
| `margin_delta_for_asset` | `0x37d77e0..0x37d79e0` | `0x37d67e0..0x37d69e0` | 512 B | `06773ad410d87661980d9af32e9b05c3e94a0ea3cf9eaf89c04577bd8b3c22e2` |

#### A. Position Margin Aggregation (`0x37d7360..0x37d77d8`)
- Iteration over user position map:
  - Traverses the `BTreeMap<AssetId, PositionRecord>` stored at offset `+0x08` of the user state via allocator helper calls (`call [rip+0x1f9e3c0]` at `0x37d73f2`).
  - Isolated position filtering: Reads `byte ptr [position]` (offset `+0x00` of `PositionRecord`). If `include_isolated == false` (flag in `sil`) and position is isolated (`test byte ptr, byte ptr; jne`), the loop skips the position.
- Per-position margin computation:
  - Invokes `compute_margin_requirement_by_mode` via `call [rip+0x1f9bdbb]` at `0x37d73b7` with `position`, asset price from oracle, mode, leverage cap, and margin tables.
- Aggregation accumulators:
  - Accumulates `signed_equity_or_value`: Adds `signed_margin_after` using `saturating_add` (detected via overflow traps and clamped additions).
  - Accumulates `margin_requirement_sum`: Adds `effective_margin` using `saturating_add`.
  - Accumulates `abs_notional_sum`: Adds `notional`.
  - Isolated margin tracking: If position is active/isolated (`summary.active`), adds `previous_margin` to `isolated_margin_sum`.

#### B. Margin Delta and Surplus Calculation (`0x37d77e0..0x37d79e0`)
- Single asset branch (`isolated == true` in `sil`):
  - Looks up specific asset in `positions_by_asset` BTreeMap (`0x37d7800..0x37d7870`).
  - If absent: returns 0.
  - If present: computes margin requirement via `call [rip+0x1f9b8ea]` at `0x37d7888`.
  - Asserts position summary is active: if inactive (`test al, al; je 0x37d79ba`), panics with string `0x59b52a` (`internal error: entered unreachable code`) and source record `0x56f3a48` (`user_state.rs:87:60`).
  - Returns `signed_margin_after.saturating_sub(computed_requirement)`.
- Cross-account branch (`isolated == false`):
  - Invokes `aggregate_position_margin_summary` with `include_isolated = false` (`call 0x37d7360` equivalent at `0x37d793a`).
  - Overflow guard on aggregate margin: Compares `margin_requirement_sum` against `i64::MAX` (`movabs rdx, 0x7fffffffffffffff; cmp rax, rdx; ja 0x37d795d`).
  - On overflow: panics with string `0x59c1f2` (`called \`Result::unwrap()\` on an \`Err\` value`) and source record `0x56f3a60` (`qtys/mod.rs:843:1`).
  - Return value: `signed_equity_or_value.saturating_sub(margin_requirement_sum as i64)`.

---

### 2. Inferred Role Models (Separated from Binary Proof)

The following role assignments are inferred based on search leads from `references/can1357-hl/l1/clearinghouse/user_state.rs`:
- Function roles:
  - `UserState::aggregate_position_margin_summary(&self, include_isolated, mode, cap_leverage, oracle_prices, tables)`
  - `UserState::margin_delta_for_asset(&self, isolated, asset, mode, cap_leverage, oracle_prices, tables)`
- Struct roles:
  - `UserState`: Contains `signed_account_value: SignedNtl` at offset `+0x00`, `positions_by_asset: BTreeMap<AssetId, PositionRecord>` at offset `+0x08`, and `open_position_count: u64` at offset `+0x20`.
  - `AggregateMarginSummary`: Returned structure holding 4 64-bit scalar fields (`signed_equity_or_value`, `margin_requirement_sum`, `abs_notional_sum`, `isolated_margin_sum`).

## Implementation and comparison

Not yet implemented in clean-room Rust.
An independent clean-room Rust implementation must:
1. Replicate BTreeMap iteration over active positions, skipping isolated positions when `include_isolated == false`.
2. Apply `saturating_add` on signed equity and unsigned margin requirement sums.
3. In `margin_delta_for_asset`, enforce the panic when an isolated query encounters an inactive summary.
4. Enforce the `i64::MAX` overflow check on `margin_requirement_sum` when calculating cross-account margin delta.
5. Be independently authored under MIT license without copying from unlicensed reference repositories.
6. No runtime or binary equivalence claim is made.

## Results and limitations

- Metrics (explicit denominators):
  - FDE extents validated: 2/2 (1,144 B and 512 B).
  - Panic string references identified: 2/2 (`0x59c1f2`, `0x59b52a`).
  - Static source records mapped: 4/4 (`user_state.rs`, `oracle.rs`, `qtys/mod.rs`, `qtys/impl_ntl.rs`).
- Limitations & Inferences:
  - Complete user order state, funding rate application, and liquidation triggers are excluded.
  - Node #115 and visor differences are not evaluated.
- No progress gate is requested.

Next question: How does `available_margin_after_reserved` deduct order-wire reserved margin from the cross-account delta computed here?
