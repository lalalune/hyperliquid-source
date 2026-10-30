# RE-007: Position Margin Mode Dispatch and Table Cutoff (node #94)

- Component ID: RE-007 (Risk / Clearinghouse / Position margin modes; `l1/clearinghouse/*`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91,774,280 bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference lead `references/can1357-hl/l1/clearinghouse/position.rs`
  (unlicensed reference lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status:
  - Observation for byte-level disassembly of FDE `0x3717480..0x37179c5`, rodata jump table `0x59742c`,
    cutoff comparison `cmp ebp, 0x32`, and panic location records in `.data.rel.ro`.
  - Inference for high-level enum variant names (`PositionMarginMode`), struct field layout names (`PositionRecord`),
    and cross-margin liquidation context.
  - Unresolved items are listed under Results and Limitations.
- Scope included and excluded:
  - Included:
    - FDE extent: `0x3717480..0x37179c5` (1,349 bytes; file offset `0x3716480..0x37169c5`).
    - Rodata jump table: `0x59742c` (5 modes, signed int32 relative displacement table).
    - Hardcoded cutoff comparison: `cmp ebp, 0x32` (`0x32` = 50 in decimal) controlling built-in single tier vs custom table.
    - Two panic records in `.data.rel.ro`:
      - `0x56f1fa8`: line 204, column 57 -> `/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/position.rs` (61 bytes).
      - `0x56f21d8`: line 279, column 86 -> `/home/ubuntu/hl/code_Mainnet/l1/src/perp_meta.rs` (48 bytes).
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
sha256sum -c research/work-items/RE-007-position-margin-modes-94/MANIFEST.sha256

# Optional human cross-check: disassemble the FDE extent
objdump -d -M intel --start-address=0x3717480 --stop-address=0x37179c5 artifacts/node/94/hl-node
```

## Evidence

Coordinates are ELF virtual addresses (VA). `.rodata` VA equals file offset; `.text` VA = file offset + 0x1000;
`.data.rel.ro` VA = file offset + 0x2000.

### 1. Observed Binary Facts (Ground Truth)

#### A. Function Boundary & Pre-Conditions
- FDE Range: `0x3717480..0x37179c5` (1,349 bytes), file offset `0x3716480..0x37169c5`.
- SHA-256 of extracted bytes: `6f0049a71097c33ddc9aa2b3e1e51b98cbbdadcbc07a0034c7c91b16da13ee3d`.
- Sign guard on price input (`rdx`):
  ```asm
  3717491: test rdx, rdx
  3717494: js   3717925   # branches to panic at 0x56f1fa8 (line 204:57)
  ```
- Signed integer overflow check on position notional:
  ```asm
  37174a0: imul r14, QWORD PTR [rsi+0x10]  # szi * oracle_px
  37174a5: jo   3717925                   # branches to panic on overflow
  ```
- Absolute notional computation:
  ```asm
  37174ae: mov   r15, r14
  37174b1: neg   r15
  37174b4: cmovs r15, r14                 # r15 = abs(signed_notional)
  ```

#### B. Jump Table Dispatch (`0x59742c`)
- Indexed jump at `0x37174bb`:
  ```asm
  37174b8: movzx  eax, cl
  37174bb: lea    rcx, [rip-0x317ff96]   # 0x59742c
  37174c2: movsxd rdx, DWORD PTR [rcx+rax*4]
  37174c6: add    rdx, rcx
  37174c9: jmp    rdx
  ```
- Jump table entries at rodata VA `0x59742c` (5 entries, 20 bytes):
  `5c 04 18 03  9f 00 18 03  f3 00 18 03  8a 01 18 03  c4 00 18 03`
  - Mode 0: `rel = +51,905,628` (`0x0318045c`) -> Target VA: `0x3717888`
  - Mode 1: `rel = +51,904,671` (`0x0318009f`) -> Target VA: `0x37174cb`
  - Mode 2: `rel = +51,904,755` (`0x031800f3`) -> Target VA: `0x371751f`
  - Mode 3: `rel = +51,904,906` (`0x0318018a`) -> Target VA: `0x37175b6`
  - Mode 4: `rel = +51,904,708` (`0x031800c4`) -> Target VA: `0x37174f0`

#### C. Built-in Table Cutoff (`0x32` = 50)
- In Mode 2 (`0x371751f`) and Mode 3 (`0x37175b6`), selector is checked:
  ```asm
  371751f: mov ebp, DWORD PTR [r12+0x38]
  3717524: cmp ebp, 0x32                  # 50 decimal
  3717527: jae 371764d                    # traverses custom BTreeMap table
  ```
- Fall-through (`ebp < 50`): Constructs a single-tier descriptor on the local stack with max leverage `ebp`.
- Branch (`ebp >= 50`): Traverses BTreeMap located at `[r9+0x38]` using key `ebp`. If absent, branches to panic `0x56f21d8` at `0x3717964`.

#### D. Static Source References
- Panic Location `0x56f1fa8` in `.data.rel.ro`:
  - `path`: `/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/position.rs` (VA `0x1ead59`, 61 bytes).
  - `line`: 204, `column`: 57.
- Panic Location `0x56f21d8` in `.data.rel.ro`:
  - `path`: `/home/ubuntu/hl/code_Mainnet/l1/src/perp_meta.rs` (VA `0x1f56ec`, 48 bytes).
  - `line`: 279, `column`: 86.

---

### 2. Inferred Role Models (Separated from Binary Proof)

The following role assignments are inferred based on search leads from `references/can1357-hl/l1/clearinghouse/position.rs`:
- Function role: `compute_position_margin_requirement(position, oracle_px, mode, cap_leverage, tables)`.
- Mode enum mapping (`PositionMarginMode`):
  - Mode 0 (`0x3717888`): `NoRequirement` (returns requirement 0).
  - Mode 1 (`0x37174cb`): `SimpleMaxLeverage` (`notional / max_leverage`).
  - Mode 2 (`0x371751f`): `Initial` (tier initial requirement via selector).
  - Mode 3 (`0x37175b6`): `Maintenance` (tier maintenance requirement via selector).
  - Mode 4 (`0x37174f0`): `CappedLeverage` (`notional / min(max_leverage, cap_leverage)`).
- Cutoff semantic: `BUILTIN_MARGIN_TABLE_CUTOFF = 50`. Selectors 0..49 define synthetic single-tier tables where max leverage equals the selector ID. Selectors 50+ map to user- or governance-defined custom margin tables.

## Implementation and comparison

Not yet implemented in clean-room Rust.
An independent clean-room Rust implementation must:
1. Handle all 5 modes according to the jump table targets.
2. Replicate the negative price check and signed notional overflow guard.
3. Mirror the selector cutoff: `< 50` synthesizes a single-tier table, `>= 50` queries table storage.
4. Distinguish cross margin (where position margin requirement is 0 at position level) from isolated margin.
5. Be independently authored under MIT license without copying from unlicensed reference repositories.
6. No runtime or binary equivalence claim is made.

## Results and limitations

- Metrics (explicit denominators):
  - FDE extent validated: 1/1 (1,349 bytes).
  - Jump table entries verified: 5/5 (100%).
  - Table cutoff threshold verified: 1/1 (`0x32` / 50).
  - Panic locations linked to source files: 2/2 (100%).
- Limitations & Inferences:
  - Higher-level risk engine caller context (e.g. cross-margin solvers, liquidation engines) is excluded.
  - Node #115 and visor differences are not evaluated.
- No progress gate is requested.

Next question: How does `aggregate_position_margin_summary` iterate across user positions and apply cross-margin netting against isolated margin reserves?
