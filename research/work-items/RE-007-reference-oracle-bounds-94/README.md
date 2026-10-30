# RE-007 (Part 4): Reference Oracle Price Distance & Bounds (Node #94)

## Target
- **Artifact**: `artifacts/node/94/hl-node`
- **SHA-256**: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- **Size**: `91,774,280` bytes

## Scope
Static analysis and deterministic offline verification of the reference oracle price distance check:
- **Function**: `Oracle::check_reference_oracle_distance`
- **FDE Range**: `0x3261290..0x326151a` (650 bytes)
- **FDE SHA-256**: `06b3ad64581f03dd4e592c5fe4d2fe58638186c0c27043db4169ffbe1f4e20e4`

## Mathematical Invariants
1. **Relative Distance Formulation**:
   ```
   distance = |(price / ref_price) - 1.0|
   ```
   - Compiled via:
     - `movq %r8, %xmm4` (integer tick price)
     - `punpckldq %xmm0, %xmm1; subpd %xmm2, %xmm1; addsd %xmm1, %xmm3` (u64 to f64 conversion)
     - `divsd %xmm0, %xmm3` (`price / ref_price`)
     - `addsd %xmm3, [0x20a278]` (`- 1.0`)
     - `andpd %xmm3, [0x202ed0]` (`fabs` sign mask `0x7fffffffffffffff`)
2. **Tolerance Comparison**:
   ```
   ucomisd (%rdx), %xmm3
   setbe %cl
   ```
   Passes if `distance <= max_distance` or `bypass != 0`.
3. **Error Reporting**:
   - If distance exceeds tolerance: emits `Price moved too far from reference oracle` (`0x58466d`) with source location `0x56df7b0` (`oracle.rs:627:35`).
   - If reference oracle is missing: emits `Missing reference oracle` (`0x584655`).
4. **Asset Exemptions**:
   - `perp_type == 3`: Assets `152` (`0x98`) and `159` (`0x9f`) are exempt from missing reference oracle requirement.
   - `perp_type != 3`: Assets `125` (`0x7d`) and `135` (`0x87`) are exempt from missing reference oracle requirement.

## Panic Records Verified
- `0x56df7b0`: `/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/oracle/oracle.rs:627:35`
- `0x56f21c0`: `/home/ubuntu/hl/code_Mainnet/l1/src/perp_meta.rs:194:38`
- `0x56f3350`: `/home/ubuntu/hl/code_Mainnet/l1/src/perp_meta.rs:319:28`

## Deterministic Verification
- Zero captured binary execution.
- Offline static analysis over mapped ELF image.
- 13 unit tests passing in `tests/test_reference_oracle_static.py`.
