# RE/ActionDelayer: Action Delay Curves, Withdrawal Timing & Status Guards (node #94)

- Component ID: `RE/ActionDelayer` (`l1/src/action_delayer.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91774280 bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference lead `references/can1357-hl/l1/action_delayer.rs`
  (diagnostic lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status: verified observation (static disassembly, panic records, float constants, and instruction opcodes)
- Scope included: 4 FDEs totaling 3,136 bytes, 4 panic records, 19 opcode controls, deterministic delay curve math, and status guard bounds
- Scope excluded: binary execution (static disassembly only), live transaction processing or network propagation

## Problem and Result

Hyperliquid node #94 schedules and throttles withdrawal and order cancellations through deterministic delay curves:
1. **FDE 1 (`0x392fab0..0x392fcc0`, 528 B)**: `deterministic_delay_seconds`
   - Dispatches across Mode 2 (`DeterministicVty`) vs. Mode 1/3 (`DeterministicEma`/Default).
   - Computes normalized volatility power weights `(vty / 10000.0)^exponent`:
     - Exponents `-1.5` (`0x20a388`) with `0.125` multiplier (`0x20a6d8`) for special action kinds.
     - Exponent `-3.0` (`0x20a380`) with `/ 12.0` divisor (`0x20b100`) for action kind 0/5.
     - Exponent `-4.0` with `/ 20.0` divisor for default actions.
   - Clamps raw weight to `[0.0, 1.0]` (`0x20a730`).
   - Scales via curve multipliers:
     - Special curve: `weight * 1.8 + 0.76` (`0x20b108` and `0x20a250`).
     - Default curve: `weight * 1.3 + 0.76` (`0x20adf0` and `0x20a250`).
   - Applies action duration multiplier:
     - Short multiplier `0.2` (`0x20a768`) for frontend actions (`10,000..110,000`) and broadcasters (`>= 100,000,000`).
     - Standard multiplier `0.65` (`0x20a9f8`) for other actions.
2. **FDE 2 (`0x392fcc0..0x3930340`, 1,664 B)**: `ActionDelayer::should_emit_status & note_action_removed`
   - Emits delay status if and only if `status.current.len() > 2` (`0x3930221: cmp QWORD PTR [rsp+0xc8], 0x2; jbe ...`).
   - Mapped panic record `0x570d828` (`/home/ubuntu/hl/code_Mainnet/l1/src/action_delayer.rs:246:73`).
3. **FDE 3 (`0x3930340..0x39304c0`, 384 B)**: `DeterministicEma::serialize`
   - Serializes field descriptors: `num`, `denom`, `decay_duration`, `last_sample_time`, `n_samples`.
   - Mapped panic record `0x570fef0` (`serde_json/src/ser.rs:2004:9`).
4. **FDE 4 (`0x39304c0..0x39306f0`, 560 B)**: `ActionDelayStatusEntry::serialize`

Total size across 4 FDEs is 3,136 bytes.

## Reproduce

Working directory: repository root. Pure static disassembly; zero binary execution.

```sh
# Generate evidence packet and run test suite
python tools/action_delayer_static.py
pytest tests/test_action_delayer_static.py

# Verify SHA-256 manifest integrity
(cd research/work-items/action-delayer-94 && sha256sum -c MANIFEST.sha256)
```

## Evidence

### 1. FDE Extents and Ground Truth

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| :--- | :--- | :--- | ---: | :--- |
| `deterministic_delay_seconds` | `0x392fab0..0x392fcc0` | `0x392eab0..0x392ecc0` | 528 B | `4d5819f68dbd07c9e35dceae4febc6b6f06dd0efb254bf4992e85765e54c51f2` |
| `ActionDelayer::should_emit_status` | `0x392fcc0..0x3930340` | `0x392ecc0..0x392f340` | 1,664 B | `408e8158b4ee6e1c86101d88fc95df7b4e0401d8d15687161b3f370973b94abf` |
| `DeterministicEma::serialize` | `0x3930340..0x39304c0` | `0x392f340..0x392f4c0` | 384 B | `7b29deb99e913a0f05c43cc71a0cb1668eddf4b5347e95771216b0e1a680fb94` |
| `ActionDelayStatusEntry::serialize` | `0x39304c0..0x39306f0` | `0x392f4c0..0x392f6f0` | 560 B | `656e30eb680da0bc9c35a3cca131d21ca3350d69e35c4e44137732e79872749a` |

### 2. Verified Constants in `.rodata`

- `0x20a250`: `0.76` (`MIN_ACTION_DELAY_SECONDS`)
- `0x20a830`: `10000.0` (`VTY_REFERENCE_NOTIONAL`)
- `0x20a730`: `1.0` (weight clamp upper limit)
- `0x20b108`: `1.8` (special curve multiplier)
- `0x20adf0`: `1.3` (default curve multiplier)
- `0x20a768`: `0.2` (short delay multiplier)
- `0x20a9f8`: `0.65` (standard delay multiplier)
- `0x20b100`: `12.0` (action kind 0/5 divisor)
- `0x20a6d8`: `0.125` (special action kind weight multiplier)

### 3. Mapped Panic Records

| Panic Record VA | File | Line:Column | Referenced By |
| :--- | :--- | :--- | :--- |
| `0x570d828` | `l1/src/action_delayer.rs` | 246:73 | FDE 2 (`0x393023d`) |
| `0x566ab58` | `base/src/duration.rs` | 112:13 | FDE 1 (`0x392fc8f`) |
| `0x566ae58` | `base/src/duration.rs` | 124:13 | FDE 1 (`0x392fca8`) |
| `0x570fef0` | `serde_json/src/ser.rs` | 2004:9 | FDE 3 (`0x39304af`) |

## Results and Limitations

- 4 FDE extents (3,136 B total), 4 source panic records, 19 opcode controls, and IEEE-754 delay curve math verified with 100% agreement against node #94.
- No captured binary execution performed.
