# RE/AgentTracker: Agent Tracking, Authorization Keys & Delegation Bounds (node #94)

- Component ID: `RE/AgentTracker` (`l1/src/agent_tracker.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91774280 bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference lead `references/can1357-hl/l1/agent_tracker.rs`
  (diagnostic lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status: verified observation (static disassembly, panic records, rodata bypass table, and instruction opcodes)
- Scope included: 3 FDEs totaling 4,032 bytes, 1 panic record, 3 bypass addresses, 13 opcode controls, and status codes (390, 81, 83, 86, 87, 89)
- Scope excluded: binary execution (static disassembly only), live transaction processing or network consensus

## Problem and Result

Hyperliquid node #94 manages delegate agents (main agent and extra agents) for subaccounts and API trading:
1. **FDE 1 (`0x3421e20..0x34224e0`, 1,728 B)**: `AgentTracker::save_extra_agent`
   - Validates name length bounds (`1 <= len <= 32`). Emits `ERR_EXTRA_AGENT_INVALID_NAME` (`83` / `0x53`) at `0x3421e58`.
   - Checks capacity tier bounds: `2 * tier + 3`. Emits `ERR_TOO_MANY_EXTRA_AGENTS` (`87` / `0x57`) at `0x3422368`.
   - Checks duplicate agent assignment across users. Emits `ERR_EXTRA_AGENT_ALREADY_USED` (`86` / `0x56`) at `0x342232a`.
   - Emits `STATUS_OK` (`390` / `0x186`) at `0x3422314`.
2. **FDE 2 (`0x34224e0..0x34227e0`, 768 B)**: `AgentTracker::delete_extra_agent`
   - Verifies agent existence. Emits `ERR_EXTRA_AGENT_DOES_NOT_EXIST` (`89` / `0x59`) at `0x3422761`.
   - Success transition emits `STATUS_OK` (`390` / `0x186`) at `0x342273d`.
   - Mapped panic record at `0x3422793` referencing `0x56eb400` (`l1/src/agent_tracker.rs:138:48`).
3. **FDE 3 (`0x3423240..0x3423840`, 1,536 B)**: `AgentTracker::save_main_agent`
   - Zero-address filter via vector instructions `pxor xmm0, xmm0` (`0x342325d`) and `pcmpeqb` mask check (`0x342328b`).
   - If zero address, removes existing main agent, pushes pending removal with `now_ms + 2000`, and returns `OK` (`390` at `0x3423400`).
   - Adds 2-second grace period chrono delta (`mov edx, 2` at `0x3423654`).
   - Checks agent ownership via SIMD address comparison (`pcmpeqb` at `0x342374e..0x342377b`). If mismatch, emits `ERR_SAVE_AGENT_UNEXPECTED` (`81` / `0x51`) at `0x3423783`.
   - On valid update, returns `OK` (`390` / `0x186`) at `0x3423748`.

4. **Hardcoded Extra-Agent Capacity Bypass Addresses (`.rodata` at `0x59c0a8`)**:
   - `0x59c0a8`: `0x677d831aef5328190852e24f13c46cac05f984e7`
   - `0x59c0bc`: `0x3c83a5cae32a05e88ca6a0350edb540194851a76`
   - `0x59c0d0`: `0x4dbf394da4b348b88e8090d22051af83e4cbaef4`

Total size across 3 FDEs is 4,032 bytes.

## Reproduce

Working directory: repository root. Pure static disassembly; zero binary execution.

```sh
# Generate evidence packet and run test suite
python tools/agent_tracker_static.py
pytest tests/test_agent_tracker_static.py

# Verify SHA-256 manifest integrity
(cd research/work-items/agent-tracker-94 && sha256sum -c MANIFEST.sha256)
```

## Evidence

### 1. FDE Extents and Ground Truth

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| :--- | :--- | :--- | ---: | :--- |
| `save_extra_agent` | `0x3421e20..0x34224e0` | `0x34214e0..0x3421ba0` | 1,728 B | `8eaa9e7ad9d98ce2cbdd63fbf11ad80ba666074b76ae53c336de14d82d198469` |
| `delete_extra_agent` | `0x34224e0..0x34227e0` | `0x3421ba0..0x3421ea0` | 768 B | `c5bfcc90f8d24091103d0160e32f755a9cec438f5e7e4ff093c89c7e45bb16b1` |
| `save_main_agent` | `0x3423240..0x3423840` | `0x3422240..0x3422840` | 1,536 B | `41ac306659c62b6370665c33a1fa30518a06a2556dec3706aa1bd2efc51b223c` |

### 2. Mapped Panic Records

| Panic Record VA | File | Line:Column | Referenced By |
| :--- | :--- | :--- | :--- |
| `0x56eb400` | `l1/src/agent_tracker.rs` | 138:48 | FDE 2 (`0x3422793`) |

### 3. Hardcoded Capacity Bypass Table

| Index | ELF VA | Address |
| ---: | :--- | :--- |
| 0 | `0x59c0a8` | `0x677d831aef5328190852e24f13c46cac05f984e7` |
| 1 | `0x59c0bc` | `0x3c83a5cae32a05e88ca6a0350edb540194851a76` |
| 2 | `0x59c0d0` | `0x4dbf394da4b348b88e8090d22051af83e4cbaef4` |

## Results and Limitations

- 3 FDE extents (4,032 B total), 1 source panic record, 3 bypass addresses, 13 opcode controls, and status codes (390, 81, 83, 86, 87, 89) verified with 100% agreement against node #94.
- No captured binary execution performed.
