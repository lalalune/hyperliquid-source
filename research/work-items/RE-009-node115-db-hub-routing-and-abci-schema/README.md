# RE-009: Node #115 `DbHub` 29-Kind 3-Shard Routing & ABCI State/Tracker/Engine Schema

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Work item**: `RE-009` (`storage` + `abci`)
- **Methodology**: Static ELF/`.text`/`.rodata`/`.data.rel.ro`/`.rela.dyn` analysis only; no captured binary execution.

## Binary-Proven Facts

1. **`db/src/db_hub.rs:51` 29-kind 2-byte prefix table & 3-shard routing (`0x3d4c7c0..0x3d4d420` live & `0x57c58d0..0x57c6530` slow)**
   - `.data.rel.ro` `0x6479df0..0x6479ed8` holds 29 contiguous `R_X86_64_RELATIVE` pointers to the 29 2-byte prefixes packed at `.rodata` `0x7bd4ed..0x7bd527`:
     `cA, lu, nf, bi, Ps, uf, aT, rh, et, fH, aH, oh, ts, th, up, ua, se, gP, de, dr, vb, Et, En, Eb, so, sq, Ea, Ec, Es`.
   - Exact shard selection bitmasks (identical in live `0x3d4c7e5`/`0x3d4c825` and slow `0x57c58f5`/`0x57c5935`):
     - **Shard 0 (`r13b = 0`)**: bitmask `0x031f_feff` (22 kinds: indices `0..=7, 9..=20, 24, 25`).
     - **Shard 1 (`r13b = 1`)**: bitmask `0x00e0_0100` (4 kinds: `8` `et`, `21` `Et`, `22` `En`, `23` `Eb`).
     - **Shard 2 (`r13b = 2`)**: fallthrough indices `26, 27, 28` (`Ea`, `Ec`, `Es` — EvmState DB; `mov r13b, 2` at `0x3d4cacb`).
   - Core-tier boundary `cmp bpl, 0x14` (`0x3d4c7fa`): kinds `0..=20` (`cA..vb`) vs `21..=28` (`Et..Es`).
   - Both live (`0x3d4c899`) and slow (`0x57c59a9`) index `0x6479df0[kind * 8]` for the 2-byte prefix and descend the `BTreeMap<u8, Db>` keyed by shard byte (`r13b`).

2. **`l1/src/abci/hash_signature_tracker.rs` 6-field serialization schema, live drain parity, & `QuorumStatus`**
   - `0x275ef30..0x275f127` (`Serialize` for `HashSignatureTracker`) emits exactly 6 fields in order from `.rodata` `0x5f6b28`:
     1. `"tracker"` (`+0x00`, len 7)
     2. `"qrs"` (`+0x48`, len 3)
     3. `"highest_quorum_height"` (`+0x80`, len 21)
     4. `"htm"` (`+0x60`, len 3)
     5. `"adu"` (`+0x88`, len 3, via `0x282d550`)
     6. `"h"` (`+0x90`, len 1, via `0x282ccc0`)
   - Live-side drain `0x2760030..0x2760227` mirrors slow-side `0x5afa030`: computes `cutoff = current_height.saturating_sub(1000)` (`0x3e8` at `0x2760048`), prunes `[tracker+0x60]`, swaps `[tracker+0x48..+0x60]` with an empty `Vec`, and compacts 104-byte (`0x68`) `qrs` entries retaining `entry[+0x20] != 0` (`0x27600f0`).
   - `QuorumStatus` (`0x28a05e0..0x28a0856`, 12 monomorphizations) encodes unit variant `"N"` (`0x5ff063`) vs payload variant `"Q"` (`0x5ff065`).

3. **`l1/src/abci/state.rs:151` checkpoint serialization dispatch (`0x26a2c80..0x26a326e`)**
   - Checks path `== "/dev/null"` (`0x26a2ce4`: `0x6c756e2f7665642f` + `'l'`), short-circuiting as a no-op.
   - Extracts extension (rejecting `".."` `0x2e2e`): `".rmp"` (`0x4659e5` at `0x26a2da4`) selects MessagePack (`0x22ebdc0`); otherwise selects pretty JSON (`0x22ebc70`) with initial capacity `0x80` (`0x26a2e1b`) and 2-space indent `"  "` (`0x5f3cc0`), then logs `"serialized abci state"` (`0x5f41ee`).

4. **`l1/src/abci/engine.rs:514,557` daily EVM archive & straggler checkpoint filter (`0x38c40f0`, `0x3d5dca0`)**
   - `0x38c40f0..0x38c51ee` formats daily EVM tar paths with `/data/daily_evm_checkpoints/` (`0x438f1d` via `0x38c4478`) and checks `periodic_abci_state_status_base_dir does not exist:` (`0x44db86`).
   - `0x3d5dca0..0x3d5dfb0` skips directories containing `/MARKED_FOR_DELETION` (`0x44c7fc` via `0x3d5dd85`), logs `"straggler evm state checkpoint"` (`0x7bd544` via `0x3d5de14`) when `h < min_expected`, and enforces the 3-bound retention check at `0x3d5de80` (`h < upper_exclusive && h >= min_expected && h <= max_inclusive`).

## Reproducibility

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-db-hub-routing-and-abci-schema/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_db_hub_routing_and_abci_schema_115
```
