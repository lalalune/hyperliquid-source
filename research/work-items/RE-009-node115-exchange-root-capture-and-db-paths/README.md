# RE-009: node #115 74-slot Exchange state-root capture layout, db_home checkpoint paths, and timer maturity

- Component ID: `storage` / `abci`
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes)

## Binary findings

1. **Exact 74-slot `Exchange` state-root capture parity (`live` vs `slow`)**:
   - Both `0x269a1b0..0x269ab6b` (live engine) and `0x4e34ce0..0x4e3569b` (slow/replay engine) capture the **exact same 74 contiguous `Exchange` field pointers** into `[rsp+0x128..=rsp+0x370]` (step 8 bytes), including `0x3d98` (L1 hash tracker, slot 71), `0x3e50` (ABCI digest tracker, slot 72), `0x3908` (slot 73), `0x3f08` (validator registry, slot 24), `0x0d88` (membership set, slot 25), and `0x10e8` (hardfork state, slot 28).
2. **`db/src/db_home.rs:286..317` checkpoint paths (`0x44681e0..0x4468b62`)**:
   - Formats `<db_home>/checkpoint` (`0x44683a8`, format template `c0 0b` at `0x434739`, literal `"/checkpoint"` at `0x43473b`) and `<checkpoint_dir>/lt_hashes.json` (`0x446857f`, `0x44685d9`, format template `c0 0f` at `0x44f3c9`, literal `"/lt_hashes.json"` at `0x44f3cb`).
3. **Timer maturity rule in `0x51520f0..0x51528fb` (`0x515218d..0x51522cd`)**:
   - Loads `f64` delay seconds from `[tracker + 0x88]` (`0x515218d`), converts via `Duration::from_secs_f64` (`0x64e0f70 -> 0x15ed960`), scales seconds by `1_000_000_000` (`0x3b9aca00`) and clamps to `i64::MAX` (`0x7fffffffffffffff`), adds to the pending entry's timestamp via `0x64e0f78 -> 0x162a9a0`, and evaluates `current_time >= inserted_time + delay` (`cmp dword ptr [r15], edx; setge dl`).

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-exchange-root-capture-and-db-paths/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_exchange_root_capture_115
(cd research/work-items/RE-009-node115-exchange-root-capture-and-db-paths && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/storage-abci \
  cargo test --offline --locked --manifest-path src/node115-db/Cargo.toml
```
