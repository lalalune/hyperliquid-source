# RE-008: node #115 `node_slow_abci_engine` runner built by `0x5649680` (39th stage)

- Component ID: abci. Question: open PR #6009 found that `0x5a6bfb0` passes the engine value with the name `node_slow_abci_engine` to slot `0x64ebc98`. #5916 mapped the `fast_abci_engine` runner `0x567bd50`. What does the slow builder make, and how does it compare with the fast runner?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues #5916 and open PR #6009. The tool imports helpers from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, constants, string bytes, relocations, the Location record, the GLOB_DAT symbol, FDE starts and call censuses are observations. "Runner", "thread pool", "B-tree map", "threshold", "minutes per year" and "milliseconds per minute" are inferred labels. The binary was not executed.
- Scope included: the call site in `0x5a6bfb0`; the whole of `0x5649680`; the stores of `0x567bd50` that match it; the B-tree inserts `0x51d4530` and `0x51d4df0`. Scope excluded: the bodies of `0x1563a60` (pool), `0x154c700` (lock), `0x47721f0` (the two 0x2a8-byte parts), the map converters `0x4d56560` and `0x4d54eb0`, and every reader of the runner. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/slow_abci_engine_115.py --check
python3 -m unittest tests.test_slow_abci_engine_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: one call site, through a slot

- `0x5a6c5fd` loads `0x93afc4` = `node_slow_abci_engine`, `0x5a6c614` sets `ecx = 0x15` (21, its length), and `0x5a6c619` calls `[0x64ebc98]`. `0x64ebc98` is relocated to `0x5649680`.
- `0x5649680` has no direct `call`, and `0x5a6c619` is the only `call [0x64ebc98]` in `.text`.
- The fast builder `0x567bd50` has one direct call, `0x5a6c21c`, also in `0x5a6bfb0`. So `0x5a6bfb0` builds both runners.

## Evidence 2: what the slow builder adds

- **A pool.** `0x56496a4..0x56496b3`: `edi = 3`, `esi = 0x10`, `rdx = 0x92a814` (`SlowAbciThreadPool::new`, `ecx = 0x17`), call `[0x64e1210]` (relocated to `0x1563a60`). The result is kept at `[rsp+8]` and stored at runner `+0xb48` (`0x5649c69`, `0x5649c6e`). Reading 3 as a thread count and 0x10 as a queue size is an inference.
- **Two maps under one key.** Both `0x56496ec` and `0x564977a` load `0x92a82b` = `compute_write/spawn_slow_abci_driver_apply_block` with `edx = 0x30`:
  - `0x5649708` calls `0x51d4530` with 0.05 (`0x459038`);
  - `0x5649796` calls `0x51d4df0` with 0.35 (`0x458f50`).

  Both callees are B-tree inserts of an f64 under a string key: they read the node length as a u16 at `+0x112`, compare keys with `memcmp` (GLOB_DAT `0x64dfb50`), follow children at `+0x118 + 8*i`, and on an equal key overwrite the f64 at `+0xb8 + 8*i`. Reading 0.05 and 0.35 as per-task time thresholds in seconds is an inference.
- **Two constant blocks.** Runner `+0xb20..+0xb38` and `+0xb50..+0xb68` each get the qwords `0, 60000, 525600, 0`. 60000 is the number of milliseconds in a minute and 525600 the number of minutes in a 365-day year; those readings are inferences.
- **A flag.** `0x5649864` loads slot `0x64e5bf8` (relocated to `0x64fdc1c`) and reads a byte from it. `0x5649c61` stores `setne` of that byte at runner `+0xb40`.

## Evidence 3: the layout shared with the fast runner

| Offset | Slow `0x5649680` | Fast `0x567bd50` |
|---|---|---|
| `+0x6a8` | 0x478 bytes (`0x5649b66`, `0x5649b7c`) | 0x478 bytes (`0x567c0c7`, `0x567c0dd`) |
| `+0x158` | 0x2a8 bytes from `[0x64e5c00]` with `ecx = 1` | 0x2a8 bytes (`0x567c139`, `0x567c148`) |
| `+0x400` | 0x2a8 bytes from `[0x64e5c00]` with `ecx = 0` | 0x2a8 bytes (`0x567c14f`, `0x567c15e`) |
| `+0x128` | dword 1000000000 | dword 1000000000 |
| lock | `0x56498df` call `[0x64e1078]` with Location `net_utils/src/rw_lock.rs:110:14` | `0x567be4e` call `[0x64e1078]` |
| setne byte | `+0xb40` | `+0xb20` |

`0x64e5c00` is relocated to `0x47721f0`; both builders call it twice (`0x5649b06`/`0x5649b60`, `0x567c074`/`0x567c0c1`). The 0x478 bytes are a zero tag qword followed by the 0x470-byte engine value, the layout #5916 corrected (`+0x6a8` tag, `+0x6b0` value). Inference: the slow runner is the fast runner's type with a pool, two threshold maps and two `{0, 60000, 525600, 0}` blocks added after `+0xb20`.

## Implementation and comparison

The tool pins 39 instruction byte runs, 18 RIP-relative references, 3 direct calls, 6 relocations (5 slots and the Location's file pointer), 4 strings, 2 f64 constants, the `memcmp` symbol and the Location's length, line and column, then recomputes the builder call census. Tests change one byte in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: `node_slow_abci_engine` is a second runner, built from the same engine value as `fast_abci_engine` in the same function `0x5a6bfb0`. It shares the fast runner's first 0xb20 bytes of layout and adds a 3/16 pool named `SlowAbciThreadPool::new`, two threshold maps (0.05, 0.35) for `compute_write/spawn_slow_abci_driver_apply_block`, and two `{0, 60000, 525600, 0}` blocks.
- Limits: what the pool, the two 0x2a8-byte parts, the map converters and the constant blocks do is not mapped; nor is whether the slow runner replays blocks, lags behind the fast one, or runs on an interval; nor what reads the runner. The byte at `0x64fdc1c` and the source of the fast runner's `+0xb20` byte are not traced.
- Next lead: find where the slow runner is spawned or polled after `0x5a6c619`, and what reads `+0xb20..+0xb68`.
