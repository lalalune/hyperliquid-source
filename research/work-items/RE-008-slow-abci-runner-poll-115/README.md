# RE-008: node #115 slow abci runner pair and the `node slow abci_state driver` thread (40th stage)

- Component ID: abci. Question: open PR #6010 found that `0x5a6bfb0` builds a fast runner (`0x567bd50`) and a slow runner (`0x5649680`, name `node_slow_abci_engine`) with a pool at `+0xb48`, two `compute_write/spawn_slow_abci_driver_apply_block` map values (0.05, 0.35) and two constant blocks. It left open where the slow runner goes, what drives it, and what the constants are.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6009 and #6010. It imports helpers from the merged `tools/freeze_snapshot_115.py` and does not depend on unmerged files.
- Claim status: instruction bytes, constants, string bytes, relocations, the vtable layout, FDE extents and call or immediate censuses are observations. "Arc", "thread", "handle", "pool", "read lock", "write lock", "blocking section", "replay" and the reading of 60000 / 525600 as time units are inferred labels. The binary was not executed.
- Scope included: the tail of `0x5a6bfb0` from `0x5a6c61f`; the two poller sites that keep its return pair; `0x5a6cbc0` up to its return; the closure vtable `0x64b8a00`; the apply-block and write-greeting part of the closure body `0x5a34440` (`0x5a34dcc..0x5a34fb8`); the constant stores of `0x5649680`. Scope excluded: the spawn helper `0x15d63c0`, the read `0x5649df0`, the pool call `0x59edc50`, the lock helpers `0x4f19fa0` / `0x4f18bd0` and the blocking helper `0x4e47900` beyond one string each, the rest of the closure body, and every reader of the constant blocks and map values. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/slow_abci_runner_poll_115.py --check
python3 -m unittest tests.test_slow_abci_runner_poll_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: `0x5a6bfb0` returns both runners

- `0x5a6c2ec` allocates 0xb38 bytes for the fast runner and keeps the pointer in `r14` (`0x5a6c300`). Nothing in `0x5a6c303..0x5a6c67e` writes `r14`.
- After the slow build (`0x5a6c619`), it writes 1 and 1 at `rsp+0x1240`/`+0x1248`, copies the 0xb70-byte slow runner behind them, allocates 0xb80 bytes (`0x5a6c655`), copies all 0xb80 bytes in, and keeps the pointer in `r15`.
- It returns `rax = r14` and `rdx = r15` (`0x5a6c67e`, `0x5a6c681`).
- Both pollers (`0x2aeaef0`, `0x2cb6500`) call it through slot `0x64e7440` (`0x2aec3ef`, `0x2cb7a0f`, the only two calls) and keep `rdx` at `[rsp+0x130]`.

## Evidence 2: the slow driver start `0x5a6cbc0`

Slot `0x64e7458` is relocated to `0x5a6cbc0`. It has no direct call; the only calls through the slot are `0x2aed2f5` (in `0x2aeaef0`) and `0x2cb8915` (in `0x2cb6500`).

- `0x5a6cbf8` passes `rsi+0x10` to slot `0x64ebca0` (`0x5649df0`, which references the name `slow_abci_engine_read_increment`) and keeps the result byte in `ebx`.
- It allocates 0xb20 bytes and builds a handle with `slow abci block` (15 bytes) and 0x1388 (5000), which it returns to the caller at `[r13+0x0..+0x28]`.
- It boxes a 0xb8-byte closure (`0x5a6ce24`) and calls slot `0x64e1750` (`0x15d63c0`) with `node slow abci_state driver` (27 bytes) and vtable `0x64b8a00`.
- The vtable holds drop `0x5a579d0`, size 0xb8, align 8 and call `0x5a34440`.

## Evidence 3: the driver body `0x5a34440`

- `get` (3 bytes) goes to `0x4f19fa0` with `[ctx+0xa0]+0x140`.
- `[ctx+0x78]` is loaded and `[it+0xb58]+0x80` goes to `0x59edc50`. With a 0x10-byte Arc header, `+0xb58` is slow runner `+0xb48`, the pool from #6010; no other runner field sits there.
- `spawn_slow_abci_driver_apply_block` (34 bytes, the same name as the #6010 map key after `compute_write/`) goes to `0x4e47900` with `edx = 1`.
- If that result's first qword is not `0x8000000000000000`, `spawn_slow_abci_driver_write_greeting` (37 bytes) goes to `0x4f18bd0` with `edx = 0` and `[ctx+0xa8]+0x140`.
- `0x4f19fa0` and `0x4f18bd0` each reference `base/src/lock_id.rs`; `0x4e47900` references `asked to exit when not entered`.

Inference: the slow runner is driven by its own named thread, which receives `slow abci block` items through a queue of 5000, takes a read lock (`get`), runs each block apply inside a blocking section on the slow runner's pool, and writes a greeting under a write lock. This fits a slow engine that replays blocks behind the fast engine, but the queue's sender and the replay order are not mapped here.

## Evidence 4: the constant blocks

`0x5649680` stores `{0, 60000, 525600, 0}` at slow runner `+0xb20..+0xb38` and again at `+0xb50..+0xb68`. The same 60000 / 525600 pair is stored by `0x434b950` at `+0x3a0` / `+0x3a8`. The 32-bit value 525600 occurs three times in `.text`: `0x434b990`, `0x5649c52`, `0x5649c92`. Inference: 60000 is milliseconds per minute and 525600 is minutes per 365-day year, so the block is a reusable rate or window structure; no reader is mapped here.

## Implementation and comparison

The tool pins 43 instruction byte runs, 16 RIP-relative references, 6 relocations, the vtable size and alignment, 5 strings and 3 helper string references, then recomputes the two slot-call censuses, the direct-call census of the driver start and body, and the 525600 immediate census. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: following the queue sender through the pollers (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the slow runner leaves `0x5a6bfb0` as the second half of a return pair, and both pollers hand it to `0x5a6cbc0`, which starts a thread named `node slow abci_state driver` that applies blocks in a blocking section and writes a greeting under a lock.
- Limits: the spawn helper `0x15d63c0` is named only by its arguments; the queue sender, item type and replay order are not mapped; the readers of the constant blocks and of the 0.05 / 0.35 map values are not found; the read `0x5649df0` and the pool call `0x59edc50` are named by address.
- Next lead: find who sends into the `slow abci block` handle returned at `[r13+0x0..+0x28]` in the two pollers.
