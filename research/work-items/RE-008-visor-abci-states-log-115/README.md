# RE-008: node #115 `node save visor_abci_state` periodic task

- Component ID: abci. Question: stage 34 (#6002) found that `0x5a39630`, reached only through the relocation at `0x64b8b30`, builds a `visor_abci_states` line writer and writes `hyperliquid_data/visor_abci_state.json`; #6004 bound the file's six fields. This packet binds who starts that task, how often it runs, what each tick writes to the `visor_abci_states` log, and what the read wrapper `0x5648400` shares with #6037's `0x5647720`.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #6002 and #6004.
- Claim status: instruction bytes, relocations, strings, Location records, the GLOB_DAT symbol, FDE extents and call or `lea` censuses are observations. "Task", "Arc", "closure", "line writer", "hourly", "per-minute counter" and "runner" are inferred labels. The binary was not executed.
- Scope excluded: the bodies of the spawner `0x15d63c0`, the blocking body `0x4e47060`, the record serializer `0x50e50b0` beyond its value-serializer call, and what `0x51eaff0` records. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/visor_abci_states_log_115.py --check
python3 -m unittest tests.test_visor_abci_states_log_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the spawn

- The closure vtable `0x64b8b18` is `{drop 0x5a5a230, size 8, align 8, call 0x5a39630}` (two relocations, two literal words).
- `.text` has exactly two `lea` references to it: `0x2aed339` in poller `0x2aeaef0` and `0x2cb8959` in poller `0x2cb6500`. Each site allocates 8 bytes (`mov edi, 8`), stores one pointer into them, loads the 26-byte name `node save visor_abci_state` (`0x93b0b6`, `mov esi, 0x1a`) and calls slot `0x64e1750`, which is relocated to `0x15d63c0`, the spawner #6011 bound for `node slow abci_state driver`.
- `0x5a39630` has no direct caller.

## Evidence 2: one tick, every 5 seconds

`0x5a39630` loads the boxed pointer (`mov r14, [rdi]`) and uses its payload at `+0x10`. Before the loop it builds a daily writer named `visor_abci_states` (17 bytes, slot `0x64e0f98`) and converts it to hourly (slot `0x64e0fa0`), as #5874 bound. Each pass then:

1. calls `0x5648400(payload, "get_visor_state")` (15 bytes); this is the only direct call to `0x5648400`;
2. builds the path through `0x5942870` with `visor_abci_state` and writes the value through `0x50de010`; an Err panics with `Result::unwrap()` at `node/src/node.rs:914:42`;
3. calls the line writer `0x4e3fe00` with the hourly writer and the value;
4. sleeps through `clock_nanosleep` (GLOB_DAT slot `0x64e11e8`) with `CLOCK_MONOTONIC` (`edi = 1`), relative (`esi = 0`), for 5 seconds (`r14d = 5`). Return 4 (EINTR) retries with the remaining time; any other error panics at `std/src/sys/thread/unix.rs:581:17`.

## Evidence 3: the log record

The line writer `0x4e3fe00` (one direct call) serialises through `0x50e50b0`, whose value serializer is `0x51addb0`. That serializer emits the same six field names, at the same string addresses and with the same lengths, as the pretty serializer `0x51adf60` used for `visor_abci_state.json` (#6004): `hardfork_version` (16), `initial_height` (14), `height` (6), `scheduled_freeze_height` (23), `consensus_time` (14), `wall_clock_time` (15). The writer then flushes only when writer `+0xaa` and the global byte `0x64ffe50` are both set, the #5876 shape.

## Evidence 4: the read wrapper

`0x5648400` calls its blocking body `0x4e47060` with `edx = 1`, then uses the counter block at `+0xb50` (lock), `+0xb60` (last minute) and `+0xb68` (count) and records through `0x51eaff0`. `0x5647720` (#6037) uses the same `lea rbx, [r13+0xb50]` block with a different blocking body, `0x4e46b50`.

## Results and limitations

- Result: both pollers start a thread named `node save visor_abci_state` that, every 5 seconds, reads the visor state under the runner, rewrites `hyperliquid_data/visor_abci_state.json` and appends the same six-field state as one line to the hourly `visor_abci_states` log.
- Limits: the record serializer's framing around the value (time field, array or object) is not mapped; the pointer the pollers box (poller `+0x840`) is not traced to the slow runner Arc of #6011; what `0x4e47060` reads is not mapped.
- Next lead: the record framing in `0x50e50b0` (its call to `0x4fcd860` before the value).
