# RE-008: node #115 parent mode byte +0x248 / +0x249 writers and the 60-second line-count loop (76th stage)

- Component ID: abci. Question: the startup-check packet (open PR #6074) traced the startup future's bytes `+0x0` / `+0x1` back to parent byte `+0x248` and the byte after it, and found that the `replica_cmds` check in `0x2b41b70` runs only when byte `+0x1` is 1 on a path where byte `+0x0` has bit 0 clear and is not 2. It left open whether anything ever writes `+0x249`, and what the second line-count caller `0x2c7d950` does.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #5902 and #6074. It imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, displacements, relocations, the dynamic symbol name, the Location record and the call and store censuses are observations. "Mode", "enum variant", "padding", "sleep", "EINTR" and "mutex" are inferred labels. The binary was not executed.
- Scope included: every store to `+0x248` / `+0x249` in the two parents `0x2ae41e0` and `0x2cde430`; the direct-call and relocation census of the two pollers and their entry copy; the body of `0x2c7d950` up to its panic call. Scope excluded: jump-table resume targets inside the parents, the lazy `.lz4` cell, the body of `0x1563bc0` beyond #6074, and who starts the `0x2c7d950` thread.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/parent_mode_bytes_115.py --check
python3 -m unittest tests.test_parent_mode_bytes_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the only byte writes to parent +0x248 are 2 and 1

The tool scans each parent for `c6` / `88` / `89` / `0f 11` stores with a `[reg+disp32]` operand of `0x248` or `0x249`.

| Parent | Store | Value | Path (#5902) | Next |
|---|---|---|---|---|
| `0x2ae41e0` | `0x2ae4604` `c6 83 48 02 00 00 02` | 2 | tag 2 | `lea r14,[rbx+0x220]`; `call 0x2aeaef0` at `0x2ae4627` |
| `0x2ae41e0` | `0x2ae5469` `c6 83 48 02 00 00 01` | 1 | tag 3 | `call 0x2aeaef0` at `0x2ae548c` |
| `0x2cde430` | `0x2cde6d0` `41 c6 85 48 02 00 00 02` | 2 | tag 2 | `call 0x2cb6500` at `0x2cde6f4` |
| `0x2cde430` | `0x2cdf567` `41 c6 85 48 02 00 00 01` | 1 | tag 3 | `call 0x2cb6500` at `0x2cdf58b` |

- No store in either parent targets `+0x249`.
- Each parent also has six 16-byte stores at `+0x248` (A: `0x2ae5249`, `0x2ae5266`, `0x2ae677f`, `0x2ae679c`, `0x2ae67dd`, `0x2ae67fa`; B: `0x2cdf325`, `0x2cdf341`, `0x2ce0833`, `0x2ce0852`, `0x2ce088a`, `0x2ce08a5`). Each pair writes a zeroed stack block and then the all-zero block at `0x457d30` over `+0x238..+0x258`. They follow a different sub-future (`0x2ae7fd0` on `+0x2d0`, dropped through `0x2ac25f0`), not the poller blocks above. Reading them as a different state of the same async layout is an inference.

## Evidence 2: the pollers are entered only from those blocks

- `0x2aeaef0` has exactly two direct calls (`0x2ae4627`, `0x2ae548c`) and `0x2cb6500` exactly two (`0x2cde6f4`, `0x2cdf58b`). No `R_X86_64_RELATIVE` relocation names either one.
- Both pass `rdi = parent + 0x220`, so poller `+0x28` is parent `+0x248`. On entry each copies `+0x28..+0x38` to `+0x38` (`0x2aeaf65`/`0x2aeaf69`, `0x2cb6575`/`0x2cb6579`), the copy #6074 follows into the startup future.

Inference: the mode byte is 1 or 2 whenever a poller first runs. With #6074's tests (mode 2 skips the future in `0x2af0660`; bit 0 set takes the join path in `0x2b41b70`), the `replica_cmds` check is not reached from these two parents. Byte `+0x249` is never written on the mode paths, which fits a payload byte that only a variant 0 would carry; no variant 0 store was found.

## Evidence 3: `0x2c7d950` re-counts a locked path every 60 seconds

`0x2c7d950` (one direct call, from the 6-byte thunk `0x2c7bb80`) runs a loop:

1. `r15d = 0x3c` (`0x2c7d980`); `clock_nanosleep(1, 0, &ts, &ts)` through GLOB_DAT slot `0x64e11e8` (`edi = 1` at `0x2c7d9b9`, `call r14` at `0x2c7d9c6`). Result 4 (EINTR) sleeps the remainder; any other non-zero result calls slot `0x64e11f0` with the Location `library/std/src/sys/thread/unix.rs:581:17`.
2. It takes the byte lock at `[arg+0x10]` (`lock cmpxchg` at `0x2c7d9fe`; contention calls slot `0x64e01f8` with `edx = 1000000000`), copies the byte buffer at `arg+0x20` / `+0x28`, and releases the lock.
3. It passes the copy to slot `0x64e1218` → `0x1563bc0` (`0x2c7da78`), the second line counter from #6074, frees it, and jumps back to step 1 (`0x2c7da95`).

Inference: a background thread that every 60 seconds counts the lines of a file whose path another thread can change.

## Implementation and comparison

The tool pins 27 byte runs, the two poller call censuses (one pass over `.text`), the absence of poller relocations, the `+0x248` / `+0x249` store census in both parents, the zero block, the line-count slot relocation, the `clock_nanosleep` dynamic symbol and the panic Location. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: executing the startup path (not allowed); decoding the parents' jump tables (bounded out).

## Results and limitations

- Result: on every mapped write, parent `+0x248` is 2 or 1 before a poller runs, and nothing writes `+0x249`.
- Limits: jump-table resume targets inside the parents are not decoded; the store census matches four opcode shapes with a `disp32` operand and would miss a write through a computed pointer, a SIB operand or a wider copy that covers `+0x249`. Who starts the `0x2c7d950` thread (no relocation or `lea` reaches `0x2c7bb80`), what path it counts, and the `.lz4` cell are not mapped.
- Next lead: the start site of the `0x2c7d950` thread and the struct whose `+0x20` path it counts.
