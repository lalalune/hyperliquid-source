# RE-008: node #115 line writers (ninth stage): what consumes the hourly `mempool_txs` writer

- Component ID: abci. Question: the eighth stage (open PR #5874) found that in `0x2af45f0` and `0x2cc1120` the hourly `mempool_txs` writer, with its flush byte set, is moved to `+0x18` of a stack struct passed to `0x5a81ed0` through slot `0x64e74d8`. It left open what `0x5a81ed0` does with the struct and what is written through the writer.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5849, #5854, #5861, #5872 and #5874. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, vtable words, the Location record, FDE extents and call or byte-pattern censuses are observations. "Spawn", "task", "future", "poll", "Arc", "JoinHandle", "JSON", "None" and "wall clock" are inferred labels from the call shapes, sizes, vtable layout and bytes written. The binary was not executed.
- Scope included: all of `0x5a81ed0`; the head of the spawn wrapper `0x15d6ef0`; the two writer reads in the poll `0x5a82670`; all of the write `0x4e3eaa0`; the line builder `0x50e6760` up to the line write; the record serializer `0x5a80250` up to its closing brace. Scope excluded: the bodies of `0x15ca9e0`, `0x15d6730`, the first future's poll `0x5a820d0`, the rest of the 0x6ec5-byte poll `0x5a82670` (where the record comes from), the time serializer `0x4fcd860`, the field serializers `0x5073b20` and `0x5091960`, and the flush path `0x14c3950` / `0x1533e80`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/line_writer_consumer_115.py --check
python3 -m unittest tests.test_line_writer_consumer_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: `0x5a81ed0` spawns two boxed futures

Slot `0x64e74d8` is relocated to `0x5a81ed0`. Its only callers are `0x2af5b03` (in `0x2af45f0`) and `0x2cc281f` (in `0x2cc1120`). Arguments: `rdi` the struct, `sil` a flag, `rdx`, `rcx`, `r8`.

- It takes the Arc-like pointer at struct `+0xf0` and increments its count (`0x5a81f06`, `lock inc` at `0x5a81f0d`).
- **First future:** a 0x60-byte allocation (`0x5a81f3d`) holding 0x20 bytes from `[rcx]` and that pointer. It goes to the wrapper `0x15d6ef0` (slot `0x64e1758`) with vtable `0x64b9188`: drop `0x5a5c580`, size `0x60`, align `8`, poll `0x5a820d0`.
- **Second future:** the struct's 0x118 bytes are copied to the frame base (`0x5a81fb8`, `0x5a81fc0`), `rdx` to `+0x118`, `r8` to `+0x120`, the flag to `+0x1a4` and `0` to the state byte `+0x1a5`. The 0x2d80-byte frame is boxed (`0x5a81fde`, `0x5a82007`) and tail-jumped to the same wrapper (`0x5a82036`) with vtable `0x64b91a8`: drop `0x5a5c610`, size `0x2d80`, align `8`, poll `0x5a82670`.
- The flag selects the name for each spawn, both 31 bytes (`mov esi, 0x1f`): `nv_stream_apply_execution_state` (`0x93b963`) and `nv_stream_forward_client_blocks` (`0x93b982`). With the flag clear, the name pointer is 0.

So the writer moved to struct `+0x18` (eighth stage) sits at `+0x18` of the second future.

## Evidence 2: the spawn wrapper

`0x15d6ef0` tests the name pointer (`0x15d6f01`). With no name it calls `0x15ca9e0` with Location `base/src/lu.rs:148:9` (`0x64014e0`) and then does `lock cmpxchg` 0xcc → 0x84 on the returned header (`0x15d6f37`–`0x15d6f41`). With a name it calls `0x15d6730` with `edx = 1`. Inference: a task spawn whose join handle is dropped at once.

## Evidence 3: the second future uses the writer in one place

The poll `0x5a82670` (FDE `0x5a82670..0x5a89535`) dispatches on the state byte `+0x1a5` (`0x5a826b5`). A byte-pattern scan of the poll finds exactly two `rbx+0x18` writer uses:

- `0x5a887cc` `cmp [rbx+0x18], 0x8000000000000000`; `je` skips the write when the writer is None;
- `0x5a887fc` `lea rsi, [rbx+0x18]`, passed to `call 0x4e3eaa0` at `0x5a88864`, the only caller of `0x4e3eaa0`.

## Evidence 4: the write `0x4e3eaa0`

1. Wall clock through slot `0x64e0990` → `0x1629690`.
2. Path rotation through slot `0x64e0f80` → `0x1546570` (fourth stage, #5849).
3. If writer `+0x48` is None (`0 - x` overflows, `0x4e3eb24`–`0x4e3eb2f`), the returned path is dropped and nothing is written.
4. If the rotation returned a new path, the line file is reopened through slot `0x64e0020` → `0x14c3b30`, and the date, hourly byte and hour are stored at `+0x98`, `+0xa8`, `+0xa9` (`0x4e3ebd1`–`0x4e3ebdf`).
5. The line is written by `0x50e6760` (`0x4e3ec13`), and the time is stored at `+0x9c`.
6. If writer `+0xaa` (the flush byte set in the eighth stage) and the byte at `0x64ffe50` (slot `0x64e0f88`) are both non-zero, `0x14c3950` → `0x1533e80` runs, and a non-null result is dropped by `0x14c4d00`.

## Evidence 5: the line format

`0x50e6760` writes `[` (`0x50e679d`), the time through `0x4fcd860`, `,` (`0x50e67e5`), the record at time `+0x10` through `0x5a80250`, `]` (`0x50e687f`) and a newline (`0x50e68c6`), then writes the buffer through `0x14c37f0` (`0x50e68dc`). `0x14c37f0` calls the flush gate slot `0x64e0008` (sixth stage, #5861) and has 96 callers.

The record serializer `0x5a80250` (one caller) writes `{`, then `tx_hash` (`0x93b509`, 7 bytes) from record `+0x10`, then `signed_actions` (`0x93b86f`, 14 bytes) from record `+0x0`, then `}`.

Result: each line of the hourly `mempool_txs` log has the shape `[<time>,{"tx_hash":…,"signed_actions":…}]`.

## Implementation and comparison

The tool pins 83 instruction byte runs, 18 RIP-relative or rel32 references, 12 relocations, two vtable layouts, five strings and one Location, then recomputes the caller censuses and the poll's writer-use scan. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: mapping the whole 0x6ec5-byte poll (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the hourly `mempool_txs` writer from #5874 is owned by the second of two spawned futures. That future writes one JSON array line per record, `[time, {tx_hash, signed_actions}]`, rotates the file hourly, and adds an extra flush when a global byte is set.
- Limits: the poll scan matches two byte shapes based on `rbx`. Other uses through another register are not ruled out. Not mapped: where the record comes from in the poll, the first future, what sets the global byte at `0x64ffe50`, the spawn internals, and the time format written by `0x4fcd860`.
- Next lead: map what sets the global flush byte `0x64ffe50`, and the poll states that build the record passed at `0x5a8885c`.
