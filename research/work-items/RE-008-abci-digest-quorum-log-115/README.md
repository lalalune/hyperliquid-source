# RE-008: node #115 `abci_digest_quorum` line writer and its record (52nd stage)

- Component ID: abci. Question: #5874 listed `abci_digest_quorum` as one of the fixed line writer names (daily constructor call `0x5a6c42c`), and #6023 found that the step wrappers compare a quorum digest in 0x68-byte entries (`+0x48..+0x68`). Where is the writer stored, who writes to it, and what does each line hold?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues #5874 and #6023 to #6031. It imports helpers from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, strings, relocations, FDE extents and call censuses are observations. "Writer", "hourly", "engine value", "record", "quorum digest", "height", "line" and "JSON" are inferred labels from the call shapes, strings and earlier packets. The binary was not executed.
- Scope included: the writer creation and copies in `0x5a6bfb0`; the two calls of `0x4e3a020` in the step wrappers; `0x4e3a020`'s flush gate; the serialiser `0x50e6fe0` and record serialiser `0x537d7b0`; the digest field path `0x5073b20` → `0x4e1c250`. Scope excluded: the `abci_hashes` writes (`0x4e3a7a0`, reached from the digest steps), the bodies of `0x5077210`, `0x14c37f0`, the rotation sink and the hex encoder (#6031), and how the 0x68-byte entries are built. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_digest_quorum_log_115.py --check
python3 -m unittest tests.test_abci_digest_quorum_log_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: creation and placement

In `0x5a6bfb0` (FDE start; the engine builder from #6008):

- `0x5a6c418` loads `abci_digest_quorum` (`0x93a6d8`, `mov edx, 18`), calls the daily constructor (slot `0x64e0f98` → `0x1546700`), then the hourly conversion (slot `0x64e0fa0` → `0x1546000`) with output `rsp+0xa0`.
- `0x5a6c448` does the same for `abci_hashes` (`0x93a6ea`, 11 bytes) with output `rsp+0xe20`.
- No `mov byte [..+0xaa], 1` follows either conversion (the tool checks the span `0x5a6c448..0x5a6c4e8`), so both writers keep flush byte 0 (#5874 pattern).
- The writers move to `rsp+0x200` / `rsp+0x150`, then into `rsp+0x14c0` and `rsp+0x1570` (0xb0 bytes each), after the 0x260-byte observer at `rsp+0x1260`. The value starting at `rsp+0x1240` is copied whole (0x438 bytes) to `rsp+0x5508`.

| Engine value offset | Holds |
|---|---|
| `+0x20` | observer (the `+0x20` passed to the digest step in #6024) |
| `+0x280` | `abci_digest_quorum` writer |
| `+0x330` | `abci_hashes` writer (the `+0x330` passed to the digest step in #6024) |

## Evidence 2: the only writes

`0x4e3a020` has exactly two direct calls: `0x5a05c5e` in the layout-A wrapper `0x5a04e40` and `0x5a0748e` in the layout-B wrapper `0x5a06600` (#6006, #6023). Both run the same loop over the 0x68-byte entries (`add r13, 0x68`):

- `rdi` = engine value `+0x280` (`lea rbx, [r12+0x280]` / `[r15+0x280]`).
- `rsi` = a time from slot `0x64e0990` (`0x1629690`, the wall clock from #5045).
- `rdx` = a 0x28-byte record: entry `+0x48..+0x68` at record `+0x0` (the 32 bytes #6023 compares) and entry `+0x0` (the height key #6023 looks up) at record `+0x20`.

Inference: every quorum entry the wrapper receives is logged, whether or not a computed digest exists for its height. The compare loop in #6023 starts from the same entry base.

## Evidence 3: the write and the line

- `0x4e3a020` calls the rotation sink (slot `0x64e0f80` → `0x1546570`, #5849), skips when the writer has no path, opens a liner (slot `0x64e0020` → `0x14c3b30`) on a path change, and calls `0x50e6fe0`.
- `0x50e6fe0` serialises the record with `0x537d7b0` into a 0x80-byte Vec, appends `\n` (`0x50e70db`) and writes through `0x14c37f0`. A serialisation error drops the line.
- `0x537d7b0` writes `{`, the field `height` (`0x924ed9`, 6 bytes) from record `+0x20`, the field `d` (`0x9247d0`, 1 byte) from record `+0x0`, and `}`.
- The `d` value goes through `0x5073b20` → `0x4e1c250` with capacity `0x42` and length `0x20`, which calls the hex slot `0x64e4d08` (`0x2eabb50`, #6031) with trim 0: a quoted `0x` plus 64 lowercase hex digits.
- After the write, `0x4e3a020` flushes again only when writer `+0xaa` and the global byte behind slot `0x64e0f88` (`0x64ffe50`, #5878) are both set; with flush byte 0 this extra flush does not run.

Each line is therefore `{"height":<u64>,"d":"0x<64 hex>"}`. Inference from #5872/#5874: the hourly writer's path is under `{root}/data/abci_digest_quorum/hourly/`.

## Implementation and comparison

The tool pins 51 instruction byte runs, 21 RIP-relative or rel32 references, 7 relocations and 4 strings, and recomputes three call censuses and the FDE owners of the call sites. Tests mutate one byte range at a time in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: `abci_digest_quorum` holds one JSON line per received quorum entry, with the height and the quorum digest, written from both step wrappers through engine value `+0x280`.
- Limits: the `abci_hashes` record (`0x4e3a7a0`) is not mapped here; the bodies of `0x5077210` (u64 field), `0x14c37f0` and the hex encoder are cited, not re-read; whether the root directory makes the writer open a file at run time follows #5872 and is not re-proved; where the 0x68-byte entries come from is outside this packet.
- Next lead: the `abci_hashes` record written by `0x4e3a7a0` from the digest steps.
