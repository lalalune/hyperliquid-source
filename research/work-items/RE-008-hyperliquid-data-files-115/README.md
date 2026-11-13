# RE-008: node #115 hyperliquid_data state files and the blocking abci state writer (34th stage)

- Component ID: abci. Question: open PR #6001 found that `0x5942870` builds `{root}/hyperliquid_data/{name}.{rmp|json}` (rmp only for `abci_state`), that two of its four callers pass `abci_state`, and that the step passes flag 1 to `0x4e45a30`, which runs `0x4e363c0` as a blocking call. It left open the names the other two callers pass, and what `0x4e363c0` writes and returns.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #5999 and #6001. It imports helpers only from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, constants, string bytes, relocations, Location records, FDE extents and call censuses are observations. "rmp", "JSON", "pretty", "blocking", "closure", "serialise", "visor state" and "file writer" are inferred labels from the strings, the shared config dword, the call shapes and the vendored tokio Locations. The binary was not executed.
- Scope included: the wrapper `0x5942b40` and its four callers' name and Location arguments; the extension branch of `0x50de010`; the call sequence of `0x5a39630` up to its write; the call chain `0x548604b` -> `0x4e45a30` -> `0x4e363c0` -> `0x4e4b3f0`; the closure body `0x4e4b3f0`. Scope excluded: the bodies of the encoders `0x51ae110`, `0x51adf60`, `0x5481900`, the file writer `0x15024a0`, `0x5648400` and `0x5a9dd40`; what the four wrapper callers write; the 0x38-byte result of `0x4e45a30` beyond the closure's Vec. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/hyperliquid_data_files_115.py --check
python3 -m unittest tests.test_hyperliquid_data_files_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: every other state file is visor_abci_state.json

`0x5942870` has four direct callers: `0x5485ae0` and `0x5486000` (the step, `abci_state`, #6001), `0x5942b57` and `0x5a396d3`.

- `0x5942b57` is inside the wrapper `0x5942b40`. The wrapper moves its first argument (the name) to `rsi` (`mov rsi, rdi` at `0x5942b4f`), builds the path, then calls the value writer `0x50de010` at `0x5942b6f` with its second argument (the value) and third argument (a Location).
- The wrapper has four direct callers. Each loads a slice record whose pointer is relocated to `0x4564d0` `visor_abci_state` (16 bytes):

| Call | Function | Name record | Location |
|---|---|---|---|
| `0x5443a82` | `0x5443930` | `0x64aaf70` | `node/src/node.rs:659:50` |
| `0x59ec380` | `0x59ec200` | `0x64b7f70` | `node/src/node.rs:659:50` |
| `0x5a08250` | `0x5a07ec0` | `0x64b7f70` | `l1/src/abci/engine.rs:316:46` |
| `0x5a08ab0` | `0x5a08720` | `0x64b7f70` | `l1/src/abci/engine.rs:316:46` |

- `0x5a396d3` loads the same record `0x64b7f70`.

So `hyperliquid_data/visor_abci_state.json` is the only `.json` name passed to `0x5942870` in this build.

## Evidence 2: the value writer chooses the encoder by extension

In `0x50de010`, the extension is compared with `rmp` (`0x4659e5`, `mov ecx, 3`, compare `0x159fca0`).

- Equal: `0x51ae110` with config dword `0x01000400` (`0x50de12f`).
- Not equal: `0x51adf60` with a 0x80-byte buffer and the two-byte indent `"  "` (`0x91b3c4`, length 2 at `0x50de1b9`).
- Both paths then call slot `0x64e09e8`, relocated to `0x15024a0` (the file writer that uses `fu_write_string_to_file_tmp/`, #5970).

Inference: `.rmp` is the MessagePack encoder and `.json` is pretty-printed JSON with a two-space indent.

## Evidence 3: the visor state loop

`0x5a39630` has no direct caller; one `R_X86_64_RELATIVE` entry at `0x64b8b30` holds its address. In order, it:

1. builds a line writer named `visor_abci_states` (17 bytes) through the daily slot `0x64e0f98` and the hourly slot `0x64e0fa0` (#5872);
2. calls `0x5648400` with `get_visor_state` (15 bytes);
3. builds the `visor_abci_state` path with `0x5942870`;
4. calls `0x50de010` with Location `node/src/node.rs:914:42`.

## Evidence 4: the blocking abci state writer

- The step calls `0x4e45a30` at `0x548604b` with `edx = 1`. `0x4e45a30` calls `0x4e363c0` at `0x4e45ac9` and `0x4e45b69`.
- `0x4e363c0` calls `0x5a9dd40` at `0x4e3642f`; that function references the tokio string `can call blocking only when running...` (`0x5a9de33`). `0x4e363c0` calls the closure `0x4e4b3f0` at `0x4e3649d` and `0x4e36569`, its only two direct callers.
- The closure `0x4e4b3f0`:
  1. reads `CLOCK_MONOTONIC` (`mov edi, 1`, `0x5c842e0`) and the height at `[box+0x28]` (`0x4e4b421`);
  2. serialises the box into an empty Vec with `0x5481900` under config `0x01000400`, the same dword as the rmp path of Evidence 2;
  3. writes the bytes through slot `0x64e09e8` with Location `l1/src/abci/state.rs:195:17`;
  4. reads the clock again and computes elapsed seconds as seconds + nanos / 1e9 (`0x458d50`);
  5. logs one line through template `0x43df63` (` WARN >>> `, `[height: `, `[elapsed: `), with the time format `%Y-%m-%dT%H:%M:%S%.3fZ` (22 bytes) and a 0x2b-byte message slice at `0x91875b` whose first 21 bytes are `serialized abci state`;
  6. returns the Vec as (capacity, pointer, length) at `[out]`, `[out+8]`, `[out+0x10]` (`0x4e4b6dc..0x4e4b6e8`).

Inference: the step serialises the abci state to MessagePack on a blocking thread, writes it to `hyperliquid_data/abci_state.rmp`, logs the size of the work, and hands the bytes back.

## Implementation and comparison

The tool pins 21 instruction byte runs, 22 direct calls, 24 RIP-relative references, 4 relocations, 7 strings, 2 name records, 5 Location records and the 1e9 divisor, then recomputes the caller censuses. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: decoding the encoders (out of scope); emulation (not allowed for this repository).

## Results and limitations

- Result: the only `.json` state file is `hyperliquid_data/visor_abci_state.json`, written pretty-printed by four engine/node call sites and by the visor state loop; `abci_state.rmp` is serialised and written by the blocking closure `0x4e4b3f0`.
- Limits: the encoders, the file writer, `0x5648400` and `0x5a9dd40` are named by strings and call shapes only. The message slice is 0x2b bytes long but only its first 21 bytes are the message; the rest is not explained. What the four wrapper callers pass as the value, and the rest of `0x4e45a30`'s 0x38-byte result, are not mapped. The second caller of `0x5481900` (`0x50dec72`) is not mapped.
- Next lead: the value each wrapper caller writes to `visor_abci_state.json` (`0x5443930`, `0x59ec200`, `0x5a07ec0`, `0x5a08720`).
