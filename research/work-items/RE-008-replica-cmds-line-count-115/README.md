# RE-008: node #115 replica_cmds line count and the startup check flag (74th stage)

- Component ID: abci. Question: the 73rd stage (open PR #6069) found that the startup helper `0x595b1a0` takes the newest `replica_cmds` file name as a height and adds a line count from `0x1500e50`. It left open how that count is taken, what happens for `.lz4` files, and what sets the byte that turns the check on in `0x2b41b70` (#6067).
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6067 and #6069. It imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, constants, strings, relocations and call censuses are observations. "Shell command", "Once", "lazy cell", "line count" and "startup check flag" are inferred labels. The binary was not executed.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/replica_cmds_line_count_115.py --check
python3 -m unittest tests.test_replica_cmds_line_count_115
```

The tool reads the ELF only. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the line count runs `wc -l` through `/bin/sh -c`

- `0x1500e50` has no direct caller. Slot `0x64e0958` is relocated to it, and the stage 73 mapper calls that slot at `0x595bb9c`.
- `0x1500e71` `cmp dword [rdi+rsi-4], 0x347a6c2e` tests for a `.lz4` suffix. A `.lz4` path runs a Once on the lazy cell `0x64f01c0` (value word relocated to `0x1568de0`, state `0x64f01d8`) and then jumps back to `0x1500e89` (`0x1501268`) with the same path. So both kinds of file reach the same command.
- The command is three slices: `wc` (`0x4659f2`, 2 bytes), `-l` (`0x4659f4`, 2 bytes) and the path. `0x15b0450` joins them with the separator at `0x468cca` (`" "`) through `0x150d100`.
- Slot `0x64e0960` is relocated to `0x1536720`. That function builds `/bin/sh` (`0x466adc`, 7 bytes) with `-c` (`0x466ada`, 2 bytes) and the joined string. Its error text is `Shell::output() failed. cmd: "{}". output: "{}"` (`0x442e16`).
- The output is parsed with a base-10 loop (`mov edi, 10` at `0x15011a8`). An empty output gives `file_n_lines empty wc output {}` (`0x442df6`).

Inference: the line count is the stdout of `/bin/sh -c "wc -l <path>"`. The path is joined into the shell string with a plain space and no quoting seen in this function. The path comes from the node's own `{root}/data/replica_cmds` listing (stage 73).

## Evidence 2: where the startup check flag comes from

- `0x2b41b70` loads future byte `+0x1` (`0x2b41bae`) and runs the `replica_cmds` check (slot `0x64e7720`) only when it is 1 (`0x2b41d32`, `0x2b41d36`). Its direct calls are `0x2af0a5f` and `0x2cbc06b`.
- In `0x2af0660` (its only call is `0x2aec151` in poller `0x2aeaef0`), the future's first 16 bytes come from state `+0x28` (`0x2af087d` → `rsp+0x5a0` → `rsp+0x5f0` at `0x2af09f0`), and state `+0x29` is copied from state `+0x1` (`0x2af07ef`, `0x2af082f`).
- The poller fills that state at `+0x1728` from its stack at `rsp+0x320` (`0x2aec10d`, `0x2aec116`).

## Implementation and comparison

The tool pins 24 instruction byte runs, 16 RIP-relative or rel32 references, 7 strings and 3 relocations, then runs one call census over `.text`. Tests change one byte at a time in a copy of the image and expect a failure (8 mutation tests).

## Results and limitations

- Result: the replica_cmds line count is an external `wc -l` run through `/bin/sh -c`, for compressed and uncompressed names alike; the flag that enables the startup check is a byte the poller passes in from its own state.
- Limits: what `0x1568de0` (the `.lz4` Once) computes is not mapped. The "non-zipped" filter that stage 73 named (`0x15021d0`, `0x15b59e0`) has no suffix compare; the only two `.lz4` dword compares in `.text` are `0x1500e75` and `0x1505fc1`, so where zipped files are skipped is not found. The source of poller `rsp+0x320` (which CLI flag, if any) is not traced. How `0x15b0450` and `0x1536720` handle spawn errors beyond the error text is not mapped.
