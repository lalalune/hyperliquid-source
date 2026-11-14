# RE-008: node #115 non-validator catch-up task poll `0x2b1df60` (69th stage)

- Component ID: abci. Question: the 68th stage (open PR #6058) found a third layout-A abci step `0x2d25620`, reached only from the task poll `0x2b1df60`, which loads "non-validator abci state not caught up yet" and "using initial abci state from non-validator". It left open the poll's loop: how blocks arrive, when it counts as caught up, and what it does then.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6023 and #6058. It does not depend on their files.
- Claim status: instruction bytes, constants, string bytes, relocations, FDE extents and call censuses are observations. "Block", "counter", "consensus time", "wall clock", "deadline", "caught up", "round" and "engine value" are inferred labels from the strings, the log templates, the arithmetic shapes and earlier packets (#5861 time add, #6004 box +0x60 consensus time). The binary was not executed.
- Scope included: the loop entry, the receive call and its end check, the per-block call chain to the step, the counter, the caught-up test, both logs and the engine value copy on the caught-up branch. Scope excluded: the receiver `0x2b149d0` and its channel source (networking boundary), the shim `0x2d275d0`, where the initial engine value in the poll state comes from, and what the awaiting parent does with the poll's output. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/nonvalidator_catchup_115.py --check
python3 -m unittest tests.test_nonvalidator_catchup_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: entry and reach

- The poll's FDE is `0x2b1df60..0x2b1f5f2`. No `call rel32` targets it; an `R_X86_64_RELATIVE` word at `0x6449fb0` holds its address.
- Before the loop it calls the shim `0x2d275d0` once (`0x2b1e1f8`, its only direct call) and stores 0 to the counter `[rsp+0x28]` (`0x2b1e1fd`).

## Evidence 2: receive and per-block step

- Each iteration calls `0x2b149d0` (`0x2b1e252`, its only direct call). If the result word `[rsp+0x190]` is 0, it jumps to `0x2b1efbf`, which loads the message at `0x60608e` ("client block recver ended before valid block") and calls the panic slot `0x64df6b8`. The receiver is not followed.
- A received block goes to `0x2774590` (`0x2b1e3ee`, its only direct call). That function's call at `0x27745e0` is the only direct call of the wrapper `0x2d23610`, which reaches the 68th-stage step `0x2d25620`.

## Evidence 3: counter and caught-up test

- `[rsp+0x28]` is incremented and saturates at `u64::MAX` (`cmove` at `0x2b1e605`).
- The box consensus time is loaded from `+0x60` (qword) and `+0x68` (dword) (`0x2b1e616`, `0x2b1e622`).
- If the counter is below 6 (`cmp rax, 6` / `jb` at `0x2b1e652`), the test is skipped and the poll is not caught up.
- Otherwise the deadline is consensus time + 2 s (`edx`) + 500000000 ns (`ecx`) through the time-of-day add slot `0x64e0f78`, the same overflow range checks and `/ 86400` magic as #5861, and the date add slot `0x64e0aa0`. A failed addition uses the far-future tuple `0x4679d0`.
- Caught up when the deadline is strictly later than the wall clock: date compared signed (`setg`), then seconds (`seta`), then fraction (`jbe` to not caught up). Reading: the state counts as caught up after at least 6 blocks once its consensus time is within 2.5 s of wall-clock time.

## Evidence 4: logs and hand-off

- Not caught up: when counter % 10 == 0 (multiply by `0xcccccccccccccccd`, `ror 1`, compare with `0x199999999999999a`), it formats template `0x44bccf` (`... @@ [n_abci_blocks_seen: {}]`) with the message pointer `0x606039`.
- Caught up: it formats template `0x4309cd` (`[abci_time] [wall_time] [round] [height]`) with the message pointer `0x606063` ("using initial abci state from non-validator") and box `+0x30` as the round argument, then copies the 0x470-byte engine value out of its state through the copy slot `0x64df508` (`mov edx, 0x470` at `0x2b1ecc9`). 0x470 is the engine value size from #6006/#6008.

## Implementation and comparison

The tool pins 40 fixed instruction byte runs, 14 RIP-relative or rel32 references, three message strings, two template fragments, one relocation and the poll FDE, and runs a one-pass direct-call census over five targets. Eight tests mutate one byte in a copy of the image and expect rejection. Alternatives considered: following the receiver to its sender (networking, out of scope); emulation (not allowed for this repository).

## Results and limitations

- Result: the catch-up poll applies received blocks with the third step until at least 6 blocks have been applied and the state's consensus time is within 2.5 s of the wall clock; it logs progress every 10 blocks, then logs "using initial abci state from non-validator" and moves the engine value out.
- Limits: where the initial engine value in the poll state comes from (no direct call to the `hyperliquid_data` path builder `0x5942870` was found in the poll); what the shim `0x2d275d0` does; the receiver and its channel; what the awaiting parent does with the poll's result; the register values stored next to the message pointers (`0x55`, `0x57`, and `esi = 0x59` for the panic) are recorded in the objdump windows but not interpreted.
- Next lead: the shim `0x2d275d0` and the source of the poll's initial engine value.
