# RE-008: node #115 slow abci driver thread-pool step `0x59edc50` (43rd stage)

- Component ID: abci. Question: open PR #6016 found that the slow abci driver pops one 0x58-byte message per block and calls `0x59edc50` before it runs `spawn_slow_abci_driver_apply_block`. #6010 found the slow runner's thread pool at `+0xb48` and two maps with 0.05 and 0.35 under that step name. This packet asks what `0x59edc50` does with the message and the pool, what the 0x28-byte items are, and whether the 0.05 / 0.35 values are read on this path.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6010 and #6016. It imports helpers only from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, immediates, string bytes, relocations, Location records, FDE extents and call censuses are observations. "Thread pool", "worker", "rayon", "install", "collect", "transaction" and "signed action" are inferred labels from the vendored rayon Locations, the call shapes and the element sizes. The binary was not executed.
- Scope included: the one call of `0x59edc50`; all of `0x59edc50`; the two collect entries and their tail jumps; the item strides of both parallel maps; the two folds up to their per-element calls; the step-name call; a census of ten functions. Scope excluded: the bodies of `0x4f0c910`, `0x59e9610`, `0x4301e90`, `0x4301ce0` beyond the pinned instructions, and the per-action function `0x36c2050`, which dispatches over action variants through 21 slot calls (variant tables are out of scope for this series). No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/slow_abci_apply_115.py --check
python3 -m unittest tests.test_slow_abci_apply_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only.

## Evidence 1: the call

`0x5a34e49` in the driver `0x5a34440` is the only direct call of `0x59edc50`.

- Pool: `mov rax,[rbx+0x78]; mov rsi,[rax+0xb58]; sub rsi,-0x80`. With the runner at Arc `+0x10`, `+0xb58` is runner `+0xb48`, the pool from #6010.
- Input: `rdx = rsp+0x100`. The driver fills `rsp+0x100` from the message it pops (`lock sub [r14+0x1c0], 2` at `0x5a34a24`, the receive from #6016).
- Fourth argument: a pointer to closure byte `+0xb0` (`0x5a346d9`).

## Evidence 2: `0x59edc50` picks one of three paths

| Condition | Path |
|---|---|
| thread-local word at `fs:-0x488` is 0 | `0x4f0c910` with job `0x64b7070` |
| `[worker+0x110] + 0x80 != pool` | `0x59e9610` |
| otherwise | inline: copy the closure byte, start Vec `{0, 8, 0}`, take the message slice (`+0x8` pointer, `+0x10` length), call `0x3d9ce60` |

`0x3d9ce60` tail-jumps to `0x4301e90`, whose panic Locations are `rayon/src/iter/collect/mod.rs:100:5` and `rayon/src/iter/collect/consumer.rs:18:9`. The function returns the collected Vec at `[out+0x0..0x18]` and the message pointer at `[out+0x18]`. Inference: this is `pool.install(|| slice.par_iter().map(..).collect())`, with the cold and cross-pool paths of rayon's `in_worker`.

## Evidence 3: two nested parallel maps

- Outer: the bridge `0x3ec1b80` walks items of 0x28 bytes (`lea rsi,[r14+r14*4]; lea rsi,[r9+rsi*8]`). The fold `0x3713530` reads item `+0x20` as a pointer `p`, takes `p`'s slice at `+0x18`/`+0x20`, passes the closure byte, and calls `0x3d9d160` (tail jump to the second collect `0x4301ce0`). Each item yields a 0x18-byte Vec. Overflow panics with `too many values pushed to consumer` at `consumer.rs:126:9`.
- Inner: `0x4301ce0` allocates 0x70-byte outputs; its bridge `0x3ebdd10` walks 0x168-byte inputs; the fold `0x3713300` calls `0x36c2050` once per input and stops on a returned word `0x1a3`.

Inference: 0x168 bytes is the decoded signed-action size from #5878, so each 0x28-byte item is a transaction whose action list is at `p+0x18`, and the pool maps every action of every transaction in parallel before the block is applied.

## Evidence 4: the result goes to the apply step

The driver moves the 0x20-byte result to `rsp+0x40` and calls `0x4e47900` with the name `spawn_slow_abci_driver_apply_block` (0x22 bytes, `0x93b00f`) and `edx = 1` (`0x5a34f0d`).

## Evidence 5: no threshold read on this path

Over `0x59edc50`, both collect entries and bodies, both bridges, both folds and `0x4e47900`, the tool finds no RIP-relative `movsd` load and no direct call to the map inserts `0x51d4530` / `0x51d4df0` from #6010. The census is a byte shape; a read through a pointer the caller passes in is not excluded.

## Implementation and comparison

The tool pins 36 instruction byte runs, 9 calls, 2 tail jumps, 5 RIP-relative references, one string and three Location records, and recomputes the caller census, the slot-call count of `0x36c2050` and the threshold census. Tests change one byte in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: per block, the slow driver runs a parallel pre-pass on its own thread pool over every action of every transaction in the message, then applies the block on a blocking thread.
- Limits: what `0x36c2050` computes per action (variant dispatch, not entered); what the closure byte `+0xb0` selects; the cold and cross-pool bodies; the 0x70-byte output layout; where the 0.05 / 0.35 values are read.
- Next lead: what `spawn_slow_abci_driver_apply_block`'s closure does with the 0x70-byte outputs.
