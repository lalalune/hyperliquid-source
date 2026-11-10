# RE-008: node #115 slow abci driver (42nd stage): the receive loop, the per-message work and the backlog counter

- Component ID: abci. Question: the 41st stage (open PR #6014) found the single send into the 'slow abci block' channel and showed that the send never waits and never reads the 5000 in the handle. It left open how the driver `0x5a34440` (open PR #6011) receives, what it does with each message, and whether anything reads the 5000 or the counter the sender increments.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6011 and #6014. The tool imports helpers from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, constants, strings, relocations, Location records, FDE extents and call censuses are observations. "Channel", "pop", "waker", "closed", "park", "counter", "gap", "observer group" and "message" are inferred labels from the access shapes, the slot targets and the strings. The binary was not executed.
- Scope included: the closure `0x5a34440..0x5a3539f` (its FDE): start-up, the receive, the park, the per-message work. Scope excluded: the bodies of the pop `0x58189f0`, the second-channel push `0x581a4f0`, `0x5647720`, `0x59edc50`, `0x4e47900`, `0x4f18bd0`, `0x4f19fa0`; the message's field meaning beyond its size, its end sentinel and its Vec; the second channel's receiver. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/slow_abci_driver_recv_115.py --check
python3 -m unittest tests.test_slow_abci_driver_recv_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: start-up

- `0x5a3445e..0x5a34472`: `hardfork_hashes` (15 bytes, `0x93b070`) is read through `0x5647720` into `rsp+0x2b8` (the only direct call of `0x5647720`).
- `0x5a34517`: when the closure's first byte is 0, the result goes on a second channel: `[[closure+0x30]+0x10]` is incremented (`0x5a34558`), the channel is `[closure+0x28]`, its message word `+0x1c0` gains 2, `0x581a4f0` pushes on `chan+0x80` and `chan+0x110` is woken. This is the send #6014 named at `0x5a34554`.
- `0x5a3466e..0x5a3468a`: a `node_slow` group (9 bytes, 0.5 at `0x459490`) is built at `rsp+0x2b8` through slot `0x64ebbc8`, which is relocated to `0x51c9cb0`, the three-observer builder of #5872.

## Evidence 2: the receive

- `[closure+0x80]` is the channel Arc (`0x5a346b2`, `0x5a34899`).
- The pop `0x58189f0` takes `chan+0x1a0` and `chan+0x80` (`0x5a348b6`). An empty result `0x8000000000000001` registers the waker at `chan+0x100` through slot `0x64e0518` (relocated to `0x5ce91b0`) and pops again (`0x5a34904`).
- Closed: the byte at `chan+0x1b8` is 1 and the word at `chan+0x1c0` is below 2 (`0x5a34935`, `0x5a3495b`).
- Taken: `lock sub [chan+0x1c0], 2` (`0x5a34a10`, `0x5a34a24`) -- the same word and step the sender adds (#6014).
- While nothing is ready, the thread parks on `[r14+0x18]` with `ecx = 1000000000` through slot `0x64e73b8` (relocated to `0x5bb4670`) and loops (`0x5a34b50..0x5a34b6e`). Inference: the driver blocks its own thread on the channel with a 1-second park timeout; it is not an async task.

## Evidence 3: each message

- A message is 0x58 bytes: the first word plus 0x50 bytes copied from `rsp+0x48` (`0x5a34a3b..0x5a34a76`). A first word of `0x8000000000000000` ends the loop (`0x5a34c9e..0x5a34cab`).
- `lock dec [[closure+0x88]+0x10]` (`0x5a34cb6..0x5a34cbd`). The sender increments the counter at `+0x10` of the handle's second Arc (#6014). Inference: closure `+0x80`/`+0x88` hold the handle's `+0x0`/`+0x8`, and the counter is the number of messages in flight.
- The wall clock is read through slot `0x64e0990` (relocated to `0x1629690`, #5045). From the second message on (`[rsp+0xa88] != 0`), the gap since the last message is taken through slot `0x64e0fc0` (relocated to `0x162a290`), turned into seconds (`nanos / 1e9`, `0x458d50`), floored at 0, set to 0 when it is +inf (`0x459010`), capped at 60.0 (`0x459718`), and recorded with count 1 into the `node_slow` group through slot `0x64e1010`, which is relocated to the observer record `0x1547530`, Location `node/src/abci_latency_sampler.rs:60:41`.
- `get` (3 bytes) through `0x4f19fa0`, Location `node/src/node.rs:652:42`; then `0x59edc50`; then `spawn_slow_abci_driver_apply_block` (34 bytes) through `0x4e47900` with `edx = 1`; on a result, `spawn_slow_abci_driver_write_greeting` (37 bytes) through `0x4f18bd0`, Location `node/src/node.rs:732:40`.
- The message's Vec of 0x28-byte items is dropped, releasing an Arc at `+0x20` of each item (`0x5a34ffd..0x5a3507b`).

## Evidence 4: the 5000 and the counter

- The closure contains no `88 13 00 00` (5000) byte run.
- The only `lock inc/dec qword [reg+0x10]` in the closure are the second channel's increment (`0x5a34558`) and the per-message decrement (`0x5a34cbd`). Nothing in the closure compares either counter.
- Inference: in the code mapped by #6014 and here, the 5000 is stored in the handle but not used as a limit, and the counter is only kept up to date. Readers elsewhere are not searched.

## Implementation and comparison

The tool pins 30 instruction byte runs, 26 RIP-relative or call references, 5 strings, 6 slot relocations, 4 f64 constants and 3 Location records, checks the closure's FDE, and recomputes the pop and sender-push call censuses and the closure scan. A Python model of the gap clamp is checked on four samples. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: emulation (not allowed for this repository).

## Results and limitations

- Result: the slow driver is a blocking thread that pops each 'slow abci block' message, decrements the in-flight counter, records the gap between messages (0 to 60 s) into its `node_slow` group, and applies the block. Nothing in the closure reads the 5000.
- Limits: the bodies listed under scope excluded; the meaning of the message fields; other readers of the counter or the 5000 outside the closure and the sender; the receiver of the second channel; the three other callers of `0x58189f0` (`0x5a428ad`, `0x5aab82e`, `0x5aab869`).
- Next lead: what `0x59edc50` does with the message and the pool `+0xb48` (#6010).
