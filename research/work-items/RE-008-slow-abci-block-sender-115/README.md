# RE-008: node #115 'slow abci block' handle: who sends into it (41st stage)

- Component ID: abci. Question: the 40th stage (open PR #6011) found that both pollers call `0x5a6cbc0` (slot `0x64e7458`), which returns a 'slow abci block' handle and starts the 'node slow abci_state driver' thread. It left open who sends into that handle, whether a send can block or drop, and what the 5000 in the handle does.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6010 and #6011. The tool imports helpers from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, constants, strings, relocations, FDE extents and call censuses are observations. "Channel", "counter", "permit", "closed", "push", "wake", "queued messages" and "observer group" are inferred labels from the access shapes and the strings. The binary was not executed.
- Scope included: the handle stores in `0x5a6cbc0`; the handle's place in both pollers and its move into the 'node handle client blocks' task; that task's body `0x2a92960`; the send site in `0x5a6e1e0`; the observer-group calls in the sender and in the driver; the driver's own send at `0x5a34554`. Scope excluded: the bodies of `0x581a2d0` and `0x581a4f0`, the driver's receive, the message contents, and the second channel the driver sends to. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/slow_abci_block_sender_115.py --check
python3 -m unittest tests.test_slow_abci_block_sender_115
```

The tool reads the ELF only. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the handle

`0x5a6cbc0` writes 0x28 bytes at `[rdi]` (`0x5a6ce72..0x5a6ce85`):

| Offset | Value |
|---|---|
| `+0x0` | channel Arc: allocation of 0x200 bytes with alignment 2^7 (`mov edi, 0x200` / `mov esi, 7`) |
| `+0x8` | a 0x18-byte `{1, 1, 0}` counter Arc |
| `+0x10`, `+0x18` | the name `slow abci block` (`0x93afd9`), length 15 |
| `+0x20` | 5000 (`mov qword [rsp+0x60], 0x1388`) |

## Evidence 2: where the pollers keep it

- Poller `0x2aeaef0` passes `r12 = rbx + 0xaf0` as the builder's `rdi` (`0x2aecf7e`, call `0x2aed2f5`), so the handle lives at state `+0xaf0..+0xb18`.
- Later it copies those 0x28 bytes (`0x2aee2dd..0x2aee306`) into a 0x718-byte closure at `+0x6e0` and starts it through slot `0x64e1750` with the name `node handle client blocks` (25 bytes, `0x605bc9`) and vtable `0x64471a0`.
- Poller `0x2cb6500` does the same (`0x2cb980d..0x2cb982f`, name `0x60f021`, same vtable).
- Vtable `+0x18` is `0x2a92960`. It copies the closure's `+0x6e0..+0x708` to the stack, sets `rcx` to that copy and calls `0x5a6e1e0` through slot `0x64e71d0` (`0x2a929ba`), the slot's only call.

## Evidence 3: the one send

`0x5a6e1e0` (`0x5a6e1e0..0x5a70656`) keeps `r13 = rcx`, loads the channel `[r13]` into `rbx` and `[rsp+0x110]`, the counter `[r13+8]` into `[rsp+0x210]`, and `chan+0x80` into `[rsp+0x398]`. Its one send site is `0x5a6fd83..0x5a6fe24`; two paths jump into it.

1. `lock inc [counter+0x10]` (`0x5a6fd8b`).
2. Load the word at `chan+0x1c0`. If bit 0 is set, go to the closed path. If it is `-2`, go to an overflow path. Otherwise `cmpxchg` it to value + 2.
3. Call `0x581a2d0` with `rdi = chan+0x80` and the message at `[rsp+0x60]`. This is the only direct call of `0x581a2d0` in `.text`.
4. `or 2` into the word at `chan+0x110`; if it was 0, take and call the stored callback at `chan+0x100`/`+0x108` (read from the listing).
5. Closed path: free the message's Vec of 0x28-byte elements (dropping an Arc at each element `+0x20`) and `lock dec [counter+0x10]` (`0x5a6ff1e`).

Inference: this is an unbounded channel send. It never waits and never refuses for being full; it fails only when the channel is closed, and then the message is dropped. The counter tracks messages in flight.

The sender never reads the handle's `+0x20`: no `mov r64, [r13+0x20]` and no immediate 5000 occur in `0x5a6e1e0`. What reads the 5000 is not mapped.

## Evidence 4: the observer groups

Slot `0x64ebbc8` is `0x51c9cb0`, the builder from #5872 that makes `{name}_block_duration`, `{name}_backlog_from_node`, `{name}_begin_block_to_commit` and a `{name}_block_times` writer. It has two calls:

| Caller | Name | f64 |
|---|---|---|
| `0x5a6e22a` (sender) | `node_fast` | 0.35 |
| `0x5a3468a` (driver) | `node_slow` | 0.5 |

## Evidence 5: the driver's own send

The driver closure `0x5a34440` loads a counter from `+0x30` and a channel from `+0x28` of its state, and sends with the same permit shape (`0x5a34554..0x5a3459c`), pushing through `0x581a4f0`. That is a second channel, not the receive side of the 'slow abci block' handle.

## Results and limitations

- Result: the 'slow abci block' channel has one sender, the 'node handle client blocks' task started by each poller. A send never blocks and never drops for being full; the 5000 is not used on the send path.
- Limits: the receive side of the handle in the driver; the message contents (a Vec of 0x28-byte elements plus 0x40 bytes); what reads the handle's 5000; the second channel at driver state `+0x28`; the bodies of `0x581a2d0`, `0x581a4f0` and `0x51c9cb0`'s per-call values.
- Next lead: the driver's receive of the 'slow abci block' channel (closure `+0x80`) and what it does with each message.
