# RE-008: node #115 hardfork_hashes channel (56th stage): sender origin, push and pop census, and the l1 hash

- Component ID: abci. Question: #6037 (stage 55) found that the slow abci driver closure `0x5a34440` sends one 0x28-byte {height, 32 bytes} message on `[closure+0x28]` when the closure's first byte is 0. It left open where that sender comes from, who receives, and what the 32 bytes are.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues #6011 and #6037; it imports helpers only from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, constants, strings, relocations, FDE extents and call censuses are observations. "Channel", "sender", "receiver", "block", "blocking mode" and "l1 hash" are inferred labels from the layout, the strings and the call shapes. The binary was not executed.
- Scope excluded: the poller code that produces the awaited 0x7f0-byte value; the live receive for this channel; everything behind the networking boundary at `0x2cdca20`; the body of `0x5a6db30` beyond its send. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/hardfork_hashes_receiver_115.py --check
python3 -m unittest tests.test_hardfork_hashes_receiver_115
```

The tool reads the ELF only. The five `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: where `[closure+0x28]` comes from

- The builder `0x5a6cbc0` (#6011) copies 0x78 bytes from its 4th argument (`r15`) to the closure image at `rsp+0x80` (`0x5a6cd79..0x5a6cdd7`), puts the runner at closure `+0x78` (`0x5a6cd71`) and the slow abci block channel and counter at `+0x80` / `+0x88` (`0x5a6cddf`, `0x5a6cde7`), then boxes 0xb8 bytes (`0x5a6ce24`, `0x5a6ce43`). So closure `+0x28` / `+0x30` are bytes `+0x28` / `+0x30` of that argument.
- Both pollers pass a copy of their state `+0x9d0` as that argument: `0x2aed259` / `0x2aed2ea` and `0x2cb8879` / `0x2cb890a`.
- Poller `0x2aeaef0` stores `+0x9d0` from `rsp+0x2e98` (`0x2aecad9`, `0x2aecaf9`), which is field `+0x758` of a 0x7f0-byte value it copies after an await (`0x2aeca29`).
- So the sender is poller state `+0x9f8` and its counter `+0xa00`; the closure's first byte is poller `+0x9d0`.

## Evidence 2: the channel type and its four senders

The push `0x581a4f0` takes a tail index with `lock xadd [chan+8]` and works on blocks of 0x520 bytes: 32 slots of 0x28 bytes, start index `+0x500`, next `+0x508`, ready bits `+0x510`, observed tail `+0x518` (`0x581a500`, `0x581a513`, `0x581a577`, `0x581a592`). It has four direct calls:

| Push | In | Sender / counter |
|---|---|---|
| `0x5a3459c` | `0x5a34440` slow driver (hardfork_hashes, once) | `[closure+0x28]` / `+0x30` |
| `0x5a6dc49` | `0x5a6db30` (called from `0x5443930`, `0x59ec200`) | `[rcx+0x28]` / `+0x30` |
| `0x59ed370` | `0x59ec200` slow step wrapper (#6021) | `[r12+0x50]` / `+0x58` |
| `0x5a6cb1d` | `0x5a6c8f0` (called from `0x5443930`) | `[rsi]` / `+0x8` |

Each push site builds a {u64, 32 bytes} message. Inference: the same {height, hash} messages also come from the per-block step wrapper and the `node.rs:659` writer `0x5443930`; that these four sites share one channel instance is not proven.

## Evidence 3: the receive side is not this pop copy

- The matching pop `0x5819770` reads the same layout (`0x5819784`, `0x58197bb`, `0x58198f0`, `0x58198f4`, free 0x520 at `0x581988f`). Its only two calls are in `0x5a8b510` and `0x5a8d5b0`, which are reached only through relocations `0x64e7230` and `0x64e72f8`; each one pops until empty, frees the blocks and the 0x200-byte channel. Inference: these drain the channel on drop, so the live receive is elsewhere.
- Ten functions free 0x520-byte blocks. A second pop with the same layout, `0x2ccf3d0`, is called from `0x2c8f050`, `0x2c92fb0`, `0x2cda0b0` and `0x2cdca20`. `0x2cdca20` is the peer-connection loop that polls the verify_peer ticker (#5963, #5964): the networking boundary. This packet stops there and does not tie that pop to this channel.

## Evidence 4: the 32 bytes are the l1 hash

- The worker calls `0x452aab0` with `edx = 1` (`0x54847a5`, `0x54847aa`). `0x452aab0` tests `edx` (`0x452aac4`), switches the thread into blocking mode (strings "can call blocking only when running on the multi-threaded runtime", "closure claimed permanent executor"), then calls `0x457cf60` (`0x452ac61`).
- `0x457cf60` loads the BLAKE3 IV `0x457ae0` (`0x457cfae`), updates through slot `0x64df510` → `0x160b3a0` and finalizes through slot `0x64df518` → `0x160bcd0` (32 bytes, `mov edx, 0x20` at `0x457d14a`), reads the clock, and logs WARN `computed l1 hash: ` (`0x431bda`, template `0x43df63`) with height and elapsed time.
- So the hardfork_hashes message is {height, l1 hash}. What the l1 hash covers is not mapped here.

## Implementation and comparison

The tool pins 41 instruction byte runs, 5 RIP-relative references, 4 relocations and 4 strings, and recomputes the push census, both pop caller censuses, the callers of `0x5a6db30` / `0x5a6c8f0`, and the list of functions that free 0x520-byte blocks. Tests mutate one byte at a time in a copy of the image (8 mutation tests).

## Results and limitations

- Result: the hardfork_hashes sender is a field of the poller's awaited value; the channel carries {height, 32-byte hash} messages from four sites; the hash in the startup message is the l1 hash (BLAKE3).
- Limits: the producer of the awaited 0x7f0 value; whether the four push sites share one channel instance; the live receive (inlined somewhere, not found by the call census); `0x2ccf3d0` and its callers past the networking boundary; what the l1 hash covers; correction to an earlier note: the `/tmp/abci_checkpoint*` strings are in `0x5a6dd30`, not in `0x5a6db30`.
- Next lead: what `0x457cf60` hashes for the l1 hash (its input pointer from `0x5484670`).
