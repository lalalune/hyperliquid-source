# Owned receive body: partial reads, pending and terminal handoff

Target: node/115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, size 105896032. Static ELF/FDE and instruction data-flow only; no captured execution or emulation.

## Gap, prerequisites and consumer

The existing `src/node115-tcp-stream-frame-lz4` reconstructs a synchronous host reader. Its native asynchronous ownership, partial-read and error behavior remain excluded. `RE-012-node115-tcp-prefix` identifies `0x5cdfa50` as an opaque prefix-poll provider. The frame-plan and LZ4 findings already establish the five-byte header, inclusive length gate, chunk size and transform decision; those are reused rather than claimed as new discoveries.

This packet binds the selected receive body's allocation and chunk slice to the actual read-exact helper, its mutable ReadBuf, pending retention, zero-progress error and terminal handoff. The new `src/node115-owned-tcp-receive` uses the existing `Header`, `admit` and `next_chunk` APIs. Its consumer can retain a body receive operation across host readiness events, then pass a completed payload to the existing transform/decoder. A complete header, maximum length and host I/O/timer events remain supplied inputs.

## Owned body and borrowed chunk identity

Let `F` be the receive future passed to `0x2b788e0`. After the complete header yields length N, `0x2b7903f` / `0x2b79043` admit `N <= *(F+0x28)`. The flag is reduced to equality with 1 at `0x2b791c6` / `0x2b791ca`. Following successful allocation, the future stores its current capacity, pointer and logical length in `F+0x60`, `F+0x68`, `F+0x70`, sets the owned-buffer flag `F[0x49] = 1`, and starts completed progress `F+0x78` at zero. Allocator internals and allocation-failure timing are not reconstructed.

For completed progress C below N, `0x2b799e9..0x2b79a32` chooses `L = min(N-C, 4,000,000)`, stores L in `F+0x80`, checks the end against the allocated logical length, and forms the exact mutable slice `(P+C, L)` from `P = *(F+0x68)`. The stream pointer and this slice follow a checked copy chain:

| Item | Initial fields | Copied fields | Local stack | Inner future after 0xb8-byte copy |
| --- | --- | --- | --- | --- |
| stream | `F+0x98` | `F+0x118` | `rsp+0x120` → `rsp+0xc0` | `S+0x70` |
| chunk pointer | `F+0xa0` | `F+0x120` | `rsp+0x128` → `rsp+0xc8` | `S+0x78` |
| chunk length | `F+0xa8` | `F+0x128` | `rsp+0x130` → `rsp+0xd0` | `S+0x80` |

Here `S = F+0x170`. At `0x2b79705`, the memcpy-bound import copies from stack+0x50 to S; the listed local offsets are therefore S+0x70/+0x78/+0x80. The subsequent call at `0x2b7971a` passes this same S to `0x2b698f0`. The pointer is not a second allocation, nor a slice reconstructed from an unrelated count.

## Actual partial-read contract

`0x2b698f0` initializes ReadBuf B at `S+0x90`: pointer from S+0x78, capacity from S+0x80, filled count zero at S+0xa0, and initialized count equal to the supplied capacity at S+0xa8. On resumed states it reloads capacity and filled count rather than resetting them. The helper passes B to `0x5cdfa50` at `0x2b699db`.

The provider computes `(B.pointer + B.filled, B.capacity - B.filled)` and passes that exact interval to the ELF `recv` import at `0x5cdfb29`, with flags zero. On a successful byte count it updates `B.filled` by that count and raises `B.initialized` if needed (`0x5cdfbea..0x5cdfc04`). Readiness/error handling can return without that successful-count update; the packet does not invent a returned byte count from the provider's raw RDX error value.

After a successful no-error provider return, the read-exact helper reloads remaining capacity. If it changed, the loop continues from the updated filled offset. If a nonempty request made no progress, it constructs the literal `early eof` (nine bytes at `0x94d48e`) with raw error kind `0x25`, then wraps it through `0x2a026d0`. Empty remaining capacity succeeds before another receive attempt.

The helper's pending arm saves its inner state byte at S+0xb0 as 3 and retains B. A separate wait/timer helper through relocation `0x64e1358` participates in the outer result: raw 2 and raw 3 must not both be called Pending. The receive caller specifically tests raw 3 at `0x2b79722`; on that branch it saves the enclosing pending states and returns without advancing F+0x78. The supplied source events abstract these I/O and timer boundaries; native timer construction, TLS behavior, deadlines, error wrapper layout and readiness registration are not reimplemented.

## Complete chunks and terminal ownership

Only a successful completed inner read advances C by the current chunk length at `0x2b79838..0x2b79852`. Partial reads update B, not C. The next chunk begins at the resulting P+C. This distinction prevents a resumed read from repeating or skipping already received bytes inside a chunk.

For a nonzero terminal inner error result, `0x2b79832` branches to `0x2b79af1`: the current nonempty allocation is released using the same F+0x60/+0x68 pair and the live flag is cleared. No partial payload vector escapes. Once C reaches N, the plaintext arm clears the live flag and moves the capacity/pointer/length triple to the output at `0x2b79b32..0x2b79b66`. The compressed arm calls the existing `0x477f8c0` transform only after that completion check; the original input allocation is subsequently released. This source returns complete bytes and `decompress_after_read` to let that existing downstream transform operate separately.

The source event API is deliberately a host adapter. `Bytes` supplies bytes received within the current requested interval, an empty successful `Bytes` event on a nonempty request means EOF, and `Pending` retains ownership. Host timeout is accepted only after a supplied Pending event; this is an adapter protocol for supplying the wait helper's outcome, not a recovered scheduling rule. Oversized supplied chunks are rejected as host misuse. A zero-length admitted body completes before consulting an event because the native path requires no body receive. Rust's initialized Vec and typed outcomes model successful logical ownership, not allocator ABI or native error encodings.

## Reproduction and exclusions

```sh
python3 research/work-items/RE-012-node115-owned-receive-progress/verify.py --target artifacts/node/115/hl-node
cargo test --manifest-path src/node115-owned-tcp-receive/Cargo.toml
```

Use Capstone 5.0.7 and pyelftools 0.32. The verifier retains three complete FDEs, 1268 instructions, 151 witnesses, four relocation bindings, recv/memcpy import bindings, and the error literal. Nine negative controls cover target identity, a different chunk allocation, skipping short-read resume, accepting zero progress, advancing past pending, selecting a different ReadBuf, omitting the destination's filled offset or filled update, and releasing the wrong pointer. These controls validate retained evidence; they do not execute target behavior.

Source fixtures exercise the 4,000,000-byte chunk boundary, partial bytes and pending retention, exact payload output, limit/empty/flag cases, EOF/error/timeout without partial output, and invalid host inputs. This does not claim native header polling, timer implementation, complete LZ4 equivalence, cancellation/drop behavior, connection shutdown, native allocation-failure equivalence or a finished RE-012 component.
