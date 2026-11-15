# Typed greeting errors terminate two connection consumers

This packet advances backlog **HL115-028** for captured node #115 (SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`). It closes a caller ownership question: what do the actual callers do with a ready error from the typed TCP greeting reader?

On the selected normal path, both callers release the returned error, release their greeting label, invoke the live connection destructor (which requests `close(fd)` for a descriptor other than -1), and bypass the connection-admission continuation. A pending result takes a separate suspension branch. This is a static reconstruction; the captured executable was not run or emulated.

## Prior work and remaining scope

Reuse [#2572](https://github.com/lalalune/hyperliquid-source/pull/2572) and [#3339](https://github.com/lalalune/hyperliquid-source/pull/3339) for the reader/decoder contract, [#2261](https://github.com/lalalune/hyperliquid-source/pull/2261) for greeting construction and selected send paths, and [#5592](https://github.com/lalalune/hyperliquid-source/pull/5592) for typed error formatting. The new evidence is the consumer chain at `0x2acd482` and `0x2ad14e2`, not another decoder or formatter implementation.

Adjacent [#5966](https://github.com/lalalune/hyperliquid-source/pull/5966) studies the later verify-peer result in `0x2accee0`; [#5968](https://github.com/lalalune/hyperliquid-source/pull/5968) studies a connect/send path. Neither establishes the typed-greeting failure ownership chain below. The downstream consumer is a source-owned connection state machine that must distinguish a suspended read from a failed greeting before it permits connection setup.

## Binding the same connection object

Let `C` be the caller's `rbx` object. Both callers copy 0x98 bytes from `C+0x20b8` to `C+0x2160`, set the live flag `C+0x2208=1`, and store `&C[0x2160]` at `C+0x2490`. The typed reader is `R=C+0x2228`, so this pointer is exactly `R+0x268`. Its configured limit is 1000 at `R+0x20`.

The reader at `0x2b79e30` moves `R+0x268` into the embedded frame reader at `R+0x30`, then calls `0x2b788e0`. This pins the connection later cleaned up to the connection passed to the read, rather than relying on similar field offsets in unrelated objects.

| Event | Caller `0x2accee0` | Caller `0x2ad0db0` |
| --- | --- | --- |
| Copy connection, mark live | `0x2acd39d..0x2acd3b9` | `0x2ad13fb..0x2ad1417` |
| Bind reader to connection | `0x2acd459` | `0x2ad14b7` |
| Call typed reader | `0x2acd482` | `0x2ad14e2` |
| Raw result 2: store suspension state 3 | `0x2acd490..0x2acd49e` | `0x2ad14f0..0x2ad14fe` |
| Ready result's low bit selects error | `0x2acd53c` | `0x2ad154b` |
| Release error through its first vtable slot | `0x2acd656` | `0x2ad1656` |
| Release owned label when capacity is nonzero | `0x2acd658..0x2acd677` | `0x2ad1658..0x2ad1677` |
| Invoke connection cleanup if live | `0x2acddcd` | `0x2ad1de8` |
| Clear live flag and store state 1 | `0x2acddd2..0x2acdde0` | `0x2ad1ded..0x2ad1dfb` |

The ready error covers the reader's transport-error sentinel and its decoder-error conversion on their normal returns. The reader already releases a nonempty owned frame after decoding at `0x2b79f9f`; it returns the error pointer at output+8. Caller output+1/+2 are not interpreted on the error arm.

## Disposal and admission bypass

Before disposal, each selected error arm formats the error, logs the 27-byte literal `could not read tcp greeting`, and unlocks the diagnostic lock. The trace below assumes the formatter reports success, the lock operations take their normal uncontended path, and invoked helpers return normally.

`0x2ab9750` receives `&C[0x2160]`. After `0x26ead80` returns, it reads the signed descriptor at connection+0x18. If that descriptor is not -1 it calls the imported `close` via slot `0x64dfe78`. This import is verified from the ELF relocation and dynamic symbol tables. It then invokes the remaining connection-field cleanup helpers. The packet establishes the close request, not its OS result or the meaning of every cleanup helper.

Each caller then cleans up `C+0x2048` via `0x2aa7210` and carries an internal result value **2** (`r12` in the first caller, `rbp` in the second). It bypasses the value-4 arm, and later the unsigned `result > 1` test branches around connection setup:

* First caller: `0x2ace043..0x2ace047` → `0x2ace450`, outer resource cleanup → `0x2ad015b`, then `eax=0`, outer state `C+0x15d=1`, return at `0x2ad0474`.
* Second caller: `0x2ad205f..0x2ad2063` → `0x2ad2471`, outer resource cleanup → `0x2ad4183`, then `eax=0`, outer state `C+0x15d=1`, return through `0x2ad4485`.

A source reconstruction must not feed the failed greeting into the success-only setup below these tests. It must retain the live connection while suspended and consume it on the selected ready-error cleanup path. No claim is made that a separate supervising task cannot reconnect later.

## Reproduction and limits

Install the repository's recorded static-analysis dependencies, then run:

```sh
python3 research/work-items/RE-008-node115-greeting-failure-consumer/verify.py --target /path/to/original/hl-node
```

The verifier authenticates the complete ELF digest, checks 15 instruction windows (2870 bytes, 538 instructions), and checks 198 semantic facts. Its 198 corruption controls change instruction operands, import/relocation bindings, or the diagnostic literal and require rejection by semantic checks. This does not replace independent review of the dataflow argument.

The packet does not implement a TCP stack, prove all nested read/drop helpers, validate uninitialized or corrupt objects, establish unwind behavior, test close success, or exercise a live peer. Remaining HL115-028 work includes comprehensive malformed-frame behavior, timeout/cancellation ownership, and a complete source-owned transport state machine.
