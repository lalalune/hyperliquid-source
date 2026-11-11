# RE-012: gossip reload metadata precision

- Component `node-runtime`; bounded question under [issue #3927](https://github.com/lalalune/hyperliquid-source/issues/3927): which metadata timestamp bits reach the existing gossip reload comparison?
- Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `0781ce04826eeefd89fe336cb8ea073be0c1de30`. Linked ELF VAs, before load bias.
- Static parsing and disassembly only; no target process, captured instruction evaluation, filesystem probe or network action. No progress gate or runtime equivalence is claimed.

## Gap and result

The [gossip reload packet](../RE-014-gossip-reload-115/README.md) maps a mixed-signed comparison of three dwords but leaves its metadata producer opaque. The [metadata packet](../RE-012-metadata-fallback-115/README.md) resolves `0x5c9c810` and its statx projection, and the [time producer packet](../RE-012-time-producer-115/README.md) identifies the difference helper and packed-date constructor. This packet binds those existing pieces through previously unresolved producer `0x15027d0`; their earlier work remains credited.

At `0x57d2fd0`, the reload owner calls relocation slot `0x64e0a10 -> 0x15027d0` using the path pointer/length at object `+0x50/+0x58`. The producer calls slot `0x64e0930 -> 0x5c9c810`. On the credited statx-success path, metadata output `+0x78/+0x80` contains modification seconds and zero-extended nanoseconds. The producer reads those fields as stack `+0x98/+0xa0`, rejects nanoseconds **>= 1,000,000,000**, and passes the pair and an all-zero origin to `0x5c84210`. A negative difference takes its error branch; successful seconds above `u32::MAX` take another error branch.

For a nonnegative accepted timestamp, normal helper return and a nonzero date-constructor result, the producer's three output dwords are: packed date from slot `0x64dfff0 -> 0x1628f50` using `floor(seconds / 86400) + 719163`, the seconds-within-day remainder, and **literal zero**. It validates input nanoseconds but does not propagate the returned fractional word into this successful triple. The exact reciprocal multiplier `0xc22e4507` implements the day quotient throughout the admitted u32 seconds domain: `86400 * multiplier = 2^48 + 47744` and `(2^32 - 1) * 47744 < 2^48`; therefore the extra fraction is smaller than one `1/86400` remainder step.

The reload owner skips the comparison when metadata returns error tag 1. On the selected non-error path it compares the producer's three dwords with object `+0x80/+0x84/+0x88`; only a strictly greater tuple reaches parser `0x50dbcb0`. When the parser's observed tag is not 2 and intervening helpers return normally without altering the saved local words, it stores those three words as the cache. Consequently, **if a previous successful reload stored this producer's tuple, a later successful statx projection for the same owner, with unchanged cached words and the same seconds but a different valid nanosecond field, produces an equal tuple and does not reach that parser through this comparison**. This is a conditional static consequence, not a claim that a particular filesystem update occurs, a runtime test, a security finding, or proof of all reload routes. Other cache writers, concurrency, metadata masks, stat64/long-path variants, helper exceptions and complete parser semantics remain outside this packet.

## Evidence and reproducibility

Five complete indexed FDEs are hashed and retained in GNU disassembly: producer `[0x15027d0,0x15028e1)` (273 bytes), reload owner `[0x57d2f80,0x57d329b)` (795), difference helper `[0x5c84210,0x5c842d6)` (198), metadata entry `[0x5c9c810,0x5c9ca28)` (536), and statx projector `[0x5c9f780,0x5c9fa97)` (791). Only the producer and the selected join/precision consequence are newly claimed; the other bodies are credited context. Their 2,593 bytes measure evidence extent, not source coverage.

```sh
PYTHONPATH=tools python3 research/work-items/RE-012-node115-gossip-mtime-precision/verify.py
(cd research/work-items/RE-012-node115-gossip-mtime-precision && shasum -a 256 -c MANIFEST.sha256)
```

On Python 3.14.5 and GNU objdump 2.42, the verifier authenticates the ELF, validates the five indexed FDE/body hashes, 93 exact instruction spans, six targets and three relative relocations. It checks the reciprocal identity and domain inequality plus boundary examples, and rejects four separate mutations to the nanosecond bound, zero store, compare branch and cache store below the whole-body hash check. The arithmetic is an independently stated mathematical relation, not a target instruction emulator. GNU raw text is retained with trailing whitespace removed. The prior metadata-fallback verifier is independently rerun to support the statx field attribution. Native library behavior, target execution and a full end-to-end filesystem scenario remain unverified. Next: establish other cache writers and the full metadata path before deciding whether a source implementation or a production defect claim is warranted.
