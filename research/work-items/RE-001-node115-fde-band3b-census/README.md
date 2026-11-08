# RE-001: node #115 FDE census for the `.text` band `0x3a40000..0x3a80000`

- Component ID: `foundation` allocation only; ownership of these target bodies is unresolved
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Claim status: observed FDE ranges and bytes; semantic and ownership labels unresolved
- Scope: complete FDEs whose entry VA starts in the 256 KiB band, their half-open extents, byte lengths, hashes and instruction counts

## Question

Which authenticated FDEs start in `.text` VA range `0x3a40000..0x3a80000`, and what are their exact target-derived ends, body hashes and instruction counts? This follows the next-step note in the merged [band 3a census](https://github.com/lalalune/hyperliquid-source/pull/2940).

Before starting, a live PR search for `0x3a40000..0x3a80000` returned no result; a search for `0x3a40000` found only the merged band 3a packet. No existing packet or open PR for this start-bounded interval was found.

## Reproduce

With GNU `readelf` and `objdump` on `PATH` and the signed target present:

```sh
python3 -B research/work-items/RE-001-node115-fde-band3b-census/verify.py
make doctor verify catalogue-check
```

`verify.py` reads the target in place. It checks the target size and digest, obtains `.text` and FDE ranges from `readelf`, hashes exact body bytes, counts decoded instructions with `objdump`, compares all derived rows and raw FDE lines to the saved records, checks the smallest body's prologue, and verifies the packet manifest. It never executes or copies the target.

## Evidence

| Item | Value |
| --- | --- |
| `.text` | VA `0x1419300`, file offset `0x1418300`, size `0x4fd7700` |
| band | `0x3a40000..0x3a80000` (FDE starts only) |
| complete FDEs starting in band | 58 |
| first range | `0x3a40970..0x3a4253d`, 7,117 bytes |
| last range | `0x3a7fa70..0x3a81212`, 6,050 bytes |
| smallest body | `0x3a7d0d0..0x3a7d7fc`, 1,836 bytes, 440 instructions, SHA-256 `5ec1da22be4a00c4ace34d761c9a9ddd66f505f62cf8e7abcd2e1ee40b6f8dae` |

All 58 rows and their exact `readelf` FDE lines are retained in `evidence.json` and `frames.txt`. A body's file offset is `VA - 0x1000`, derived from the recorded `.text` VA and file offset. FDE ends are not clipped to the band: the final body's end lies beyond `0x3a80000`, while remaining within `.text`.

## Interpretation and limits

This is a bounded function-map contribution to RE-001. It records compiler unwind extents, not source function names, semantics, callers, callees, or a validated component denominator. The `foundation` label is only the repository's work allocation; these bytes have not been attributed to that component. Instruction counts reflect GNU objdump's decoding. No Rust implementation, behavior, binary equivalence, or progress-gate credit is claimed.

The target was inspected statically only. The packet contains no copied upstream source and makes no claim about runtime safety or current-network compatibility. Next, map the callers and outgoing calls of one selected FDE in this band before extending the census further.
