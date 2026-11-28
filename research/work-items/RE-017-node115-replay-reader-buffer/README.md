# RE-017 #115 replay decoder input buffer

The selected producer at `0x5a806f0` takes the input pointer and length for decoder `0x5860bb0` from the completion result of TCP read future `0x5ab4390`. In the ordinary buffer-return arm, the future transfers ownership of the buffer to the producer. This supplies the input-side link for [the replay payload pair](../RE-017-node115-replay-payload-pair/README.md), which starts its dataflow at the decoder call. The TCP reader attribution is supported by [the existing source-location packet](../RE-001-node115-loc-edge-5ab4cd5/README.md).

| Site | Observed behavior |
| --- | --- |
| `0x5ab4bfa–0x5ab4e31` | The reader saves the requested size at reader+0x58. The selected allocation arm passes that size to the function resolved through GOT slot `0x64df598` and records the returned base at +0x68, with the size at +0x60 and +0x70. The zero-size arm uses base value 1. It starts the cursor at zero at +0x78. |
| `0x5ab56ed–0x5ab5768` | The next chunk uses the saved base plus cursor as its destination and limits the remaining byte count to `0x3d0900`. It stores the destination and count at +0xa0 and +0xa8. The completed arm at `0x5ab5536–0x5ab5559` advances the cursor by the stored chunk size. |
| `0x5ab57a7–0x5ab5888` | At completion with reader+0x50 clear, `0x5ab586c` reloads +0x60/+0x68/+0x70. It reaches the shared output stores at `0x5ab5824`, `0x5ab5827` and `0x5ab582b`, writing allocation size, base pointer and span length to output+0/+8/+16. |
| `0x5a80ca9–0x5a80de7` | The producer passes stack+0xf0 as the output. On the selected completed result it loads the returned base and span length into RBP and R15, then copies them to RSI and RDX for `0x5860bb0`. |
| `0x5a80dec–0x5a80e1a` | After decoder result tag `0x12`, the producer checks allocation size and releases the buffer when the size is nonzero. It passes the same base pointer, allocation size and zero to the release call. |

The packet covers the ordinary buffer-return arm with reader+0x50 clear. The alternate completion path goes through a separate helper and is outside this observation. The handoff establishes the source of the decoder's byte span at this call site. A captured packet or checkpoint fixture would be needed to identify its contents for an actual replay.

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-replay-reader-buffer/verify.py
```

The verifier hashes the pinned ELF, checks the instruction bytes within their FDE ranges, and validates the selected operands, branch targets and GOT relocations. It reads the ELF as data. See [the raw run](offline-log.txt) and [the selected instructions](windows.txt).
