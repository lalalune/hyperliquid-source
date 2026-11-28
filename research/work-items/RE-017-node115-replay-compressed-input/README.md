# RE-017 #115 compressed replay input handoff

The selected replay producer at `0x5a806f0` can receive the output of the size-prefixed LZ4 adapter rather than the original TCP buffer. This packet establishes the ownership and length boundary between that adapter and RE-017 decoder `0x5860bb0`. The existing [LZ4 packet](../RE-012-lz4-decode-115/README.md) documents the adapter itself. The [ordinary RE-017 return](https://github.com/lalalune/hyperliquid-source/pull/7243) follows the direct-buffer branch of the same reader.

| Site | Observed dataflow |
| --- | --- |
| `0x5a80c41–0x5a80cb9`, `0x5ab43db–0x5ab43df` | The producer copies +0x680 to +0x6b0, then passes its +0x690 subobject to the reader. The reader moves its input +0x20 (producer +0x6b0) to reader+0x28. |
| `0x5ab57a7–0x5ab57d5` | On the nonzero completion arm, the reader passes the original input base (+0x68), original input length (+0x70) and saved limit (+0x28) to GOT slot `0x64e7790`. The captured RELATIVE relocation resolves to LZ4 adapter `0x477f8c0`. |
| `0x477ff73–0x477ff8b`, `0x5ab57db–0x5ab588a` | The successful adapter arm writes output capacity, decoded base and decoded length to the result's +0/+8/+16. The reader uses a scratch result at stack+0xc0 and loads those fields into R12, RBP and R14. |
| `0x5ab5954–0x5ab5977`, `0x5ab5817–0x5ab582b` | The completion arm releases original compressed storage from reader+0x60 and +0x68 when the live flag and allocation size are nonzero. The shared return uses the decoded capacity, base and length. |
| `0x5a80ca9–0x5a80de7` | The producer loads the reader's returned base and length from stack+0xf8/+0x100 and passes them as RSI/RDX to `0x5860bb0`. Offline compressed input for this selected arm therefore needs a binding from the adapter output span to the recorded decoder input. |

The observation covers the selected successful compressed branch. It does not supply a captured replay record, reproduce a live exchange, establish checkpoint height, or validate a state root.

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-replay-compressed-input/verify.py
```

The verifier checks the pinned ELF digest, selected instruction encodings, FDE bounds, argument slots, branch targets and RELATIVE relocations. It reads the ELF as data. See [raw output](offline-log.txt) and [instruction windows](windows.txt).
