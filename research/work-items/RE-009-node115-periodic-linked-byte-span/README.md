# RE-009 · Match a node #115 periodic payload to the linked digest byte span

For both native periodic/freeze serializer layouts, the successful file-write and linked-digest paths receive the same pointer and length. The on-disk periodic payload can therefore supply the exact state bytes for a linked-digest check on this selected route, provided the retained file belongs to the same successful write and has not been replaced.

| Boundary | Compact layout | Expanded layout |
| --- | --- | --- |
| Named MessagePack serializer call | `0x4e4b010 → 0x5480950` | `0x4e4b480 → 0x5481900` |
| Common file-writer call | `0x4e4b063` | `0x4e4b4d3` |
| Exact pointer and length returned by closure | `0x4e4b26f..0x4e4b278` | `0x4e4b6df..0x4e4b6e8` |
| Same two values copied into the linked input and used | `0x5a0802c..0x5a080b9` | `0x5a0888c..0x5a08919` |

Both closures configure the serializer with `0x01000400`, pass its vector pointer and length to slot `0x64e09e8`, and preserve those words for the returned capture. The common writer `0x15024a0` forwards them to `0x5ca5110` as the source and byte count. On the selected successful path, the resolved dynamic `write` call walks that source and count as bytes are consumed. There is no output header or capacity copy on this path. The selected success continuation then passes its temporary destination through the existing rename binding. The save and hash paths use a shared source slice, while the digest helper adds its own separate raw root input.

The [step-linked-hash evidence](../RE-008-step-l1-hash-115/README.md) identifies both serializer families and the linked digest ABI. The [expanded linked-state packet](../RE-017-abci-linked-commit-115/README.md) follows the expanded capture already. The [file-write evidence](../RE-009-abci-state-export-115/README.md) establishes the writer's transfer loop. This packet joins the exact pointer/length words and file sink for both layouts and adds a two-artifact byte check. [#7317](https://github.com/lalalune/hyperliquid-source/pull/7317) decodes an LZ4 archive frame. [#7351](https://github.com/lalalune/hyperliquid-source/pull/7351) identifies the periodic payload and separate status files. [#7378](https://github.com/lalalune/hyperliquid-source/pull/7378) consumes an exact state slice to compare digest artifacts.

Use the decoded MessagePack payload and a separately retained serializer span. The comparator reads both in bounded chunks, checks both supplied SHA-256 values, and reports the first differing offset including a truncated or appended tail. It measures byte equality and does not establish producer identity, height, filesystem durability, or correspondence with a separately timed hardfork worker invocation. No actual H/H+1 archive was provided.

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From the repository root with the pinned target available:

```sh
packet=research/work-items/RE-009-node115-periodic-linked-byte-span
python3 -B "$packet/verify.py"
python3 -B "$packet/compare.py" PERIODIC.rmp PERIODIC_SHA256 SPAN.bin SPAN_SHA256
```

A match exits 0, a measured difference exits 1, and a malformed or unpinned input exits 2. The [measured offline output](offline-log.txt) includes authentic static ELF checks and synthetic byte comparisons only.
