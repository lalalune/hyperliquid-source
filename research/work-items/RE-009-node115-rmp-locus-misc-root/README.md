# RE-009 #115 complete named Locus misc subtree comparison

Compare all seven named `exchange.locus.msc` fields against the ordered raw ABCI subtree at `[0,15]`. This is the nested Locus field. The inputs use independent SHA-256 pins, the reference tree must rehash to its declared digest, and its inner `[0,0,2]` height leaf must reproduce H.

The named checkpoint writer takes Locus `+0xa38` at `0x5480d2d` and passes it to `0x5677a50`. Raw visitor `0x3d24cb0` visits the same source locations in serializer order.

| Relative raw path | Named field | Native input |
|---|---|---|
| `[0]` | `apw` | Binary64 bits from `+0x20`, little-endian |
| `[1]`, `[2]` | `ape`, `tse` | Boolean bytes at `+0x38` and `+0x39` |
| `[3]`, `[4]` | `mts`, `nts` | Unsigned little-endian qwords at `+0x28` and `+0x30` |
| `[5]` | `uts` | Address/U64 map at source base with separate ordered digest streams for keys, values, and a length leaf |
| `[6]` | `scr` | Boolean byte at `+0x3a` |

`uts` goes through named pair writer `0x528b320`. Its compact lane advances by 32 bytes per row and takes value at row `+0x18`. The raw collection visitor `0x3c57ad0` supplies the same row geometry to key and value visitors and sends the count separately to `0x41adc70`. Nonempty rows produce one digest for the concatenated 20-byte keys and a separate digest for the ordered U64 values. An empty collection only contributes its count. The comparison preserves signed zero and the ordered structure. Semantic interpretations of abbreviated fields are outside its scope.

Use exact source paths and pins from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) and [#7344](https://github.com/lalalune/hyperliquid-source/pull/7344). From the checkout root, run `python -B research/work-items/RE-009-node115-rmp-locus-misc-root/verify.py --helpers PATH --rustc PATH`. Verification checks authenticated ELF bytes and runs synthetic empty and populated cases, including signed zero, address normalization, map substream order, reference integrity and inner height. No network checkpoint or measured root is included.
