# RE-009 #115 direct named Locus ctr root counters

Compare all seven direct scalar counters in `exchange.locus.ctr` with the raw tree at `[0,10]`. The inputs are separately byte-pinned, the complete supplied raw tree must reproduce its digest, and its inner Context height leaf must independently reproduce H.

| Relative slot | Named key | Counter offset |
|---|---|---|
| 0 | `tn` | `+0xc8` |
| 1 | `vn` | `+0xd0` |
| 2 | `tc` | `+0xd8` |
| 3 | `sc` | `+0xe0` |
| 4 | `to` | `+0xe8` |
| 5 | `so` | `+0xf0` |
| 7 | `ad` | `+0xf8` |

The checkpoint writer at `0x5480c92` passes Locus `+0xa78` to `0x5679120`. It emits each named qword only when nonzero. The raw visitor `0x3d2e000` always supplies these seven source words to distinct children of an eight-child branch, with one BLAKE3 digest of a little-endian Qword for each. An omitted named counter therefore expects a present zero-word leaf. Child 6 is the independent `ac` subtree and remains opaque. A pass establishes the seven scoped comparisons only.

Use the byte-pinned helper layouts from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) and [#7344](https://github.com/lalalune/hyperliquid-source/pull/7344). From the checkout root, run `python -B research/work-items/RE-009-node115-rmp-locus-ctr-root/verify.py --helpers PATH --rustc PATH`. The verifier authenticates node #115 without executing the ELF. Synthetic tests cover all counters omitted, explicit zero, maximum unsigned values, swapped leaves, independent sibling differences, stale reference and wrong inner H. No genuine checkpoint or observed network root is included.
