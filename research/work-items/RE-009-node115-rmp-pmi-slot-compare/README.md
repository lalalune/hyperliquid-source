# RE-009 · Node #115 named checkpoint PMI to raw ABCI slot 54

The named checkpoint field `exchange.pmi` and ordered exchange ABCI branch 54 can now be compared from the two same-height files. The checker matches the requested height against the checkpoint's `exchange.locus.ctx.height` and the raw export's numeric height, verifies both SHA-256 pins, and rehashes the exported tree before comparing its PMI branch. It reports payload equality, discriminant equality and child order separately.

| Named MessagePack value | Ordered raw branch preimages |
| --- | --- |
| Explicit nil | Child 1 contains little-endian qword 0 |
| A 42-byte lowercase `0x`-prefixed Address string | Child 0 contains the decoded 20 bytes, then child 1 contains little-endian qword 1 |

A present all-zero Address has child 0 and tag 1. An omitted key has no affirmed writer value, so the checker requires an explicit value. The scope is the named writer's representation and one restored field at H. Future work needs actual exports and independently proven replay transitions for H+1.

## Native evidence

Target `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- `0x54815b5` obtains the compact field at `+0x42b0`. The call at `0x54815c2` reaches `0x5677fc0`, which names `pmi` at `0x5677fd7`.
- `0x5677ffa` tests source tag 1. The alternate writer path appends `c0` at `0x567804b`. Tag 1 advances the pointer by one and invokes `0x52f7bf0` with the literal `Address`.
- `0x52f7c40..0x52f7c50` supplies output width 42, input width 20 and a cleared fifth argument to the hex formatter. Relocation `0x64e4d08` resolves to `0x2eabb50`. The formatter starts with `0x`, uses the lowercase digit table at `0x455d40` and retains the leading nibble when the fifth argument is clear. `0x52f7c5c` forwards the resulting slice to the MessagePack string writer `0x57cf860`.
- Root builder slot 54 binds the same `+0x42b0` field to `0x4d3f050`. The tag-1 arm advances the pointer once, then `0x141b9e3..0x141b9f1` copies the 20-byte body to child 0. The tag qword constants used for child 1 are 1 at `0x4d3f0f9` and 0 at `0x4d3f147`. [#7328](https://github.com/lalalune/hyperliquid-source/pull/7328) documents the visitor. [#7465](https://github.com/lalalune/hyperliquid-source/pull/7465) compares the separately restored Context under root path `[0,0]`.

The checker uses the byte-pinned streaming parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the ordered native export reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404). Arrange those PR helper subdirectories beside this packet in a staging directory. Run from the repository root with Python and `msgpack==1.1.2` installed, Rust 1.95 or compatible, and the pinned local ELF available.

```sh
python3 -B research/work-items/RE-009-node115-rmp-pmi-slot-compare/verify.py \
  --helpers /path/to/helper-staging-directory --rustc "$(command -v rustc)"
```

To compare supplied same-height files with a built `hash_tree` executable from #7404:

```sh
python3 -B research/work-items/RE-009-node115-rmp-pmi-slot-compare/compare_pmi.py \
  HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256
```

Exit 0 means slot 54 matches, exit 1 reports a branch difference and exit 2 rejects the inputs. The [offline run](offline-log.txt) verifies native byte evidence and uses synthetic named checkpoints and raw exports with nil, zero and nonzero Address cases. It also tests payload-only and child-order differences and rejects an incorrect export digest.
