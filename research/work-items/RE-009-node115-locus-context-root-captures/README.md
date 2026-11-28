# RE-009 · Localize Locus and Context differences in node #115 roots

A raw ABCI tree mismatch under root slot `[0]` can now be attributed to one of 16 named checkpoint Locus fields. A mismatch below `[0,0]` can be attributed to one of 13 Context inputs. The [capture table](captures.tsv) lists the ordered paths, compact state offsets, descriptors, constructors and visitors.

| Important Context value | Raw tree path | Compact offset |
| --- | --- | --- |
| `hardfork_height` | `[0,0,0]` | `+0x10` |
| `hardfork` | `[0,0,1]` | `+0x18` |
| `height` | `[0,0,2]` | `+0x28` |
| `round` | `[0,0,4]` | `+0x30` |
| `time`, `prev_time` | `[0,0,5]`, `[0,0,6]` | `+0x60`, `+0x6c` |

Root slot 0's descriptor `0x64a8160` binds to constructor `0x3d29f50` and visitor `0x3d2a000`. The constructor allocates 16 entries of 24 bytes and initializes their sentinel words. The visitor takes the compact builder's 16 contiguous capture pointers, builds the 16 data/descriptor pairs in order, and dispatches them through `0x3ddbda0`. The first capture is the object base and its descriptor is `0x6479380`, which binds to the Context visitor `0x43037c0` and constructor `0x4303730`.

The Context constructor allocates 13 entries of 24 bytes. The visitor builds 13 singleton slices in source order, checks the destination's entry count, and processes each 24-byte destination in turn. It creates a child via descriptor `+0x20` when the entry is empty, calls the writer at `+0x18`, and stops on a child status other than 4. Context height, hardfork height, the three counters, and `mac` reach the 8-byte leaf writer `0x14199b0` directly. The round and system nonce visitors tail-jump to the same writer through relocation slot `0x64df530`. Their successful direct path appends the input word in little-endian byte order. The serialized checkpoint reader and writer have different encoding boundaries from these leaf preimages.

The [compact slot map](../RE-008-abci-hash-slots-115/README.md) establishes the outer group slot. The [keyed result packet](../RE-017-abci-keyed-result-115/README.md) follows a particular grouped child 4. [#7303](https://github.com/lalalune/hyperliquid-source/pull/7303) ties checkpoint serialization keys to compact capture offsets. This packet adds the complete grouped visitor routes and the nested Context capture table. [#7333](https://github.com/lalalune/hyperliquid-source/pull/7333) can locate differing tree paths when both exports retain their trees. These checks identify preimage inputs and do not establish a live checkpoint restore or any H/H+1 digest values.

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From repository root, with the pinned artifact present:

```sh
python3 -B research/work-items/RE-009-node115-locus-context-root-captures/verify.py
```

The verifier statically decodes the two ordered setup instruction streams, checks the literal references, FDEs, relocations, and selected direct and indirect call sites, and compares the recovered rows to the checked-in table. [Measured offline output](offline-log.txt).
