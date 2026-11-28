# RE-009 · Node #115 gas-auction root captures

The compact exchange fields `register_token_gas_auction`, `perp_deploy_gas_auction`, and `spot_pair_deploy_gas_auction` feed root slots 28, 29, and 30 from box offsets `+0x3a00`, `+0x3a40`, and `+0x3a80`. All use the 64-byte descriptor `0x64a84f8` with visitor `0x4d3e9b0`. The checkpoint writer's selected key loads at `0x54811fa`, `0x5481225`, and `0x5481250` distinguish the three fields. Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

The visitor requires a non-leaf destination with two 0x18-byte entries. A leaf destination returns 1. A wrong entry count returns 3. In a freshly initialized two-entry node, source dword tag 2 bypasses entry 0 and writes raw little-endian qword 0 to entry 1's leaf buffer. Every other tag initializes entry 0 via `0x3d1eb60` when needed and runs the nested visitor `0x3d1ebc0`. When that visitor returns 4, entry 1 receives raw little-endian qword 1. An earlier child error reaches the return without appending the trailing discriminant. A bypassed pre-existing entry 0 remains untouched in the tag-2 arm.

The nested allocator uses 0x90 bytes for six 0x18-byte entries, each initialized with the empty-slot sentinel. Its visitor supplies six singleton field descriptors in the following order to `0x41ade90`, whose guard requires six entries.

| Nested entry | Source offset | Descriptor |
| --- | --- | --- |
| 0 | `+0x10` | `0x6478778` |
| 1 | `+0x28` | `0x6476f58` |
| 2 | `+0x00` | `0x64787a0` |
| 3 | `+0x30` | `0x6474020` |
| 4 | `+0x20` | `0x64741c8` |
| 5 | `+0x38` | `0x6476f58` |

The slot shape and explicit discriminant provide local mismatch coordinates when comparing an independently captured raw ABCI tree. A missing aggregate, a default empty vector, and a tag-2 node with its qword-0 leaf are different inputs. The nested field writers' semantic types and the actual H/H+1 values remain open.

[The slot catalogue](../RE-008-abci-hash-slots-115/README.md) establishes the top-level descriptor. [#6894](https://github.com/lalalune/hyperliquid-source/pull/6894) identifies the wrapper as a bounded FDE with tag and guard checks. [#7303](https://github.com/lalalune/hyperliquid-source/pull/7303) maps key names to root fields. This packet binds the wrapper to slots 28–30 and follows its relocated child calls, constants, and nested field order.

## Reproduce

From the repository root with the pinned artifact available:

```sh
python3 -B research/work-items/RE-009-node115-root-gas-auction-captures/verify.py
```

The verifier reads the ELF offline and checks its digest, unwind-indexed [disassembly bytes](windows.txt), slot and name mappings, discriminant data, and relocation destinations. [Measured offline output](offline-log.txt).
