# Node #115 named oracle admission lanes

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This extends [the existing admission packet](../RE-010-node115-oracle-admission/README.md), which establishes the lookup and the four bounded offsets but intentionally leaves their field names unresolved. The new scope follows the selected successful decoder output through the tagged action copy and execute call, and names those four offsets. It does not claim committed oracle writes.

| Decoded field | Payload offset | Selected admission |
| --- | --- | --- |
| `oraclePxs` | descriptor +0, count +0x18 | at most 10,000 |
| `externalPerpPxs` | descriptor +0x20, count +0x38 | at most 10,000 |
| `scalarUpdates.usdtUsdcPx` | optional triple +0x40, count +0x50 | present: at most 100, then scalar converter |
| `scalarUpdates.nativePx` | optional triple +0x58, count +0x68 | present: at most 100, then scalar converter |

The top-level decoder `0x56b4a70` recognizes the literal fields and routes them through tags 0, 1 and 2. On ordinary successful conversion, it places the two 32-byte descriptors at output +0 and +0x20 and the nested 48-byte scalar result at +0x40. The nested decoder `0x56b9380` recognizes `usdtUsdcPx` as tag 0 and `nativePx` as tag 1; its result places their triples at offsets 0 and +0x18. It normalizes a missing nested field to signed minimum as the absent marker. Present empty and absent are distinct in the subsequent call path.

The action decoder's selected successful arm `0x4d40afe` calls the decoder, sets action tag 0x9e, and stages its result words in the tagged allocation. The 0x9e arm bypasses the 0xe2 special case; the normal tail copies the staged tail from stack +0x110 to +0x218, allocates 0xf0 bytes, and copies the tagged object there. The existing packet proves the selected dispatch table entry; `0x54a3439` advances the action pointer by eight and passes it as the fourth argument to `0x552f980`. That function saves and reloads the same pointer at `0x552f9c1` and `0x552ff59`, calling `0x54cd990` at `0x552ff61`. The new windows retain those handoffs and the field dataflow; the prior admission packet supplies the lookup and conversion-result gates.

After the prior lookup and result gate succeed, admission processes present `usdtUsdcPx`, then present `nativePx`, then checks `oraclePxs` and `externalPerpPxs`, stopping on the first over-limit or converter error. The companion Rust model projects these named count lanes and the tagged payload offset from successfully decoded bytes; it does not reproduce the prior admission gate, wire decoder, converter, execution state, or resulting writes. The prior packet has no reusable source module in this baseline. The option models the observed absent marker, not all possible invalid raw descriptor bit patterns. Valid decoded payloads, normal ABI/layout handoffs, and the prior packet's selected branch are premises.

Run `python3 research/work-items/RE-010-node115-oracle-named-admission/verify.py` on the pinned input. The static verifier checks 24 selected windows, literal bytes, instruction operands and 22 altered-instruction controls. It reads original ELF bytes as data; it does not execute or emulate captured instructions. These are bounded static observations, not full component equivalence or a full decoder proof.
