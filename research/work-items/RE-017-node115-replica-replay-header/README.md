# RE-017 · Map replica header fields to the #115 replay preflight

The #115 replica archive's `abci_block.hardfork` fields populate the two qwords called `block_parent_time` in the current Rust apply-block input. The timestamp comes from different bytes. Feeding the archived timestamp to those two inputs would compare it against the wrong state fields on the first block.

Linux x86-64 #115 artifact SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `2da45cb0a761cff6b478e40421699857d87a94df`. [Replica JSON schema](../RE-017-node115-replica-json-schema/README.md) established the outer and nested field names. [Apply-block guards](../RE-009-node115-abci-apply-block-guards-and-history-prune/README.md) established the comparisons. The tables here join them using both the member loads and the selected value writer.

| Archive field | Native writer input | Replay input |
| --- | --- | --- |
| `height` | Outer record `+0x80`, decimal qword | Sequential archive coordinate. Keep independent from every round. |
| `abci_block.round`, `parent_round` | Inner block `+0x18`, `+0x20`, decimal qwords | `EngineBlock.new_round`, `EngineBlock.prev_round`. Native requires an advancing round and a match with the state's previous round. |
| `abci_block.hardfork.version`, `hardfork.round` | Inner block `+0x28`, `+0x30`, decimal qwords | `ApplyBlockPipelineInput.block_parent_time` in this order, despite the historical name. The independently restored qwords at state `+0x18`, `+0x20` supply the companion field `state_time`. |
| `abci_block.time` | Inner block `+0x38` through `+0x43`; quoted date, `T`, time formatter | Preserve the timestamp text for fixture comparisons. Its native ingress loads are distinct from the two hardfork words. |
| `abci_block.proposer` | Inner block `+0x44`; fixed 20-byte hex value | Preserve the proposer bytes for fixture comparisons. |

The hardfork object writer at `0x4d6de30` emits `version` from the passed base and `round` from that base plus 8. The enclosing writer passes the block base plus `0x28`. The preflight reads the nested block pointer at `0x5a04e71`, then obtains these same qwords in RSI and RDX at `0x5a04ea3` and `0x5a04ea7`. The unchanged RSI/RDX values are compared with the state qwords at `0x5a04f17` and `0x5a04f20`. Both mismatch branches target `0x5a0626d`. In the same preflight the timestamp's qword and dword are loaded from `+0x38` and `+0x40` and staged independently.

The quoted timestamp follows `0x5076270` to `0x4fcd860`. Its formatter writes the date fragment, emits `T` at `0x57a6f34`, and advances the source by 4 for the time formatter. [Quicknode's block schema](https://www.quicknode.com/docs/hyperliquid/datasets/blocks) and [Dwellir's block schema](https://www.dwellir.com/docs/hyperliquid/data-catalog/node-feeds/blocks) show zone-free timestamps with nanosecond fractions and separate nested hardfork metadata. The local projection preserves timestamp text, including all fractional digits.

[project.py](project.py) maps an input row into a typed header. It exposes the existing pipeline tuple names as a boundary adapter, keeps the canonical names on the parsed data, and checks an explicit `height` against the caller's archive coordinate when both are available. The caller supplies the coordinate for a heightless archive and supplies restored hardfork metadata independently. The remaining fixture fields still require their own evidence, including the loader sequence, copied round, header/payload counts and state root. This is an offline field projection over an ordinary selected row; state restoration and apply-block execution are outside its scope.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replica-replay-header/verify.py
```

The verifier checks the recorded LLVM instruction bytes against the pinned ELF and its FDE extents, verifies literal targets and relative/relocated calls, and checks synthetic controls. In particular, changing only the timestamp leaves the hardfork comparands equal, while changing either hardfork word makes them unequal. [offline-log.txt](offline-log.txt) records the actual run. The ELF is read as data.
