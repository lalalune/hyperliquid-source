# Node 115 HIP-3 `sub_deployers` serializer handoff

This packet joins previously separate evidence for the `Hip3.schema` record,
its `sub_deployers` field helper, the sequence wrapper and loop, and the element
writer. It traces all three compiled copies from schema field offset `+0x50` to
the sequence element's action-name and address-set writer calls.

The bounded question follows the explicit next step in merged [PR #4549](https://github.com/lalalune/hyperliquid-source/pull/4549).
It advances the open DEX-registry acceptance issue [#3920](https://github.com/lalalune/hyperliquid-source/issues/3920),
but it does not prove an authorized state mutation, the valid Rust type or
runtime ownership/lifetime of these values, or any component gate.

## Target and reproduction

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Coordinates are ELF virtual addresses; function ranges are `.eh_frame` FDE
  extents. The verifier uses Python 3, Capstone 5.0.7 and the repository's ELF
  and FDE readers.

```sh
python3 research/work-items/dex-registry-sub-deployer-handoff-115/verify.py
python3 -m unittest tests.test_dex_registry_sub_deployer_handoff_115
```

The verifier reads the pinned ELF only. It checks the full FDE byte hashes for
18 bodies across three copies and 39 exact instruction anchors, including
direct call destinations. It never executes the captured binary.

## Observations

Across all three copies:

1. Each `schema` serializer advances its record pointer by `0x50` and calls the
   matching `sub_deployers` field helper with that value pointer.
2. The field helper checks the writer's byte at `+0x1b` for equality to `1`.
   It emits the `sub_deployers` key (`0xad`) on that branch, then tail-jumps to
   the corresponding sequence wrapper with the field value.
3. The sequence wrapper sends its input to the matching sequence loop. The
   wrapper's previously reconstructed branches distinguish the B-tree form
   (`cap == 2^63`) from the split-slice form.
4. In the B-tree path, the sequence loop calls its iterator-next helper. It
   forwards the returned `RAX` value as the element writer's second argument,
   preserves the returned `RDX` value as the third argument, and supplies the
   writer as the fourth argument. The loop also contains a split-slice path
   that calls the same element writer directly.
5. The element writer passes its second argument to the action-name writer
   and its third argument to the address-set writer, then calls the tuple-end
   writer. Those callees' bodies and their output semantics are independently
   covered by merged [PR #4549](https://github.com/lalalune/hyperliquid-source/pull/4549)
   and [PR #4563](https://github.com/lalalune/hyperliquid-source/pull/4563).

The byte-level path supports the inference that a `sub_deployers` sequence
element carries an action/tag value alongside an address-set value. The exact
source-language type and which of the wrapper's container representations is
valid at this callsite remain unresolved.

## Evidence and limits

`records.json` records every selected FDE, its byte hash, all three copy
families, and the 39 instruction anchors. `verify.py` independently checks
those facts against the pinned binary. Prior packets provide the recovered
wrapper, iterator and element semantics: [schema serializers](../dex-registry-hip3-limits-schema-state-115/README.md),
[field helpers](../dex-registry-hip3-subrecord-helpers-115/README.md),
[container writers](../dex-registry-container-writers-115/README.md),
[stage and element writers](../dex-registry-stage-writers-115/README.md), and
[sub-deployer element output](../dex-registry-sub-deployers-115/README.md).

This packet does not trace the caller that constructs or authorizes the
`Hip3.schema` value. It also does not claim that the action/tag and address-set
pair is a particular Rust type, that either pointer has a particular lifetime,
or that the DEX-registry component is complete. No progress gate is changed.
