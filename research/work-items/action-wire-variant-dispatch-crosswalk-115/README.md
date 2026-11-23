# Node #115: crosswalk Action serializer variants to dispatch arms

This packet joins the existing `Action` serializer variant records to every entry in the node #115 relative method-dispatch table. It validates 92 index/tag rules against 92 unique table targets. The special `VoteGlobal` niche rule (`tag < 0x86`) selects default index 20 in both recorded schemes.

- Components: action-dispatch / RE-010 and action-wire / RE-005; one bounded cross-table mapping.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source record: `research/work-items/RE-010-action-serialize-tag-dispatch-115/variants.tsv`; method targets come from the raw relative table selected by dispatcher `0x36c3180` at base `0x79b120`.
- Claim status: static numerical crosswalk and target byte observations. It does not claim the serializer and method dispatcher operate on the same runtime object or that the serializer calls this dispatcher.

## Reproduce

From repository root, with Python 3 standard library plus the shared ELF/FDE parsers:

```sh
python3 tools/action_wire_variant_dispatch_crosswalk_115.py
python3 -m unittest tests.test_action_wire_variant_dispatch_crosswalk_115 -v
sha256sum -c research/work-items/action-wire-variant-dispatch-crosswalk-115/MANIFEST.sha256
```

The verifier authenticates the target digest, dispatcher FDE and instruction anchors, derives table base `0x79b120` from the dispatcher LEA, and reads all 92 signed relative entries. It joins each index with the existing serializer variant name, serde wire name, and tag rule. Every table target is required to be unique and inside the dispatcher FDE; its first 12 bytes are retained in the crosswalk.

## Evidence

The serializer record states the niche base is `0x86`, with the dataful `VoteGlobal` variant selected for any tag word below that base and default index 20. In the method dispatcher at `0x36c3180`, the code subtracts `0x86`, initializes the selected index to 20, and replaces it with `tag - 0x86` when the unsigned tag is at least `0x86`; it then indexes the signed relative table at `0x79b120`.

For all other 91 variants, the serializer record's tag value is `0x86 + index`. The verifier checks this equation and joins that same index to one unique method-table target. The resulting artifact has 92 rows, 92 distinct indices, and 92 distinct targets. For example, index 75 / tag `0xd1` / `SendToEvmWithData` selects target `0x36c3696`.

## Limits

- The serializer's variant and serde wire names are inherited from the existing serializer evidence packet; this verifier does not rerun that six-copy serializer reconstruction.
- Numerical agreement of tag class, index, and table entry does not establish runtime-object identity, a call sequence from serializer to dispatcher, or accepted external wire encoding.
- The dispatcher table's behavior for values beyond the recorded 92-entry range is outside this crosswalk.
- No source-level handler semantics, EIP-712 preimage, digest, signature behavior, or component gate closure is claimed.
- The captured executable is only read; it is never run.

## Results

- 92 serializer rows joined to indices 0 through 91.
- 92 distinct method-dispatch targets, each within FDE `0x36c3180..0x36c5348`.
- The below-base `VoteGlobal` rule maps to default index 20; all other tag values match `0x86 + index`.
- Tests cover complete join, the special niche rule, tag and table mutations, target-byte change detection, and deterministic manifest generation.
