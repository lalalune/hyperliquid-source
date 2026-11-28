# RE-017 · Node #115 retained replay batch checks adjacent Block continuity

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `2da45cb0a761cff6b478e40421699857d87a94df`. Addresses are linked ELF virtual addresses.

The [receive-order projection](https://github.com/lalalune/hyperliquid-source/pull/7279) packet establishes the decoded receive-order fields. The [verified publication](https://github.com/lalalune/hyperliquid-source/pull/7286) packet picks up after the retained batch returns ordinary results. The [signed admission](../RE-008-signed-message-admission-115/README.md) work lists the later helper call. The detail here is how the validator's adjacent-row continuity comparison gets its two operands before that helper.

1. **First retained row.** At `0x5a818b4`, the retained-buffer caller reads F+0x110 and passes it as the third argument to `0x4facd10` at `0x5a818ca`. The batch uses this word as the first row's expected identity, with its local predecessor value absent. This represents the beginning of this local batch, which supplies no earlier batch member. The selected acceptance adapter `0x5b2b500` preserves the two argument qwords in its `0x2e` result at +8/+0x10.
2. **Constructing the next row's expectation.** After the first accepted row, let P be the first preserved qword on the selected valid Block-owner path. At `0x4face1e..0x4face46`, the batch selects P+0x60 if P+0x28 equals `0x8000000000000001`, otherwise P+0xb0, then saves its unsigned saturating successor. The batch also calls `0x57e8d40` on a small descriptor with P+0x10 at descriptor +8. This helper writes two 16-byte halves to its output buffer. The batch saves those exact bytes, then stages the saved successor, present tag, and 32 bytes in the validation descriptor before passing the next input pair through the same `0x5b2b500` adapter. The second call at `0x4fad00c` uses the actual following 16-byte row of the retained input span.
3. **Comparing within the batch.** The selected validator `0x4fadcc0` chooses a layout base from incoming owner +0x30, +0x28, or +0xb8. An identity qword read at layout base+0x30 is compared against descriptor +0. With the staged predecessor present, the validator compares the 32 bytes at layout base+0x48 with descriptor +0x11. At `0x4fadd64`, the all-byte equality path continues to the separate helper at `0x4faddcf`. The first and second halves are both included. This covers the normal accepted path with layout and owner prerequisites and onward helper admission still required.

An offline replay fixture with two successive legitimately acquired rows therefore tests a link that a one-row retained fixture does not exercise. The observed byte buffer comes from the previous accepted retained Block owner. Its complete serialization or hash equivalence remains open, and the comparison supplies no ABCI state-root value or checkpoint compatibility result. The analysis assumes ordinary returns and stable aliased fields and does not exercise the target or any live peer.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-retained-batch-parent-link/verify.py
```

The [offline log](offline-log.txt) records the run and selected disassembly. The [instruction spans](windows.txt) were matched across GNU and LLVM, authenticated against the pinned ELF and located in indexed FDE extents. The verifier checks call and branch destinations, source and destination offsets, and equality across both 16-byte data lanes.
