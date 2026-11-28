# RE-017 · Node #115 retained replay validates attachments against ordered Block digests

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `2da45cb0a761cff6b478e40421699857d87a94df`. Addresses are linked ELF virtual addresses.

The prior [attachment handoff](https://github.com/lalalune/hyperliquid-source/pull/7273) maps how the two owners are supplied to the replay worker. The [verified publication](https://github.com/lalalune/hyperliquid-source/pull/7286) packet maps where they go after the batch returns ordinary results. This packet checks the normal validation of one retained row between those boundaries. The [consensus Block encoder](../RE-008-node115-block-certificate-caller/README.md) describes the separate signing digest and fields of the Block digest vector. The ordered attachment test below uses that vector and reuses the already identified sponge primitives.

1. **Identify the two inputs.** The adapter at `0x5b2b500` saves its incoming owner words as a pair and calls `0x4fadcc0` with its address. The validator loads the original Block owner A from pair+0. On the selected response from the prior [signed admission helper](../RE-008-signed-message-admission-115/README.md), the validator reads the attachment owner B from pair+8. B+0x18 supplies the first row address and B+0x20 supplies the count. The first loop walks 40-byte rows.
2. **Check the raw payload of each attachment.** At `0x4fade39..0x4fade57`, the first 32 bytes of each row are retained for comparison. Row+0x20 refers to an individual payload owner. Its +0x18 and +0x20 fields are passed as address and length to the sponge update. The state initialization shows rate 136 and delimiter 1. The relocation-backed update and finalize calls bind to the existing Keccak routines. The finalize request is 32 bytes. At `0x4fadf28..0x4fadf45`, both halves of those bytes are compared with the row's first 32 bytes before the attachment cursor advances to validate another row.
3. **Check the correspondence with A.** At `0x4fadfc2..0x4fadfca`, B+0x20 and A+0x20 are compared as counts. With equal counts, `0x4fadfde..0x4fae049` reads the two address fields at +0x18 and compares each attachment row's leading 32 bytes against the next 32-byte digest in A. It advances B by 40 and A by 32, comparing both 16-byte halves at each step. Both spans exhaust on the selected matching route. After the remaining normal continuation selects result tag `0x2e`, the adapter writes the original A and B words at result +8/+0x10.

For legitimate offline fixtures with multiple attachments, retaining the attachment list in the same order as the Block's digest vector is observable here. The proof assumes valid initialized owners, the prior admission result, the selected ordinary completion and preserved aliased fields. It identifies the hashed byte view and the ordered comparison. It does not decode the payload's application fields, establish producer-side serialization from semantic actions, execute any capture, or compare a replayed state root.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-retained-attachment-digest-order/verify.py
```

The [offline run](offline-log.txt) records the checks. The [instruction spans](windows.txt) agree across GNU and LLVM and are authenticated against the pinned ELF. The verifier checks the two relocation entries, the source and digest offsets, both loops and exact strides, and the accepted owner projection. A synthetic two-row stride control uses distinct byte sequences. It supplies neither a native hash observation nor a replay input.
