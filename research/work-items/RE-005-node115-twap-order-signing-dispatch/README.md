# RE-005: bind the node #115 `0xaa` signing-dispatch arm to its writer

- Component: `serialization` / RE-005.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Related task: [#3912, Action wire and signing](https://github.com/lalalune/hyperliquid-source/issues/3912).
- Claim status: exact static table selection and direct handoff; no complete signing-input reconstruction is claimed.

## Finding

The signing serializer at `0x36aa9a0` calls the action dispatcher at `0x36b1600`. When the variant word loaded from the dispatcher's input is `0xaa`, the dispatcher's `tag - 0x86` selector chooses table index 36. The signed relative entry at `0x799fec` resolves to arm `0x36b1eaf`.

That arm advances the input pointer by eight bytes and writes these pointer/length values into its stack record:

| Address | Value evidenced by the target |
| --- | --- |
| `0x36b1eb3` | pointer `0x79d5a6`, six bytes `Action` |
| `0x36b1ec8` | pointer `0x79d71e`, nine bytes `TwapOrder` |
| `0x36b1edd` | pointer `0x45a144`, four bytes `type` |
| `0x36b1ef2` | pointer `0x79c892`, nine bytes `twapOrder` |
| `0x36b1eaf..0x36b1f14` | preserves the incoming `rdx` value in the final record word |

At `0x36b1f14`, the arm calls `0x3c20f20` with the advanced input pointer in `rsi`, the output context in `rdi`, and the stack record in `rdx`. The callee is in FDE `0x3c20f20..0x3c213bb`; the retained bytes include its descriptor handoff and first mode-dependent writer steps.

This establishes which writer the `0xaa` arm in the signing dispatcher calls. The separate action-wire packet uses a different dispatcher and a different writer FDE (`0x3c213c0..`); this packet does not assume those copies are equivalent. In particular, the observed labels and handoff do not establish the entire nested order encoding, final preimage, Keccak digest, returned tag, or runtime values.

## Reproduction

From the repository root:

```sh
python3 tools/twap_order_signing_dispatch_115.py
python3 tools/twap_order_signing_dispatch_115.py --self-test
sha256sum -c research/work-items/RE-005-node115-twap-order-signing-dispatch/MANIFEST.sha256
```

The verifier checks the target size and SHA-256, exact FDE extents and body hashes, the signed table-relative target, selected arm instructions, direct call target, and pointed-to literals. Its self-test flips the selected table entry, the direct call instruction, and a referenced string byte; all three mutations must fail. It reads the captured ELF as data and never executes or emulates it.

## Limits

No name is assigned to the variant type or to the generic writer's source-level abstraction. No equivalence is claimed with another writer copy, and no change to the RE-005 acceptance gates is requested.
