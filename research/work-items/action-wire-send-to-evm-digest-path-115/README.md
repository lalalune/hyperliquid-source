# Node #115: join the SendToEvmWithData action path to its EIP-712 builder

This packet joins one action-dispatch table entry to the signing wrapper and type builder for `SendToEvmWithData`. It establishes a selected static call path from numeric tag `0xd1` to builder `0x44290c0`; the existing type record identifies that builder as `HyperliquidTransaction:SendToEvmWithData(...)`.

- Component: `action-wire` / `action-dispatch`
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: digest-bound static call/relocation observations; action identity is corroborated by existing serializer and type-builder records. The callback producer and complete digest remain unresolved.
- This is a selected cross-path packet, not closure of issue [#3912](https://github.com/lalalune/hyperliquid-source/issues/3912), the action-wire component, or a signature-verification gate.

## Reproduce

From the repository root, with Python 3.12 and the standard library plus the shared ELF/FDE parsers:

```sh
python3 tools/action_wire_send_to_evm_digest_path_115.py
python3 -m unittest tests.test_action_wire_send_to_evm_digest_path_115 -v
```

The verifier authenticates the target digest, checks six FDE extents, nine byte anchors, three `R_X86_64_RELATIVE` call slots, two direct call targets, the selected relative-table entry, and the existing serializer/type records. It reads the ELF only; it does not execute the captured node.

## Evidence

The existing `RE-010-action-serialize-tag-dispatch-115/variants.tsv` record maps Action variant index 75 to `SendToEvmWithData` and the internal tag word `0xd1`. Independently, the selected method dispatcher at `0x36c3180` subtracts `0x86`, selects table index 75 for `0xd1`, and jumps to `0x36c3696` through signed table entry `0x79b24c` relative to base `0x79b120`.

The selected arm calls through slot `0x64e8e48`; its `.rela.dyn` relocation resolves to method `0x442d000`. That method's FDE is `0x442d000..0x442d480`. Within it:

- `0x442d192` calls through the function pointer loaded from the action record at `+0x60`. Adjacent inputs are read from `+0x68`, `+0x70`, and `+0x78`. The callback target and the code that supplies this pointer are not established here.
- `0x442d31f` directly calls `0x46e6d30`.
- `0x46e6d4c` directly calls wrapper `0x4433f90`.
- The wrapper calls through slot `0x64ea978`, relocated to hash function `0x4428520`.
- The hash function calls through slot `0x64ea980`, relocated to builder `0x44290c0`.

The existing `action-wire-typed-data-structs-115/eip712.tsv` record for builder `0x44290c0` contains the full `SendToEvmWithData` type string and type hash. The join therefore links the selected numeric dispatch route to the correct typed-data builder while reusing, rather than duplicating, the serializer and builder inventories.

## Limits

- The serializer tag mapping and method-dispatch table are independently observed. This packet establishes their matching index/tag and the downstream selected call chain; it does not prove every runtime action object follows this route or that the two observations share a particular object instance.
- The dynamic callback at action record `+0x60` remains unresolved. No bytes-field encoding, callback output, full EIP-712 struct preimage, final digest, or public/synthetic verification vector is claimed.
- This packet does not establish ECDSA recovery, nonce/replay behavior, accepted wire encodings, error ordering, or runtime success.
- Open PR [#7082](https://github.com/lalalune/hyperliquid-source/pull/7082) inventories the action method table arms. This packet's bounded delta is the selected arm's downstream path through the digest wrapper to the action's typed-data builder; it does not repeat the 92-arm inventory.

## Results

- Verifier: 9 instruction-byte anchors, 3 relocated calls, 2 direct calls, 6 FDEs, one relative table entry; all match the pinned target.
- Focused tests: 5, including table-entry, callback-site, wrapper-call and relocation corruption controls.
- No component gate changes. The unresolved callback must be traced before claiming a complete `SendToEvmWithData` preimage or verification vector.
