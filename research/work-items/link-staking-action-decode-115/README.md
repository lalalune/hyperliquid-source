# Node #115 LinkStakingUser Action decoder arm

This packet binds one externally named `Action` variant to the in-memory variant word consumed by the existing link-staking handler evidence. It addresses the decoder-to-handler gap named in issue #3928 without asserting public account identities or complete transaction semantics.

- Component: `action-wire` / `action-dispatch`; related acceptance issue #3928.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Bounded question: what does Action decoder FDE `0x2bd6140..0x2bd8476` do for variant index 11?
- Coordinates: linked ELF virtual addresses; half-open FDE extents.

## Reproduce

```sh
python3 tools/link_staking_action_decode_115.py --out /tmp/link-staking-action-decode-115
python3 -m unittest tests.test_link_staking_action_decode_115
python3 tools/catalogue.py --check
```

The generator checks the full target digest, the Action decoder FDE, its relative jump-table instruction sequence, the signed table entry at index 11, the exact arm bytes, the variant-name bytes and ten `.rela.dyn` descriptor slots. It reads the ELF as data and does not execute it. `descriptor-relocations.tsv` preserves the raw string bytes and adjacent length words. The first five pointer/length pairs are recorded as the count-5 string slice passed by the arm; the following five are retained as adjacent context.

## Evidence and joined path

At `0x2bd6140`, the decoder FDE begins a structured Action deserialization route. Its `0x609c20` signed-relative table maps index 11 to interior block `0x2bd6d56`. That arm passes the pointer at `0x616d3b` (`LinkStakingUserAction`), name length `0x15`, descriptor pointer `0x6450ed8`, and count `5` to helper `0x2046db0`. The five pointer/length pairs selected by that count contain, in order, `signatureChainId`, `hyperliquidChain`, `user`, `isFinalize`, and `nonce`. This is the raw field-name list passed to the helper; field payload semantics are not inferred from the names. On the observed normal path it copies 64 bytes into the Action payload at `rbx+8`, then writes the internal tag `0x91`. A status byte comparison at `[rsp+0x5d]` routes value `2` to block `0x2bd8127`.

The previously merged Action type matcher maps the wire spelling `linkStakingUser` to index 11 (`RE-010-action-type-matcher-115`). The action admission binding associates nominal tag `0x91` / index 11 / `LinkStakingUser` with class 2 (`RE-017-node115-action-admission-binding`). The existing `RE-010-link-staking-path-115` packet follows tag `0x91` through the selected handler to the request/finalize writes. These are separate static packets joined by the exact numeric index/tag; together they provide a decoder-to-handler route. The admission class is not itself a signer verdict.

## Limits

This packet records the five field names and their order but does not recover their payload semantics, validate real input acceptance, establish the signature/nonce preconditions, or prove persistent transaction behavior. It does not execute the target or advance a component gate. FDE extents describe unwind ranges; the dispatch target is an interior block, not a separate source function.
