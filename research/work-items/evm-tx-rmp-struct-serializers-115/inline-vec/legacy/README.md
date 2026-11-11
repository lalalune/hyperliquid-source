# Family-a inline-Vec Legacy writer

Extend this work item's explicitly excluded `0x2331e60` caller, not its
already recovered by-reference `0x2331bf0` body. Component `evm`.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x2331e60..0x23322e1`: 1,153 bytes / 278 instructions.

Entry RDI=output, RSI=payload B, RDX=inline-Vec buffer. Its mode is +0x1b,
capacity/storage/length +0/+8/+0x10; this is not the sibling Serializer+0xb ABI.
Full qword [B] determines cardinality 6 when zero, otherwise 7. Nonzero mode
calls container helper 0x25e7540; zero mode calls 0x25e7c10, with that count.
Their stack result qword must be 2 before fields proceed.

| Order | Field / writer | Source |
| --- | --- | --- |
| optional first | chainId / 0x29feb10 | presence qword +0, qword +8 via stack temporary |
| next | nonce / 0x29feb10 | qword +0x60 via stack temporary |
| next | gasPrice / 0x2967e20 | address +0x30 |
| next | gas / 0x29feb10 | qword +0x68 via stack temporary |
| next | to / 0x26e5590 | address +0x70 |
| next | value / 0x233aff0 | address +0x40 in R8, key length 5 |
| final | input / 0x233b960 | address +0x10 in R8, key length 5 |

Inline chainId/nonce/gasPrice/gas keys and the separately called to key all
require mode exactly 1. The to key uses 0x25e8bf0, pool 0x5eab4c, length 2.
This differs from the family-3 Legacy body's nonzero-mode to-key gate; no clone
equivalence is assumed. Value/input key policies are delegated.

Chain omission tests the full qword [B]. On the mode-one key path only, a
zero low byte emits nil instead of calling its writer. Thus tag 256 is a
noncanonical witness: seven fields in all modes, nil in mode 1, value writer
in mode 0/2. It is not a valid Option-layout claim. The destination encoder is
delegated; no local tag/address rule is inferred from the family-3 body.

Nested result 0x8000000000000004 permits continuation; other results copy
all three words. Full completion writes only that discriminator. Container
and to-key failures are repackaged under 0x8000000000000000. Inline growth
calls use 0x231e050, reload descriptor fields and rejoin the pending stores.

```sh
python3 research/work-items/evm-tx-rmp-struct-serializers-115/inline-vec/legacy/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full digest/FDE, complete decoding,
instruction/data pins and branches checked; eleven operative mutations reject
below image SHA guard. Independent optional-chain model: 1,280 mode/tag cases.
Full raw/FDE/CIE/call/branch/pool exports retained. No captured execution or
interpretation. Valid stable nonaliasing storage, capacity invariants and normal
helper returns are assumptions. Nested encodings, allocator/unwind behavior
and full native-tool suite remain unqualified. No gates change. Next: close
the separately excluded inline-Vec access-list transaction writer.
