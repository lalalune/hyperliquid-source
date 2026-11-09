# Family-a inline-Vec Eip1559 writer

Close this work item's explicitly excluded `0x23326f0` caller, not the
already covered by-reference `0x2332430` body. Component `evm`.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x23326f0..0x2332ab2`: 962 bytes / 232 instructions.

Entry RDI=output, RSI=payload B, RDX=inline-Vec buffer. Mode +0x1b is
distinct from the sibling Serializer+0xb convention; capacity/storage/length
are +0/+8/+0x10. The header is low-byte `((mode XOR 1)<<4) OR 0x89`:
array-9 0x99 for 0, map-9 0x89 for 1, 0xb9 for 2. Chain is unconditional.

| Order | Field / observed delegate | Source |
| --- | --- | --- |
| 1 | chainId / 0x29feb10 | qword +0x60 via stack temporary |
| 2 | nonce / 0x29feb10 | qword +0x68 via stack temporary |
| 3 | gas / 0x29feb10 | qword +0x70 via stack temporary |
| 4 | maxFeePerGas / 0x2967e20 | address +0x40 |
| 5 | maxPriorityFeePerGas / 0x2967e20 | address +0x50 |
| 6 | delegated destination / 0x233b510 | address +0x90 |
| 7 | value / 0x233aff0 | B in R8, key length 5 |
| 8 | delegated collection / 0x233b630 | address +0x78 |
| 9 | input / 0x233b960 | address +0x20 in R8, key length 5 |

The collection's access-list interpretation is inference; nested schema is
open. Inline chainId/nonce/gas keys and fee-key calls require mode exactly 1.
Fee keys use 0x25e8bf0 with pool 0x5eab58 length 12 and 0x5eab64 length 20;
the bytes and all actual call sites are retained. Other key policies are
delegated. No concrete type or equivalence with the family3 callees is assumed.

Nested stack results must equal full 0x8000000000000004 to continue. A
different result copies all three words and omits subsequent fields; completion
writes only the discriminator. Fee-key calls require RAX=2; otherwise RAX/RDX
are repackaged under 0x8000000000000000. Inline growth calls use 0x231e050,
reload buffer fields and rejoin stores. Allocation and nested encodings remain
outside this body-level contract.

```sh
python3 research/work-items/evm-tx-rmp-struct-serializers-115/inline-vec/1559/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full SHA/FDE, complete decoding,
instruction/data pins and branches checked. Ten operative mutations reject
below the image SHA guard; independent header checks cover 256 modes. Full
raw/FDE/CIE/call/branch/pool exports retained. No captured execution/interpreter.
Valid stable nonaliasing storage, capacity invariants and normal helper returns
are assumptions. Nested encodings, allocator/unwind behavior and full native
suite remain unqualified. No gates change. Next: recover the separate blob
writer's additional source fields without assuming this nine-field layout.
