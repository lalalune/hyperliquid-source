# Family-a inline-Vec Eip4844 writer

Close this work item's explicitly excluded `0x2333450` caller, not its
already covered by-reference `0x2333150` body. Component `evm`.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x2333450..0x2333849`: 1,017 bytes / 244 instructions.

Entry RDI=output, RSI=payload B, RDX=inline-Vec buffer. Mode is +0x1b,
distinct from the sibling Serializer+0xb; capacity/storage/length +0/+8/+0x10.
Header is low-byte `((mode XOR 1)<<4) OR 0x8b`: array-11 0x9b for 0,
map-11 0x8b for 1, 0xbb for 2. Eleven fields are visited in this order:

| Order | Field / observed delegate | Source |
| --- | --- | --- |
| 1 | chainId / 0x29feb10 | qword +0x70 via stack temporary |
| 2 | nonce / 0x29feb10 | qword +0x78 via stack temporary |
| 3 | gas / 0x29feb10 | qword +0x80 via stack temporary |
| 4 | maxFeePerGas / 0x2967e20 | address +0x40 |
| 5 | maxPriorityFeePerGas / 0x2967e20 | address +0x50 |
| 6 | delegated destination / 0x233a300 | address +0xb8 |
| 7 | value / 0x233aff0 | B in R8, key length 5 |
| 8 | delegated collection / 0x233b630 | address +0x88 |
| 9 | blob delegate 0x233a3b0 | address +0xa0 |
| 10 | blob delegate 0x233a4f0 | address +0x60 |
| 11 | input / 0x233b960 | address +0x20 in R8, key length 5 |

The collection/access-list and blob-field semantic names are inferences; only
the observed offsets, order and targets are claimed. Their encodings remain
open. No equivalence with family3's differently addressed callees is assumed.
Inline chainId/nonce/gas and separately called fee keys require mode exactly 1.
Fee keys use 0x25e8bf0, pool 0x5eab58 length 12 and 0x5eab64 length 20.
Other key policies are delegated. Pool context and all exact call sites are
retained without assigning unused adjacent bytes to fields.

Nested stack results must equal 0x8000000000000004 before continuation.
Other results copy all three words; completion writes only that discriminator.
Fee-key RAX!=2 repackages RAX/RDX under 0x8000000000000000 before returning.
Inline growth calls use 0x231e050, reload buffer fields and rejoin stores.
Allocation and nested wire encoding remain outside the local contract.

```sh
python3 research/work-items/evm-tx-rmp-struct-serializers-115/inline-vec/4844/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full SHA/FDE, complete decoding,
instruction/data pins and branches checked. Ten operative mutations reject
below image SHA guard; independent header checks cover all 256 modes. Full
raw/FDE/CIE/call/branch/pool exports retained. No captured execution/interpreter.
Valid stable nonaliasing storage, capacity invariants and normal helper returns
are assumptions. Nested encoding, allocator/unwind behavior and full native
suite remain unqualified. No gates change. Next: recover the two blob delegate
schemas before assigning concrete types or claiming wire compatibility.
