# Family-a inline-Vec Eip7702 writer

Close this work item's explicitly excluded `0x2333850` caller, rather than
its already recovered by-reference `0x2333c30` body. Component `evm`.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x2333850..0x2333c2a`: 986 bytes / 238 instructions.

Entry RDI=output, RSI=payload B, RDX=inline-Vec buffer. Mode is +0x1b,
not the sibling Serializer+0xb convention. Capacity/storage/length are
+0/+8/+0x10. Header is low-byte `((mode XOR 1)<<4) OR 0x8a`: array-10
0x9a for mode 0, map-10 0x8a for 1, and 0xba for 2.

| Order | Observed field / delegate | Payload source |
| --- | --- | --- |
| 1 | chainId / 0x29feb10 | qword +0x60 through stack temporary |
| 2 | nonce / 0x29feb10 | qword +0x68 through stack temporary |
| 3 | gas / 0x29feb10 | qword +0x70 through stack temporary |
| 4 | maxFeePerGas / 0x2967e20 | address +0x40 |
| 5 | maxPriorityFeePerGas / 0x2967e20 | address +0x50 |
| 6 | delegated destination / 0x233a300 | address +0xa8 |
| 7 | value / 0x233aff0 | B in R8, key length 5 |
| 8 | delegated collection / 0x233b630 | address +0x78 |
| 9 | extra delegate 0x2339e80 | address +0x90 |
| 10 | input / 0x233b960 | address +0x20 in R8, key length 5 |

The ninth field's authorization-list interpretation is inference; its
offset/target/order are the observations, not a recovered nested schema.
The first three inline keys and fee-key calls require mode exactly 1. Fee
keys use 0x25e8bf0 with pool 0x5eab58 length 12 and 0x5eab64 length 20.
Other key policies are delegated. No equivalence with family3's different
callees or a concrete Rust layout is assumed.

Each nested stack result must equal 0x8000000000000004 before continuing.
Other results copy all three words; full completion writes only the tag.
Separate key calls require RAX=2 and otherwise repackage RAX/RDX under
0x8000000000000000. Inline growth calls use 0x231e050, reload fields and
rejoin stores. Nested encodings and allocation behavior remain opaque.

```sh
python3 research/work-items/evm-tx-rmp-struct-serializers-115/inline-vec/7702/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full image SHA/FDE, complete decode,
instruction/data pins and branch boundaries checked. Ten operative mutations
reject below image SHA guard; independent scalar checks cover 256 header modes.
Complete raw/FDE/CIE/call/branch/pool exports retained. No captured execution
or instruction interpretation. Valid stable nonaliasing pointers, capacity
invariants and normal helper returns are assumptions. Nested schemas,
allocation/unwind behavior and full native-tool suite remain unqualified.
No gates change. Next: recover extra delegate 0x2339e80 independently.
