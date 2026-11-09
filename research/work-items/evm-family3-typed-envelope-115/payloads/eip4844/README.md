# EVM family-3 Eip4844 eleven-field payload

Component `evm`, extending the merged typed envelope's tag-3 target.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x5b60450..0x5b60849`: 1,017 bytes / 244 instructions.

Entry RDI=output, RSI=payload B (parent enum+0x10), RDX=buffer.
Buffer mode +0x1b produces low-byte `((mode XOR 1)<<4) OR 0x8b`:
array-11 0x9b for mode 0, map-11 0x8b for mode 1; mode 2 gives 0xbb.

| Order | Field / observed delegate | Payload source |
| --- | --- | --- |
| 1 | chainId / 0x4fb2950 | qword +0x70 via stack temporary |
| 2 | nonce / 0x4fb2950 | qword +0x78 via stack temporary |
| 3 | gas / 0x4fb2950 | qword +0x80 via stack temporary |
| 4 | maxFeePerGas / 0x4f000d0 | address +0x40 |
| 5 | maxPriorityFeePerGas / 0x4f000d0 | address +0x50 |
| 6 | delegated destination / 0x5b6a3f0 | address +0xb8 |
| 7 | value / 0x5b69430 | B in R8, key length 5 |
| 8 | accessList / 0x5b691e0 | address +0x88 |
| 9 | blob-specific delegate 0x5b69a20 | address +0xa0 |
| 10 | blob-specific delegate 0x5b69620 | address +0x60 |
| 11 | input / 0x5b69050 | address +0x20 in R8, key length 5 |

The blob field semantic names are deliberately left to their delegates; only
their order, offsets and targets are claimed here. No copied Eip1559 layout
is assumed. The first three inline keys and the two fee-key calls require
mode exactly 1. Fee keys use pinned pool bytes at 0x93e4b2 (12 bytes) and
0x93e4be (20 bytes); other key policies are delegated. AccessList's bounded
key prefix is context evidence, not newly recovered by this packet.

Every nested result must equal full discriminator 0x8000000000000004 before
the next field. Other results copy all three stack words to output. Separate
fee-key calls require RAX=2; another value repackages RAX/RDX under high-bit
discriminator 0x8000000000000000. All-field completion writes only the full
completion discriminator. Local reserve calls target 0x5963a10 and rejoin
stores after reloading descriptor fields; helper semantics remain opaque.

```sh
python3 research/work-items/evm-family3-typed-envelope-115/payloads/eip4844/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full SHA/FDE, complete decode,
instruction/data pins and branches checked. Fourteen operative mutations,
including blob source offsets/call target, reject below image SHA guard.
Independent scalar checks cover 256 header modes and six result classes.
Complete bytes/FDE/CIE/calls/branches/pool context retained. No captured
instruction execution/interpretation.

Valid stable nonaliasing storage, capacity invariants and normal helper returns
are assumptions. Nested blob/address/numeric encodings, delegated key policies,
allocation, unwind behavior and full native-tool suite remain unqualified.
No gates change. Next: resolve the two blob-specific field adapters separately.
