# EVM family-3 Eip7702 ten-field payload

Component `evm`, tag-4 target in the merged typed envelope.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x5b60850..0x5b60c2a`: 986 bytes / 238 instructions.

Entry RDI=output, RSI=payload B (parent enum+0x10), RDX=buffer. Mode byte
buffer+0x1b yields low-byte `((mode XOR 1)<<4) OR 0x8a`: array-10 0x9a
for 0, map-10 0x8a for 1, and 0xba for 2. No optional-chain count adjustment.

| Order | Field / delegate | Payload source |
| --- | --- | --- |
| 1 | chainId / 0x4fb2950 | qword +0x60 via stack temporary |
| 2 | nonce / 0x4fb2950 | qword +0x68 via stack temporary |
| 3 | gas / 0x4fb2950 | qword +0x70 via stack temporary |
| 4 | maxFeePerGas / 0x4f000d0 | address +0x40 |
| 5 | maxPriorityFeePerGas / 0x4f000d0 | address +0x50 |
| 6 | delegated destination / 0x5b6a3f0 | address +0xa8 |
| 7 | value / 0x5b69430 | B in R8, key length 5 |
| 8 | accessList / 0x5b691e0 | address +0x78 |
| 9 | additional delegate 0x5b69550 | address +0x90 |
| 10 | input / 0x5b69050 | address +0x20 in R8, key length 5 |

The ninth field's authorization-list interpretation is inference from its
position in the Eip7702-shaped record; the observed offset/target is the claim.
Its schema/encoding remains open. The destination call and layout differ from
the Eip1559 record; no shared concrete Rust struct is inferred.

The three inline keys and fee-key calls require mode exactly 1. Fee-key pool
bytes at 0x93e4b2 (length 12) and 0x93e4be (length 20) are pinned. Other key
policies are delegated; the accessList prefix is context, not new recovery.
Each nested result must equal full discriminator 0x8000000000000004 before
continuing. Another result copies all three words to output; full completion
writes only the discriminator. Fee-key calls instead require RAX=2 and
repackage RAX/RDX under 0x8000000000000000 on another value. Local growth
calls target 0x5963a10, reload descriptor fields and rejoin the pending stores.

```sh
python3 research/work-items/evm-family3-typed-envelope-115/payloads/eip7702/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full SHA/FDE, complete decoding,
instruction/data pins and branches checked. Eleven operative mutations reject
below image SHA guard; independent checks cover 256 modes and six result
classes. Complete raw/FDE/CIE/call/branch/constant exports retained. No captured
execution/interpreter. Valid stable nonaliasing storage, capacity invariants
and normal helper returns are assumptions. Nested encodings, delegated keys,
allocation, unwinding and full native-tool suite remain unqualified. No gates
change. Next: recover delegate 0x5b69550 before assigning its field schema.
