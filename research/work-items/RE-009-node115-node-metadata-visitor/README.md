# RE-009: NodeMetadata field dispatch in the indexed artifact decoder

Scope: the NodeMetadata arm in the Linux x86-64 node #115 storage codec. Base revision: 2da45cb0a761cff6b478e40421699857d87a94df. Target SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. No external source code or gate changes.

The [indexed artifact study](../RE-009-indexed-artifact-content-codec-115/README.md) identified the enum arm and listed its fields. It excluded the struct-variant body. This packet follows the second copy from 0x57c3e52 into 0x4d51ac0 and checks the field-specific calls in both input routes. All coordinates are link-time ELF virtual addresses.

- The map route at 0x4e296b0 compares two-byte keys with little-endian words 0x7668 and 0x6862 at 0x4e2986b and 0x4e29876, respectively. The map and sequence routes call the same numeric helper 0x4d517e0 and string helper 0x4d51720. The helpers test different Value tags (0x8000000000000002 and 0x8000000000000003).
- The sequence route at 0x4e258d0 reads the numeric field first. The second helper receives a destination with length 32 at 0x4e25a3c. Its returned error bit is tested at 0x4e25a63. The success-side stores at 0x4e25a71 through 0x4e25aa8 place the 32 destination bytes at output offsets 0x08 through 0x27. The numeric word goes at 0x28 and the status word is set to zero. The equality check at 0x4e25ab7 branches to the normal return route when there are exactly two entries. The zero-entry and one-entry paths lead to the length diagnostic at 0x4e25938 and 0x4e259df, respectively.
- These observations establish the selected local decoder boundary. The downstream hex grammar, cleanup behavior, first copy, and meaning or origin of the 32 bytes remain open. The packet makes no claim about full decode equivalence or production identity.

Run from the repository root:

```sh
python3 research/work-items/RE-009-node115-node-metadata-visitor/verify.py
```

The verifier pins the ELF by hash, resolves seven relative calls and checks seven instruction windows. Its negative control changes one target byte in memory and confirms rejection. The recorded output is in offline-log.txt. GNU objdump 2.42 (cross-target) was used to read the selected instruction ranges. No target code was executed.
