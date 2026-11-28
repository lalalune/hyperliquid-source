# RE-017 Node #115 replay count and write passes

- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node` (105,896,032
  bytes), SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `c42e4eebf847462db32c934af4140a346ebba310`.
- Coordinates: ELF VAs. Code bounds are from the target's DWARF FDEs.

The repository's [replay wire codec](../RE-017-node115-replay-wire-payload-codec/README.md)
establishes the input shape of native `ClientBlockWireOrTx` reader
`0x4eff5f0`. Follow the distinct callers of attachment writer `0x5b56e10`
to locate a native output path with the matching shape. The count/write
pair identifies a point for comparing an offline encoder with the pinned
target, before framing or compression.

## Observations

The wrapper `0x5823480` stores the input pointer at `rsp + 0x8`, initializes
its count slot at `rsp + 0x48` to zero, and passes the saved input to
counter `0x4fb5ae0` at `0x58234bb`. When count status is tag 8, the
resulting count becomes the requested allocation size for a nonzero count
and the initial VecWriter capacity. The VecWriter cursor starts at zero.
The write call at `0x582353a` passes the same saved input to `0x4fb5ce0`.
The wrapper returns the completed vector on tag 8.

Both passes select their variant by testing the first qword in the input
pair. The zero and one dwords at `0x459e6c` and `0x45a05c` go to compact
U32 counter `0x58220e0` and writer `0x5821f30` in their respective passes.
The selected semantics are:

| Input owners | Writer after the variant tag | Matching reader path |
| --- | --- | --- |
| First qword nonzero, second zero | Tag 0, Signature, Header, proof option, then raw byte 0 | Block through `0x4fb7760`, attachments absent in `0x4e052f0` |
| Both qwords nonzero | Tag 0, same Block children, raw byte 1, then vector from second owner `+0x10` | Block, then option 1 dispatches to attachment-vector reader `0x5824840` |
| First qword zero | Tag 1, compact U64 length from second owner `+0x20`, then contiguous bytes from `+0x18` | Blob reader `0x5824b60` |

The Block writer invokes `0x59681d0`, `0x5967060`, and `0x4e055d0`
for the three Block children. The attachment object is considered only
after these calls have succeeded. On the Some path, `0x4fb5de4` emits
one raw byte and `0x4fb5dfb` calls `0x5b56e10`. On the None path,
`0x4fb5f1a` emits one raw byte and returns without a vector call. The
counter always charges one byte for this Block attachment option, then
invokes attachment count helper `0x5b56f70` only when the second owner
is present. For Tx, it counts the length prefix plus the byte length.
The write path calls compact U64 writer `0x5822910` for the length,
then appends the exact blob through the linked `memcpy` slot. Zero
length skips the copy.

The [ClientBlocks response decoder](../RE-001-node115-client-block-success-grammar/README.md)
has a mandatory vector after its Block. The extra option above establishes
the distinct replay envelope, including the difference between absent and
present-empty vectors. The observations show matched native component
boundaries. Captured runtime byte equality, consumer provenance for an
actual record, signatures, and state-root validation remain open.

## Reproduce offline

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-017-node115-replay-native-writer/verify.py
(cd research/work-items/RE-017-node115-replay-native-writer && sha256sum -c MANIFEST.sha256)
```

[Instruction windows](windows.txt) retain the LLVM objdump commands,
operands and bytes. The [offline log](offline-log.txt) records the digest,
FDE bounds, tested tag constants, dynamic import bindings and four rejected
changed-operand cases. No captured instructions were executed.
