# RE-017 Node #115 ClientBlocks writer boundary

- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032
  bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `c2772e3b1c742734af159c2c42c9541c7ebb7ac2`.
- Coordinates: ELF VAs in `.text` and `.rodata`. The verifier bounds code
  using the target's DWARF FDEs.

## Native writer evidence

The [ClientBlocks success grammar](../RE-001-node115-client-block-success-grammar/README.md)
establishes the decoder layout. The
[gossip error wire prefix](../RE-005-node115-gossip-error-wire-prefix/README.md)
records a call to `0x4fb65f0`. The landed
[gossip encoder byte matches](../RE-005-node115-transport-runtime-logic-wave3-byte-matches/README.md)
now identify the enclosing response encoder and model its ClientBlock child
as a call stand-in. The success
branch of `0x5aaa810` emits two compact U32 zero tags at `0x5aaa89f` and
`0x5aaa984`, both from the zero dword at `0x459e6c`. It writes the U64
count from input `+0x20` at `0x5aaa9a5`, then iterates the input pointer
from `+0x18` in 16-byte steps, calling `0x4fb65f0` for each entry. These
parent facts anchor the new evidence in the Client writer and its vector
child.

The Client writer calls four children in sequence. Each completed child
must return tag 8 before the next call.

| Call site | Target | Selected responsibility |
| --- | --- | --- |
| `0x4fb6659` | `0x59681d0` | Signature writer |
| `0x4fb6676` | `0x5967060` | Header with parent certificate, using the first aggregate at `+0x10` |
| `0x4fb6698` | `0x4e055d0` | Proof option from the first aggregate at `+0x188`, emitting a raw 0 or 1 |
| `0x4fb66b8` | `0x5b56e10` | Attachment vector from the second owner at `+0x10` |

The proof writer emits its Some byte before delegating to the signature/header
and QC writers. The [consensus encode matches](../RE-008-node115-consensus-bincode-encode-byte-matches/README.md)
cover its two child encoders and the header with parent certificate. This
packet adds their composition inside the selected Client writer.

The first write in `0x5b56e10` is a compact U64 count. Zero reaches success
without entering the row loop. A nonempty vector iterates 40-byte rows
whose first 32 bytes are passed to the fixed-width writer `0x5822260`.
Each row's owner pointer at `+0x20` supplies the blob length at owner
`+0x20` and the data pointer at owner `+0x18`. The writer encodes that
length as compact U64, copies the raw bytes through the linked `memcpy`
slot, then advances the output cursor by the length. The 40-byte step
describes the in-memory row.

## Reader boundary

The known ClientBlocks Client decoder at `0x4fbad90` reads Block then
dispatches directly to attachment-vector reader `0x5824840` with callback
`0x4e04e90`. That agrees with the selected writer's mandatory vector.

The [replay decoder](../RE-017-node115-replay-wire-payload-codec/README.md)
instead reads an outer compact U32 variant and, after the Block in variant
0, calls option reader `0x4e052f0`. That reader consumes one raw presence
byte before dispatching to the same vector reader on byte 1. The layouts
therefore join at the Block and attachment-row contracts, while the
post-Block framing differs:

| Post-Block form | Attachment suffix |
| --- | --- |
| ClientBlocks Client | `U64(count) rows` |
| Replay Block with absent attachments | `00` |
| Replay Block with present attachments | `01 U64(count) rows` |

For example, an empty Client vector and an absent replay vector both end
in `00`, but present-empty replay emits `01 00`. A zero-row sample alone
cannot identify the envelope. This writer cannot establish a native replay
writer or real replay bytes. Static observations here cover selected
normal serialization and its call boundaries. No executable implementation,
captured execution, live networking, or component gate change is claimed.

## Reproduce offline

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-017-node115-clientblocks-writer-boundary/verify.py
(cd research/work-items/RE-017-node115-clientblocks-writer-boundary && sha256sum -c MANIFEST.sha256)
```

The [offline log](offline-log.txt) records the genuine verifier run, four
changed-operand controls, and the linked `memcpy` slot from LLVM readelf.
The [instruction windows](windows.txt) record LLVM objdump commands and
the selected raw encodings and operands.
