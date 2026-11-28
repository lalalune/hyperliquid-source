# RE-017 Node #115 replay wire owners enter the connection queue

- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Analysis base: `c42e4eebf847462db32c934af4140a346ebba310`.
- Coordinates: original ELF VAs. Code bounds come from DWARF FDEs.

The [callback filter](../RE-017-node115-replay-callback-filter/README.md)
establishes two worker modes and an earlier membership check. This packet
follows the referenced byte owner beyond that filter. The question is
which serialization is retained in the callback's connection queue and
whether the referenced bytes include the optional attachments.

## Two carrier constructions

`0x5861530` calls `0x4e45c50`, which forwards the input to replay writer
wrapper `0x5823480` on its two selected continuations. The latter's
successful result has Vec capacity, pointer and length in three qwords
after the tag. `0x58615b9..0x58615c7` copies those qwords to the caller's
output. This is the output of the count/write pair `0x4fb5ae0/0x4fb5ce0`.

The worker calls the callback at `0x5a63100` with selectors 0 and 1
at `0x5a6e42d` and `0x5a6e43d`, respectively. The callback references
the source label `node/src/connections.rs`. It constructs two candidate
owners at entry:

| Owner | Construction | Callback slot |
| --- | --- | --- |
| Full | At `0x5a63138`, serialize the original pair. Allocate `0x28` bytes, write two counter qwords initialized to 1, and copy the serialized vector to owner `+0x10/+0x18/+0x20`. | `rsp + 0x10` |
| Block-only | At `0x5a631a0`, call relocation slot `0x64ebba0`, which resolves to `0x4fba210`. A null original first word returns null. A nonnull first word is retained, the staged second word is set to zero, and the same serializer and owner layout are used. | `rsp + 0x80` |

On the selected mode-zero iteration, `0x5a6367a` reaches the increment
for the full owner at `0x5a63820`. On the selected nonzero-mode
continuation through `0x5a63849`, the candidate saved at `rsp + 0xf0`
is used. It was chosen by `0x5a63606..0x5a63618`, which prefers the
nonzero Block-only owner and otherwise uses the full owner. This describes
those paths only. Other nonzero-mode filter outcomes may select a
different continuation.

## Queue boundary

On the accepted queue path, the common continuation stores the selected
owner at `rsp + 0x140` after a dword at `rsp + 0x130` and a qword at
`rsp + 0x134`. The call at `0x5a63cf7` passes the resulting entry
address in RSI and the queue at `[selected connection + 0x50] + 0x80`
in RDI. The queue helper at `0x581a8b0` selects a 32-slot segment and
indexes the slot by `24 * slot`. It copies 16 bytes from the entry plus
the owner pointer at `+0x10`, then sets the segment's slot bit at
`+0x310` with a locked OR. The queue carries a reference to the bytes
and does not copy the payload itself at that boundary.

The new evidence connects the native serialized bytes to an in-memory
connection queue. It is conditional on successful serialization and
allocation, a selected entry and a queue accepting the transfer. It
does not establish later transmission, a durable file record, runtime
reachability, or state-root agreement. No captured node was executed.

## Reproduce offline

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-017-node115-replay-connection-carrier/verify.py
(cd research/work-items/RE-017-node115-replay-connection-carrier && sha256sum -c MANIFEST.sha256)
```

[Instruction windows](windows.txt) retain the LLVM commands and bytes.
[Raw output](offline-log.txt) records the six FDE bounds, relocation
slot, source label and four rejected operand mutations.
