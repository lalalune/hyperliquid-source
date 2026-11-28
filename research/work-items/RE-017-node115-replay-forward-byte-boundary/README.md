# RE-017 Node #115 forwarded replay byte boundary

- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Analysis base: `2da45cb0a761cff6b478e40421699857d87a94df`.
- Coordinates: ELF virtual addresses. Code spans are selected inside captured DWARF FDEs.

The [external transaction forwarding packet](../RE-001-node115-external-transaction-forwarding/README.md)
maps the worker's input and call ordering, leaving encoder `0x58610b0`
opaque. This packet connects the timed carrier's outbound queue to that
worker using its constructor. It then resolves the writer's raw record
boundary for the selected opaque-wire owner.

## Shared queue instance

The setup at `0x5a7c7d0` allocates the 0x120-byte starting segment at
`0x5a7c9a1`, places its pointer into the queue state, and copies that
state into the allocation held in R14 at `0x5a7ca76`. Its pointer
is carried through two future captures:

| Capture | Pointer flow |
| --- | --- |
| Timed sender | `0x5a7cbf0` stores R14 at stack `+0x1b8`. The copied future starts at stack `+0x180`, making this future offset `+0x38`. The table slot `0x64b8c58` binds poll function `0x5a71040`. |
| External-forward receiver | The same R14 was saved at stack `+0x138` by `0x5a7cb2a`. The 16-byte moves at `0x5a7ccec/ccfc`, `0x5a7cdec/cdf4` and `0x5a7cf98/cfb0` pass its low qword through stack `+0x1d0` and `+0xb0` back to `+0x180`. The final `0x98`-byte future starts there, so offset zero is the same queue pointer. Table slot `0x64b8f38` binds poll function `0x5a7dce0`. |

The timed sender adds `0x80` to its queue pointer and calls `0x581b4b0`.
The sender's final store puts the payload owner pointer into an 8-byte
slot, then sets its ready bit at segment `+0x110`. At `0x5a7de90`,
the external-forward worker uses the cursor from queue `+0x1a0` and
state from `+0x80` for receive helper `0x5819960`. The helper reads
the same kind of ready bit and loads `segment + 8 * (index & 31)`
into RDX. On the selected ready, nonnull path, the worker places
that pointer at encoder input `+0x8` without re-encoding the inner bytes.

## Outer writer boundary

The worker stages the captured origin (20 bytes) at encoder input
`+0x178` and passes the in-memory discriminant `0x8000000000000000`.
Its `consensus forward external tx` call leads from `0x58610b0`
via `0x4e48cc0` and pre-count/allocate wrapper `0x5823750` to
`0x581f160`. The wrapper starts the write cursor at zero.

The VecWriter initially copies the origin as 16 bytes plus a dword,
advancing by 20. The observed high-bit discriminant produces index zero
in the signed-relative table at `0x935b40`, taking `0x581f1e4`.
That arm writes byte 0, reads the retained owner's length at `+0x20`,
and passes it to the compact U64 writer `0x5822910`. It reads the
owner's data pointer at `+0x18` and copies exactly that span into the
writer, preserving the inner bytes.

```text
origin[20] | 00 | U64(length) | original owner bytes[length]
```

For offline integration, the nested payload begins at
`21 + encoded_width(length)` relative to the wrapper output. This is
a native serialization boundary observed statically. No runtime
delivery, peer acceptance, durable record, or proof of ingesting
a real checkpoint is claimed. No captured code was executed.

## Reproduce offline

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-017-node115-replay-forward-byte-boundary/verify.py
(cd research/work-items/RE-017-node115-replay-forward-byte-boundary && sha256sum -c MANIFEST.sha256)
```

The [disassembly windows](windows.txt) record the selected instruction
bytes. The [offline log](offline-log.txt) records the authenticated
target, FDE bounds, dispatch and relocation targets and four rejected
operand mutations.
